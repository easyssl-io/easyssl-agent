// Command easyssl-agent is the easySSL Agent binary. Subcommands:
//
//	register --server <url> [--key <key>] [--name <name>]   interactive registration
//	run                                                     the systemd service loop (periodic check-in)
//	status [--json]                                         print local state + what the Server says
//	uninstall [--yes]                                       unregister and remove the Agent
//	plugin install <name> [--json]                          fetch a plugin from the Marketplace and report it
//	plugin list [--json]                                    what this host has installed
//
// A host runs one Agent, so the commands need no instance selector. The CLI
// writes human output to stdout, JSON where asked, and errors to stderr;
// connections are only ever made from Agent to Server, never the reverse.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"math/rand/v2"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/easyssl-io/easyssl-agent/internal/commands"
	"github.com/easyssl-io/easyssl-agent/internal/csr"
	"github.com/easyssl-io/easyssl-agent/internal/deploy"
	"github.com/easyssl-io/easyssl-agent/internal/flow"
	"github.com/easyssl-io/easyssl-agent/internal/identity"
	"github.com/easyssl-io/easyssl-agent/internal/keystore"
	"github.com/easyssl-io/easyssl-agent/internal/pluginmgr"
	"github.com/easyssl-io/easyssl-agent/internal/sdnotify"
	"github.com/easyssl-io/easyssl-agent/internal/serverapi"
	"github.com/easyssl-io/easyssl-agent/internal/sysd"
	"github.com/easyssl-io/easyssl-contract/wire"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	if err := rootPreflight(os.Args[1:], os.Geteuid()); err != nil {
		fmt.Fprintln(os.Stderr, "easyssl-agent: "+err.Error())
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var err error
	switch os.Args[1] {
	case "register":
		err = cmdRegister(ctx, os.Args[2:])
	case "run":
		err = cmdRun(ctx, os.Args[2:])
	case "status":
		err = cmdStatus(os.Args[2:])
	case "uninstall":
		err = cmdUninstall(ctx, os.Args[2:])
	case "plugin":
		err = cmdPlugin(ctx, os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "easyssl-agent: unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "easyssl-agent: "+err.Error())
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: easyssl-agent <register|run|status|uninstall|plugin> [flags]")
}

// rootPreflight refuses every operational command before it parses flags,
// reads a path, or contacts the Server. This slice keeps all Agent state under
// a root-only directory, so waiting for the filesystem error both leaks which
// particular file was reached first and gives otherwise-equivalent commands
// inconsistent failures.
func rootPreflight(args []string, euid int) error {
	cmd := rootCommand(args)
	if euid == 0 || cmd == "" {
		return nil
	}
	if cmd == "register" {
		// Registration has to name both routes to root: a host operator may
		// already be in a root shell on a system where sudo is not installed.
		return errors.New("register must run as root: use sudo, or run it from a root shell")
	}
	return rootOnlyError(cmd)
}

// rootCommand returns only recognized commands that can read or change Agent
// state. Keeping the inventory here makes the early gate reviewable as one
// complete list; help, incomplete groups, and unknown commands retain their
// normal usage errors.
func rootCommand(args []string) string {
	if len(args) == 0 {
		return ""
	}
	switch args[0] {
	case "register", "run", "status", "uninstall":
		return args[0]
	case "plugin":
		if len(args) < 2 {
			return ""
		}
		switch args[1] {
		case "catalog", "install", "list":
			return "plugin " + args[1]
		}
	}
	return ""
}

func rootOnlyError(cmd string) error {
	return fmt.Errorf("this command requires root; re-run as root with \"sudo easyssl-agent %s\"", cmd)
}

func cmdRegister(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("register", flag.ExitOnError)
	server := fs.String("server", "", "easySSL Server base URL (required)")
	key := fs.String("key", os.Getenv("REGISTRATION_KEY"), "Organization registration key (defaults to $REGISTRATION_KEY)")
	name := fs.String("name", os.Getenv("AGENT_NAME"), "Agent name (defaults to $AGENT_NAME, else the hostname; prompted when interactive)")
	_ = fs.Parse(args)
	if *server == "" {
		return errors.New("register: --server is required")
	}
	return flow.Register(ctx, flow.Options{ServerURL: *server, RegistrationKey: *key, Name: *name})
}

func cmdUninstall(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	_ = fs.Parse(args)
	return flow.Uninstall(ctx, *yes)
}

func cmdRun(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	_ = fs.Parse(args)
	cfg, err := identity.LoadConfig()
	if err != nil {
		return stateError("run", err)
	}
	token, err := identity.LoadToken()
	if err != nil {
		return stateError("run", err)
	}

	api := serverapi.New(cfg.ServerURL)
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	// So key generation is reported in the same format as everything else the
	// service writes, rather than through the default handler.
	keystore.SetLogger(logger)
	// A command type with no handler here is reported unsupported, which is
	// also what an Agent older than its Server does.
	runner := commands.NewRunner(api, token, logger, map[string]commands.Handler{
		wire.CommandRequestCSR: csr.New(api, token, logger),
		wire.CommandDeploy:     deploy.New(api, pluginmgr.New(nil, nil), token, logger),
	})

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var streaming sync.Once

	// Under Type=notify systemd waits for this before calling the service
	// started; a no-op anywhere else (see sdnotify).
	sdnotify.Ready()
	sdnotify.Status("Checking in.")

	// Set once when the token stops being accepted, so the message is written
	// at error level the first time and rarely after that: the condition does
	// not change on its own, and a line a minute would bury everything else in
	// the journal.
	removedSince := time.Time{}

	poll := 60
	for {
		resp, err := api.Checkin(ctx, token, flow.CheckinBody())
		if err == nil {
			if !removedSince.IsZero() {
				// Nothing recovers a revoked token by itself, so this only
				// happens if the host was registered again while the service
				// ran. Say so, since the last thing the log said was the
				// opposite.
				logger.Info("token accepted again; resuming work")
				sdnotify.Status("Checking in.")
				removedSince = time.Time{}
			}
			// A rename in the web console reaches the host here rather than
			// waiting for a re-registration that may never happen.
			if (resp.OrganizationName != "" && resp.OrganizationName != cfg.OrganizationName) ||
				(resp.OrganizationID != "" && resp.OrganizationID != cfg.OrganizationID) {
				if resp.OrganizationName != "" {
					cfg.OrganizationName = resp.OrganizationName
				}
				if resp.OrganizationID != "" {
					cfg.OrganizationID = resp.OrganizationID
				}
				if err := identity.SaveConfig(cfg); err != nil {
					logger.Warn("could not record the Organization name", "err", err)
				}
			}
			poll = resp.NextPollSeconds
			if resp.Status == wire.StatusActive {
				// Only now: every push-channel route refuses an Agent that is
				// still awaiting authorization, exactly as the check-in does,
				// so subscribing earlier would just loop on 401s.
				streaming.Do(func() { go streamCommands(ctx, api, token, runner, logger) })
				if shouldReconcile(resp) {
					runner.Reconcile(ctx)
				}
			}
		} else if isUnknownToken(err) {
			// Removed from the web console, or the token revoked. The service keeps
			// running and stops doing work: this Agent belongs to the host, not
			// to the Server, so a decision taken in
			// the web console does not stop a unit here, remove a file, or leave a
			// failed unit in `systemctl --failed` for a host that is behaving
			// correctly. Uninstalling stays the operator's action, and the
			// message names both ways out.
			if removedSince.IsZero() {
				removedSince = time.Now()
				logger.Error("this host is no longer registered with the Server: its token was rejected or revoked",
					"server", cfg.ServerURL,
					"next", "register again by re-running the installer, or remove this Agent with `easyssl-agent uninstall`",
					"note", "no work will be done until then; nothing under "+identity.BaseDir+" has been touched")
				sdnotify.Status("Not registered: token rejected or revoked. Re-run the installer to register again, or `easyssl-agent uninstall` to remove this Agent.")
			} else if time.Since(removedSince) > 30*time.Minute {
				removedSince = time.Now()
				logger.Error("still not registered with the Server; re-run the installer or uninstall this Agent",
					"server", cfg.ServerURL)
			}
			// Fall through to the wait: the loop keeps the service alive and
			// picks the work back up if the host is registered again.
		}
		// A transient error (Server unreachable) falls through and retries.
		if poll <= 0 {
			poll = 60
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(time.Duration(poll) * time.Second):
		}
	}
}

// streamCommands keeps the event stream open for as long as the service runs,
// reconciling on connect and on every command the Server pushes.
//
// A dropped stream is ordinary, not a failure: networks and proxies close idle
// connections, and the check-in loop keeps delivering commands the whole time.
// So this reconnects quietly and never ends the service. The one thing it will
// not retry is a rejected credential, which no amount of waiting repairs.
// shouldReconcile decides whether a check-in has to be followed by the
// reconcile fetch.
//
// A reported zero is the Server saying it has nothing outstanding for this
// host, and is the only case worth skipping. On a fleet that is mostly idle
// that removes one request per Agent per cadence whose answer was an empty
// list.
//
// nil is not zero. It is a Server that does not report the count, which is
// every Server older than the field, and it means fetch exactly as before.
// Reading a missing field as zero would make this Agent stop fetching commands
// from an older Server and never notice, which is the one outcome this cannot
// have.
//
// The count may be stale by the time it is read, because a command can be
// created immediately after it was taken. That costs at most one cadence: the
// event stream nudges, and the next check-in counts again. Nothing here
// concludes that a command exists, only that none did, so a stale count delays
// work rather than inventing or losing it.
func shouldReconcile(resp wire.CheckinResponse) bool {
	return resp.PendingCommands == nil || *resp.PendingCommands > 0
}

func streamCommands(ctx context.Context, api *serverapi.Client, token string, runner *commands.Runner, logger *slog.Logger) {
	const (
		minBackoff = 2 * time.Second
		maxBackoff = 5 * time.Minute
		// A stream that stayed up this long proves the Server is reachable, so
		// the next drop starts over at the short delay. Without it the delay
		// only ever grows: an Agent up for weeks would wait the maximum after a
		// routine proxy timeout, having been connected the entire time.
		healthyFor = time.Minute
	)
	backoff := minBackoff
	for {
		// Reconcile on every (re)connect, before trusting anything to arrive on
		// the stream: whatever was published while disconnected is waiting.
		runner.Reconcile(ctx)

		var connectedAt time.Time
		err := api.SubscribeCommands(ctx, token, func() {
			connectedAt = time.Now()
			logger.Info("command stream connected")
		}, func() {
			// The event is a nudge and carries nothing. Reconcile reads
			// authoritative state, which also picks up anything this Agent
			// missed while the stream was down.
			runner.Reconcile(ctx)
		})
		if ctx.Err() != nil {
			return
		}
		if isUnknownToken(err) {
			logger.Warn("command stream refused; token rejected or revoked")
			return
		}
		if !connectedAt.IsZero() && time.Since(connectedAt) >= healthyFor {
			backoff = minBackoff
		}
		// Info, not Debug: an Agent that can never hold the stream open looks
		// exactly like a healthy one from the host, and this is the only place
		// that difference is visible there.
		logger.Info("command stream ended; reconnecting", "err", err, "retry_in", backoff)

		select {
		case <-ctx.Done():
			return
		case <-time.After(jitter(backoff)):
		}
		if backoff *= 2; backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// jitter spreads reconnects so a fleet that lost its Server does not return in
// lockstep the moment it comes back.
func jitter(d time.Duration) time.Duration {
	return d/2 + time.Duration(rand.Int64N(int64(d/2)+1))
}

// stateError explains why the Agent's on-disk state could not be read. The two
// common causes have obvious fixes, but the raw "permission denied" on
// config.json sends people hunting for a filesystem problem instead: the state
// is deliberately root-only (0600 under a 0700 directory) so an unprivileged
// process cannot read the bearer token.
func stateError(cmd string, err error) error {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("no easySSL Agent is registered on this host (%s does not exist); register one with \"sudo easyssl-agent register --server <url>\"", identity.ConfigPath())
	case errors.Is(err, fs.ErrPermission):
		return rootOnlyError(cmd)
	}
	return fmt.Errorf("%s: %w", cmd, err)
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	_ = fs.Parse(args)

	cfg, err := identity.LoadConfig()
	if err != nil {
		return stateError("status", err)
	}
	token, tokenErr := identity.LoadToken()

	// Whether the Agent is still registered is not a local fact: the Server
	// owns it and can drop an Agent without telling the host, so a stored token
	// proves only that one was issued once. Ask the Server. This is a read
	// (GET), not a check-in, so running status never refreshes last-seen and
	// therefore cannot make a stopped Agent look alive in the web console.
	stateCode, stateDetail := serverState(cfg, token, tokenErr)

	if *asJSON {
		out := map[string]any{
			"agentId":        cfg.AgentID,
			"displayName":    cfg.DisplayName,
			"serverUrl":      cfg.ServerURL,
			"organization":   cfg.OrganizationName,
			"organizationId": cfg.OrganizationID,
			"serviceName":    identity.ServiceName(),
			"serviceState":   sysd.State(),
			"tokenPresent":   tokenErr == nil,
			// Short code for machines; the printed line spells it out.
			"serverState": stateCode,
		}
		return json.NewEncoder(os.Stdout).Encode(out)
	}

	line := func(label, value string) { fmt.Printf("%-12s %s\n", label, value) }
	line("Agent", cfg.AgentID)
	line("name", cfg.DisplayName)
	line("Server", cfg.ServerURL)
	if cfg.OrganizationName != "" || cfg.OrganizationID != "" {
		line("Organization", cfg.Organization())
	}
	line("service", fmt.Sprintf("%s (%s)", identity.ServiceName(), sysd.State()))
	if tokenErr == nil {
		line("token", "stored in "+identity.TokenPath())
	} else {
		line("token", "missing, so this Agent cannot authenticate")
	}
	line("state", stateDetail)
	return nil
}

// serverState asks the Server what this Agent actually is right now, which a
// host cannot tell from its own files: it has no way to know it was removed
// from the web console. Read-only, so status stays free of side effects.
//
// It returns a short stable code for machines and a sentence for people. The
// wire calls an authorized Agent "active", which printed next to a stopped
// systemd unit reads as if the Agent were running, when it only means the
// operator admitted it; the web console says "Authorized" and so does this.
func serverState(cfg identity.Config, token string, tokenErr error) (code, detail string) {
	if tokenErr != nil {
		return "not-registered", "not registered (no local token)"
	}
	// Short: status must stay snappy on a host that cannot reach the Server.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := serverapi.New(cfg.ServerURL).RegistrationStatus(ctx, token)
	switch {
	case err == nil && resp.Status == wire.StatusActive:
		return "authorized", "authorized"
	case err == nil && resp.Status == wire.StatusPending:
		return "pending", "pending authorization"
	case err == nil:
		return resp.Status, resp.Status
	case isUnknownToken(err):
		return "not-registered", "not registered (the Server rejected this token; it was removed or revoked there)"
	default:
		return "unknown", fmt.Sprintf("unknown (could not reach %s: %v)", cfg.ServerURL, err)
	}
}

// isUnknownToken reports whether err is the Server's unknown-token response.
func isUnknownToken(err error) bool {
	apiErr, ok := errors.AsType[*serverapi.APIError](err)
	return ok && apiErr.Code == wire.CodeUnknownToken
}

// cmdPlugin dispatches the plugin subcommands. Plugins are fetched from the
// Server's Marketplace on demand; nothing is bundled into this binary.
func cmdPlugin(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: easyssl-agent plugin <catalog|install|list> [flags]")
	}
	switch args[0] {
	case "catalog":
		return cmdPluginCatalog(ctx, args[1:])
	case "install":
		return cmdPluginInstall(ctx, args[1:])
	case "list":
		return cmdPluginList(args[1:])
	default:
		return fmt.Errorf("unknown plugin command %q (want catalog, install or list)", args[0])
	}
}

func cmdPluginInstall(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("plugin install", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	yes := fs.Bool("yes", false, "install without the confirmation prompt")
	_ = fs.Parse(args)
	if fs.NArg() == 0 {
		return errors.New("usage: easyssl-agent plugin install <name>... [--yes] [--json]")
	}
	names := fs.Args()

	cfg, err := identity.LoadConfig()
	if err != nil {
		return stateError("plugin install", err)
	}
	token, err := identity.LoadToken()
	if err != nil {
		return stateError("plugin install", err)
	}

	// Said before anything is installed, because this is the moment the
	// authorization is given and it grants more than it looks like: a Plugin
	// runs with this Agent's privileges, which is root wherever the Agent is
	// a system service, and there is no boundary between the two past the
	// digest check. Skipped for --json, which is a machine's call,
	// and for --yes, which is the person saying they know.
	if !*asJSON && !*yes {
		// One line per paragraph, wrapped by the terminal rather than here. A
		// fixed width is a guess about a window this program cannot see: on a
		// narrower one every line is folded again a few words from its end, and
		// the result reads as a ragged column with words split across it, which
		// is the opposite of what wrapping the text was meant to achieve.
		fmt.Fprintf(os.Stderr,
			"Installing %s on this host.\n\n"+
				"A Plugin runs with this Agent's privileges, which is root wherever the "+
				"Agent runs as a system service. Authorizing this install authorizes code "+
				"execution at that level on this host: a Plugin can read and write private "+
				"key material and restart services. The Server's digest check is the only "+
				"boundary, and it answers whether the artifact is the one easySSL published, "+
				"not what it can do.\n\n",
			strings.Join(names, ", "))
		ok, err := confirm("Install and run it with those privileges?")
		if err != nil {
			return err
		}
		if !ok {
			fmt.Fprintln(os.Stderr, "Nothing installed.")
			return nil
		}
	}

	mgr := pluginmgr.New(
		pluginmgr.HTTPCatalog{BaseURL: cfg.ServerURL},
		serverapi.New(cfg.ServerURL),
	)
	// The host's own platform: an Agent installs for the machine it runs on,
	// never for another, so there is no flag to get this wrong.
	out := make([]pluginmgr.Installed, 0, len(names))
	for _, name := range names {
		inst, ierr := mgr.Install(ctx, token, name, runtime.GOOS, runtime.GOARCH)
		if ierr != nil {
			// Whatever was installed before this one stays installed and is
			// reported, so a partial run says what it did rather than only
			// what it could not do.
			if !*asJSON {
				printInstalled(out, cfg.ServerURL)
			}
			return ierr
		}
		out = append(out, inst)
	}
	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(out)
	}
	printInstalled(out, cfg.ServerURL)
	return nil
}

func printInstalled(out []pluginmgr.Installed, serverURL string) {
	for _, inst := range out {
		fmt.Printf("installed  %s v%s\n", inst.ID, inst.Version)
		fmt.Printf("path       %s\n", inst.Path)
		fmt.Printf("digest     sha256:%s\n", inst.Digest)
		fmt.Printf("reported   to %s\n", serverURL)
	}
}

// confirm asks a yes/no question on the terminal. A closed stdin answers no:
// a non-interactive run that reached this prompt did not mean to install.
func confirm(question string) (bool, error) {
	fmt.Fprintf(os.Stderr, "%s [y/N] ", question)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return false, nil //nolint:nilerr // no answer is not an answer of yes
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	}
	return false, nil
}

// cmdPluginCatalog lists what the Marketplace offers for this host, so a Plugin
// can be found and installed without knowing its name in advance.
func cmdPluginCatalog(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("plugin catalog", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	_ = fs.Parse(args)

	cfg, err := identity.LoadConfig()
	if err != nil {
		return stateError("plugin catalog", err)
	}
	catalog, err := pluginmgr.HTTPCatalog{BaseURL: cfg.ServerURL}.Fetch(ctx)
	if err != nil {
		return err
	}
	entries := catalog.Plugins
	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(entries)
	}
	if len(entries) == 0 {
		fmt.Println("The Marketplace offers no Plugins for this host's platform.")
		return nil
	}
	for _, e := range entries {
		fmt.Printf("%-16s v%-10s %s\n", e.ID, e.Version, e.Party)
		if e.Description != "" {
			fmt.Printf("%-16s %s\n", "", e.Description)
		}
		if e.Publisher != "" {
			fmt.Printf("%-16s by %s\n", "", e.Publisher)
		}
		if e.SourceURL != "" {
			fmt.Printf("%-16s %s\n", "", e.SourceURL)
		}
		fmt.Println()
	}
	fmt.Println("Install one with: easyssl-agent plugin install <name>")
	return nil
}

func cmdPluginList(args []string) error {
	fs := flag.NewFlagSet("plugin list", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	_ = fs.Parse(args)

	mgr := pluginmgr.New(nil, nil)
	installed, err := mgr.List()
	if err != nil {
		return err
	}
	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(installed)
	}
	if len(installed) == 0 {
		fmt.Println("No Plugins installed. Install one with: easyssl-agent plugin install generic-cli")
		return nil
	}
	for _, p := range installed {
		fmt.Println(pluginListLine(p))
	}
	return nil
}

func pluginListLine(p pluginmgr.Installed) string {
	return fmt.Sprintf("%-16s v%-10s sha256:%s", p.ID, p.Version, p.Digest)
}
