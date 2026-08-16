// Command easyssl-client is the easySSL Client binary. Subcommands:
//
//	register --server <url> [--key <key>] [--name <name>]   interactive registration
//	run                                                     the systemd service loop (periodic check-in)
//	status [--json]                                         print local state + what the Server says
//	uninstall [--yes]                                       unregister and remove the Client
//	plugin install <name> [--json]                          fetch a plugin from the Marketplace and report it
//	plugin list [--json]                                    what this host has installed
//
// A host runs one Client, so the commands need no instance selector. The CLI
// writes human output to stdout, JSON where asked, and errors to stderr;
// connections are only ever made from Client to Server, never the reverse.
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

	"github.com/easyssl-io/easyssl-client/internal/commands"
	"github.com/easyssl-io/easyssl-client/internal/csr"
	"github.com/easyssl-io/easyssl-client/internal/deploy"
	"github.com/easyssl-io/easyssl-client/internal/flow"
	"github.com/easyssl-io/easyssl-client/internal/identity"
	"github.com/easyssl-io/easyssl-client/internal/keystore"
	"github.com/easyssl-io/easyssl-client/internal/pluginmgr"
	"github.com/easyssl-io/easyssl-client/internal/serverapi"
	"github.com/easyssl-io/easyssl-client/internal/sysd"
	"github.com/easyssl-io/easyssl-contract/wire"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
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
		fmt.Fprintf(os.Stderr, "easyssl-client: unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "easyssl-client: "+err.Error())
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: easyssl-client <register|run|status|uninstall|plugin> [flags]")
}

func cmdRegister(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("register", flag.ExitOnError)
	server := fs.String("server", "", "easySSL Server base URL (required)")
	key := fs.String("key", os.Getenv("REGISTRATION_KEY"), "organization registration key (defaults to $REGISTRATION_KEY)")
	name := fs.String("name", os.Getenv("CLIENT_NAME"), "Client name (defaults to $CLIENT_NAME, else the hostname; prompted when interactive)")
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
	// also what a Client older than its Server does.
	runner := commands.NewRunner(api, token, logger, map[string]commands.Handler{
		wire.CommandRequestCSR: csr.New(api, token, logger),
		wire.CommandDeploy:     deploy.New(api, pluginmgr.New(nil, nil), token, logger),
	})

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var streaming sync.Once

	poll := 60
	for {
		resp, err := api.Checkin(ctx, token, wire.CheckinRequest{ClientVersion: flow.Version})
		if err == nil {
			poll = resp.NextPollSeconds
			if resp.Status == wire.StatusActive {
				// Only now: every push-channel route refuses a Client that is
				// still awaiting authorization, exactly as the check-in does,
				// so subscribing earlier would just loop on 401s.
				streaming.Do(func() { go streamCommands(ctx, api, token, runner, logger) })
				runner.Reconcile(ctx)
			}
		} else if isUnknownToken(err) {
			// Rejected or revoked: stop cleanly so systemd does not restart-loop.
			fmt.Fprintln(os.Stderr, "run: token rejected or revoked; re-registration required")
			return nil
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
func streamCommands(ctx context.Context, api *serverapi.Client, token string, runner *commands.Runner, logger *slog.Logger) {
	const (
		minBackoff = 2 * time.Second
		maxBackoff = 5 * time.Minute
		// A stream that stayed up this long proves the Server is reachable, so
		// the next drop starts over at the short delay. Without it the delay
		// only ever grows: a Client up for weeks would wait the maximum after a
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
		}, func(commandID string) {
			// The id is a nudge, not the work. Reconcile reads authoritative
			// state, which also picks up anything this Client missed.
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
		// Info, not Debug: a Client that can never hold the stream open looks
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

// stateError explains why the Client's on-disk state could not be read. The two
// common causes have obvious fixes, but the raw "permission denied" on
// config.json sends people hunting for a filesystem problem instead: the state
// is deliberately root-only (0600 under a 0700 directory) so an unprivileged
// process cannot read the bearer token.
func stateError(cmd string, err error) error {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("no easySSL Client is registered on this host (%s does not exist); register one with \"sudo easyssl-client register --server <url>\"", identity.ConfigPath())
	case errors.Is(err, fs.ErrPermission):
		return fmt.Errorf("cannot read %s: the Client's config and token are root-only; re-run as root with \"sudo easyssl-client %s\"", identity.BaseDir, cmd)
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

	// Whether the Client is still registered is not a local fact: the Server
	// owns it and can drop a Client without telling the host, so a stored token
	// proves only that one was issued once. Ask the Server. This is a read
	// (GET), not a check-in, so running status never refreshes last-seen and
	// therefore cannot make a stopped Client look alive in the console.
	stateCode, stateDetail := serverState(cfg, token, tokenErr)

	if *asJSON {
		out := map[string]any{
			"clientId":     cfg.ClientID,
			"displayName":  cfg.DisplayName,
			"serverUrl":    cfg.ServerURL,
			"serviceName":  identity.ServiceName(),
			"serviceState": sysd.State(),
			"tokenPresent": tokenErr == nil,
			// Short code for machines; the printed line spells it out.
			"serverState": stateCode,
		}
		return json.NewEncoder(os.Stdout).Encode(out)
	}

	fmt.Printf("client     %s\n", cfg.ClientID)
	fmt.Printf("name       %s\n", cfg.DisplayName)
	fmt.Printf("server     %s\n", cfg.ServerURL)
	fmt.Printf("service    %s (%s)\n", identity.ServiceName(), sysd.State())
	if tokenErr == nil {
		fmt.Printf("token      stored in %s\n", identity.TokenPath())
	} else {
		fmt.Printf("token      missing, so this Client cannot authenticate\n")
	}
	fmt.Printf("state      %s\n", stateDetail)
	return nil
}

// serverState asks the Server what this Client actually is right now, which a
// host cannot tell from its own files: it has no way to know it was removed
// from the console. Read-only, so status stays free of side effects.
//
// It returns a short stable code for machines and a sentence for people. The
// wire calls an authorized Client "active", which printed next to a stopped
// systemd unit reads as if the Client were running, when it only means the
// operator admitted it; the console says "Authorized" and so does this.
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
		return errors.New("usage: easyssl-client plugin <catalog|install|list> [flags]")
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
		return errors.New("usage: easyssl-client plugin install <name>... [--yes] [--json]")
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
	// runs with this Client's privileges, which is root wherever the Client is
	// a system service, and there is no boundary between the two past the
	// digest check (FR-008c). Skipped for --json, which is a machine's call,
	// and for --yes, which is the person saying they know.
	if !*asJSON && !*yes {
		// One line per paragraph, wrapped by the terminal rather than here. A
		// fixed width is a guess about a window this program cannot see: on a
		// narrower one every line is folded again a few words from its end, and
		// the result reads as a ragged column with words split across it, which
		// is the opposite of what wrapping the text was meant to achieve.
		fmt.Fprintf(os.Stderr,
			"Installing %s on this host.\n\n"+
				"A Plugin runs with this Client's privileges, which is root wherever the "+
				"Client runs as a system service. Authorizing this install authorizes code "+
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
	// The host's own platform: a Client installs for the machine it runs on,
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
// can be found and installed without knowing its name in advance (FR-005,
// FR-007).
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
	fmt.Println("Install one with: easyssl-client plugin install <name>")
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
		fmt.Println("No plugins installed. Install one with: easyssl-client plugin install generic-cli")
		return nil
	}
	for _, p := range installed {
		fmt.Printf("%-16s v%-10s sha256:%s\n", p.ID, p.Version, p.Digest[:12]+"…")
	}
	return nil
}
