// Command easyssl-agent is the easySSL Agent binary. A host runs one Agent, so
// the commands need no instance selector. The CLI writes human output to
// stdout, JSON where asked, and errors to stderr; connections are only ever
// made from Agent to Server, never the reverse.
//
// What a command says to a person is in the host's language (internal/msg).
// JSON output, the service's logs and everything sent to the Server are the
// same in every language.
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

	"github.com/easyssl-io/easyssl-contract/catalog"

	"github.com/easyssl-io/easyssl-agent/internal/commands"
	"github.com/easyssl-io/easyssl-agent/internal/csr"
	"github.com/easyssl-io/easyssl-agent/internal/deploy"
	"github.com/easyssl-io/easyssl-agent/internal/flow"
	"github.com/easyssl-io/easyssl-agent/internal/identity"
	"github.com/easyssl-io/easyssl-agent/internal/inventory"
	"github.com/easyssl-io/easyssl-agent/internal/keystore"
	"github.com/easyssl-io/easyssl-agent/internal/msg"
	"github.com/easyssl-io/easyssl-agent/internal/pluginmgr"
	"github.com/easyssl-io/easyssl-agent/internal/plugintrace"
	"github.com/easyssl-io/easyssl-agent/internal/sdnotify"
	"github.com/easyssl-io/easyssl-agent/internal/serverapi"
	"github.com/easyssl-io/easyssl-agent/internal/service"
	"github.com/easyssl-io/easyssl-contract/l10n"
	"github.com/easyssl-io/easyssl-contract/plugincontract"
	"github.com/easyssl-io/easyssl-contract/wire"
)

func main() {
	// Before anything is said, usage and refusals included.
	msg.SetLanguage(commandLanguage())
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
	case "language":
		err = cmdLanguage(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintln(os.Stderr, "easyssl-agent: "+msg.T("main.unknown_command", "unknown command \"{command}\"", "command", os.Args[1]))
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "easyssl-agent: "+err.Error())
		if flow.Unchanged(err) {
			os.Exit(exitUnchanged)
		}
		os.Exit(1)
	}
}

// exitUnchanged is the status of a `register` that failed before it changed
// anything on the host. The install script restores the Agent build it
// replaced on this status and on no other.
const exitUnchanged = 3

func usage() {
	fmt.Fprintln(os.Stderr, msg.T("main.usage", "usage: easyssl-agent <register|run|status|uninstall|plugin|language> [flags]"))
}

// commandLanguage is the language this run speaks: EASYSSL_LANG when it names a
// supported one, else the language saved on this host, else the operating
// system locale's, else English.
//
// A configuration that cannot be read counts as no saved language, not a
// failure: nothing may be registered yet, or the caller may not be root, and
// the refusal that follows is still said in the locale's language.
func commandLanguage() string {
	saved := ""
	if cfg, err := identity.LoadConfig(); err == nil {
		saved = cfg.Language
	}
	lang, _, _ := msg.Resolve("", os.Getenv(msg.EnvVar), saved, os.Getenv)
	return lang
}

// newFlagSet words the heading of `--help` as a message. What the flag package
// itself writes under it, the default values and its own parse errors, stays in
// English.
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), msg.T("main.flags_heading", "Flags of easyssl-agent {command}:", "command", name))
		fs.PrintDefaults()
	}
	return fs
}

// rootPreflight refuses every operational command before it parses flags, reads
// a path, or contacts the Server. All Agent state is under a root-only
// directory, so waiting for the filesystem error would leak which file was
// reached first and give equivalent commands inconsistent failures.
func rootPreflight(args []string, euid int) error {
	cmd := rootCommand(args)
	if euid == 0 || cmd == "" {
		return nil
	}
	if cmd == "register" {
		// Registration has to name both routes to root: a host operator may
		// already be in a root shell on a system where sudo is not installed.
		return msg.Err.T("main.register_not_root", "register must run as root: use sudo, or run it from a root shell")
	}
	return rootOnlyError(cmd)
}

// rootCommand returns only recognized commands that can read or change Agent
// state, so the early gate is reviewable as one complete list. Help, incomplete
// groups and unknown commands keep their normal usage errors.
func rootCommand(args []string) string {
	if len(args) == 0 {
		return ""
	}
	switch args[0] {
	case "register", "run", "status", "uninstall", "language":
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
	return msg.Err.T("main.root_only", "this command requires root; re-run as root with \"sudo easyssl-agent {command}\"", "command", cmd)
}

func cmdRegister(ctx context.Context, args []string) error {
	fs := newFlagSet("register")
	server := fs.String("server", "", msg.T("register.flag.server", "easySSL Server base URL (required)"))
	key := fs.String("registration-key", os.Getenv(wire.EnvRegistrationKey), msg.T("register.flag.key", "Organization registration key (defaults to ${env})", "env", wire.EnvRegistrationKey))
	reactivation := fs.String("reactivation-token", os.Getenv(wire.EnvReactivationToken), msg.T("register.flag.reactivation_token", "reactivation token from a deactivated Agent's page, to resume that Agent (defaults to ${env})", "env", wire.EnvReactivationToken))
	name := fs.String("agent-name", os.Getenv(wire.EnvAgentName), msg.T("register.flag.name", "Agent name (defaults to ${env}, else the hostname; prompted when interactive; ignored with a reactivation token)", "env", wire.EnvAgentName))
	// No default from EASYSSL_LANG, unlike the flags above: the variable only
	// pre-selects what the language step offers, because every install command
	// the web console gives carries it, and the flag is what skips the step.
	lang := fs.String("lang", "", msg.T("register.flag.lang", "language of this Agent's commands, set without asking: {supported} (otherwise asked, defaulting to $EASYSSL_LANG, then the language already saved on this host, then the locale's)", "supported", msg.SupportedList()))
	// A refusal here wrote nothing, so it exits with the status that tells the
	// install script to put back the build it replaced.
	fs.Init("register", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return flow.RefusedUnchanged(err)
	}
	if *server == "" {
		return flow.RefusedUnchanged(msg.Err.T("register.server_required", "register: --server is required"))
	}
	return flow.Register(ctx, flow.Options{ServerURL: *server, RegistrationKey: *key, ReactivationToken: *reactivation, Name: *name, Language: *lang})
}

func cmdUninstall(ctx context.Context, args []string) error {
	fs := newFlagSet("uninstall")
	yes := fs.Bool("yes", false, msg.T("uninstall.flag.yes", "do not ask for confirmation"))
	_ = fs.Parse(args)
	return flow.Uninstall(ctx, *yes)
}

// cmdLanguage prints the language saved on this host, or saves another.
func cmdLanguage(args []string) error {
	fs := newFlagSet("language")
	_ = fs.Parse(args)
	if fs.NArg() > 1 {
		return msg.Err.T("language.usage", "usage: easyssl-agent language [<code>]")
	}
	cfg, err := identity.LoadConfig()
	if err != nil {
		return stateError("language", err)
	}
	if fs.NArg() == 0 {
		if saved, ok := l10n.Base(cfg.Language); ok {
			fmt.Println(msg.Describe(saved))
			return nil
		}
		fmt.Println(msg.T("language.none_saved", "No language is saved on this host, so its commands speak {language}, from $EASYSSL_LANG or the locale. Save one with: sudo easyssl-agent language <code>", "language", msg.Describe(msg.Language())))
		return nil
	}
	lang, err := msg.Parse(fs.Arg(0))
	if err != nil {
		return err
	}
	cfg.Language = lang
	if err := identity.SaveConfig(cfg); err != nil {
		return msg.Err.T("language.save", "saving the language: {err}", "err", err)
	}
	// Said in the language just saved, which is the first proof it took.
	msg.SetLanguage(lang)
	fmt.Println(msg.T("language.saved", "✓ This host's Agent commands now speak {language}.", "language", msg.Describe(lang)))
	return nil
}

func cmdRun(ctx context.Context, args []string) error {
	fs := newFlagSet("run")
	_ = fs.Parse(args)
	cfg, err := identity.LoadConfig()
	if err != nil {
		return stateError("run", err)
	}
	token, err := identity.LoadToken()
	if err != nil {
		return stateError("run", err)
	}

	api, err := serverapi.New(cfg.ServerURL)
	if err != nil {
		return stateError("run", err)
	}
	// From here on this process is the service: its log and its reports to the
	// Server read the same on every host. Only the refusals to start, above, are
	// said in the host's language.
	msg.SetLanguage(l10n.English)

	logger := agentLogger()
	// So key generation is reported in the same format as everything else the
	// service writes, rather than through the default handler.
	keystore.SetLogger(logger)
	// A command type with no handler here is reported unsupported, which is
	// also what an Agent older than its Server does.
	plugins := pluginmgr.New(nil, logger)
	runner := commands.NewRunner(api, token, logger, map[string]commands.Handler{
		wire.CommandRequestCSR: csr.New(api, token, logger),
		wire.CommandDeploy:     deploy.New(api, plugins, token, logger),
	})

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var streaming sync.Once

	// Under Type=notify systemd waits for this before calling the service
	// started; a no-op anywhere else (see sdnotify).
	sdnotify.Ready()
	sdnotify.Status("Checking in.")

	// Set once when the token stops being accepted, so the message is written at
	// error level the first time and rarely after that: the condition does not
	// change on its own, and a line a minute would bury the journal.
	removedSince := time.Time{}

	poll := 60
	for {
		// The fingerprint on the wire is always over the whole current inventory; the
		// document itself goes only when the Server says it lacks it. A contributor
		// that could not be read leaves the fingerprint empty, so the Server keeps
		// its last document rather than one with a hole.
		inv, invErr := inventory.Collect(ctx, plugins)
		fingerprint := inv.Fingerprint
		if invErr != nil {
			logger.Warn("host inventory not computed this check-in", "err", invErr)
			fingerprint = ""
		}
		resp, err := api.Checkin(ctx, token, flow.CheckinBody(fingerprint))
		if err == nil {
			if !removedSince.IsZero() {
				// Only a new registration while the service ran recovers a revoked token.
				// Say so, since the last thing the log said was the opposite.
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
				// The language may have been changed on the host since this
				// service read the configuration, and writing the copy held
				// here would undo that.
				if current, err := identity.LoadConfig(); err == nil {
					cfg.Language = current.Language
				}
				if err := identity.SaveConfig(cfg); err != nil {
					logger.Warn("could not record the Organization name", "err", err)
				}
			}
			poll = resp.NextPollSeconds
			if resp.ReportInventory && fingerprint != "" {
				if err := api.ReportInventory(ctx, token, inv); err != nil {
					// The next check-in's fingerprint still disagrees with the
					// Server's, so it asks again; nothing to retry here.
					logger.Warn("host inventory not accepted", "err", err)
				} else {
					logger.Info("host inventory reported", "plugins", len(inv.Plugins), "keys", len(inv.Keys))
				}
			}
			if resp.Status == wire.AgentStatusActive {
				// Only now: every push-channel route refuses an Agent still awaiting
				// authorization, as the check-in does, so subscribing earlier would loop on
				// 401s.
				streaming.Do(func() { go streamCommands(ctx, api, token, runner, logger) })
				if shouldReconcile(resp) {
					runner.Reconcile(ctx)
				}
			}
		} else if isUnknownToken(err) {
			// Deactivated or removed in the web console. The service keeps running and
			// stops doing work: this Agent belongs to the host, so a decision taken in
			// the web console does not stop a unit, remove a file, or leave a failed
			// unit in `systemctl --failed` on a host that is behaving correctly.
			// Uninstalling stays the operator's action, and the message names every way
			// out: the reactivation command from the Agent's page in the web console
			// (the same Agent again), the installer with the registration key (a new
			// one), or uninstalling.
			if removedSince.IsZero() {
				removedSince = time.Now()
				logger.Error("this host is no longer registered with the Server: the Agent was deactivated or removed, so its token is refused",
					"server", cfg.ServerURL,
					"next", "run the reactivation command from the Agent's page in the web console to resume this Agent, re-run the installer with the registration key to register a new one, or remove this Agent with `easyssl-agent uninstall`",
					"note", "no work will be done until then; nothing under "+identity.ConfigDir+" or "+identity.StateDir+" has been touched")
				sdnotify.Status("Not registered: the Agent was deactivated or removed. Run the reactivation command from its page in the web console, re-run the installer to register anew, or `easyssl-agent uninstall`.")
			} else if time.Since(removedSince) > 30*time.Minute {
				removedSince = time.Now()
				logger.Error("still not registered with the Server; reactivate this Agent from the web console, re-run the installer, or uninstall it",
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

// agentLogger writes to stderr, which systemd captures into the journal, at the
// level EASYSSL_LOG_LEVEL asks for. The service and the subcommands an operator
// runs by hand share it, so `easyssl-agent plugin install` shows the same
// Plugin exchange the service would log.
//
// The level and the format are environment variables rather than flags so that
// turning debug on needs no edit to the shipped unit: `systemctl edit
// easyssl-agent`, one Environment= line, restart. Neither changes the Agent's
// behavior, only how much is written and in what shape.
func agentLogger() *slog.Logger {
	return slog.New(plugintrace.Handler(os.Stderr,
		os.Getenv(plugintrace.LevelEnv), os.Getenv(plugintrace.FormatEnv)))
}

// shouldReconcile decides whether a check-in has to be followed by the
// reconcile fetch. Only a reported zero skips it: the Server has nothing
// outstanding for this host, which on a mostly idle fleet saves one request
// per Agent per cadence.
//
// nil is not zero. It is an older Server that does not report the count, and
// reading it as zero would make this Agent stop fetching commands from that
// Server and never notice.
//
// The count may be stale, because a command can be created right after it was
// taken. That costs at most one cadence: the event stream nudges, and the next
// check-in counts again. A stale count delays work rather than inventing or
// losing it.
func shouldReconcile(resp wire.CheckinResponse) bool {
	return resp.PendingCommands == nil || *resp.PendingCommands > 0
}

// streamCommands keeps the event stream open for as long as the service runs,
// reconciling on connect and on every command the Server pushes.
//
// A dropped stream is ordinary: networks and proxies close idle connections,
// and the check-in loop keeps delivering commands meanwhile. So this
// reconnects quietly and never ends the service. The one thing it does not
// retry is a rejected credential, which no amount of waiting repairs.
func streamCommands(ctx context.Context, api *serverapi.Client, token string, runner *commands.Runner, logger *slog.Logger) {
	const (
		minBackoff = 2 * time.Second
		maxBackoff = 5 * time.Minute
		// A stream that stayed up this long proves the Server is reachable, so the
		// next drop starts over at the short delay. Otherwise the delay only grows,
		// and an Agent connected for weeks would wait the maximum after a routine
		// proxy timeout.
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
			// The event is a nudge and carries nothing; Reconcile reads authoritative
			// state.
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

// stateError explains why the Agent's on-disk state could not be read. The raw
// "permission denied" on config.json sends people hunting for a filesystem
// problem, when the state is deliberately root-only (0600 under a 0700
// directory) so an unprivileged process cannot read the bearer token.
func stateError(cmd string, err error) error {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return msg.Err.T("main.not_registered", "no easySSL Agent is registered on this host ({path} does not exist); register one with \"sudo easyssl-agent register --server <url>\"", "path", identity.ConfigPath())
	case errors.Is(err, fs.ErrPermission):
		return rootOnlyError(cmd)
	}
	return fmt.Errorf("%s: %w", cmd, err)
}

func cmdStatus(args []string) error {
	fs := newFlagSet("status")
	_ = fs.Parse(args)

	cfg, err := identity.LoadConfig()
	if err != nil {
		return stateError("status", err)
	}
	token, tokenErr := identity.LoadToken()

	// Whether the Agent is still registered is the Server's to say: it can drop an
	// Agent without telling the host, so a stored token proves only that one was
	// issued once. This is a GET, not a check-in, so status never refreshes
	// last-seen and cannot make a stopped Agent look alive in the web console.
	stateDetail, reg := serverState(cfg, token, tokenErr)
	serviceName, _, _ := service.Describe()

	line := func(label, value string) { fmt.Printf("%-12s %s\n", label, value) }
	// The id and name are the Server's to say, so they are printed only when
	// it answered; a host holds neither.
	if reg.AgentID != "" {
		line(msg.T("status.label.agent", "Agent"), reg.AgentID)
	}
	if reg.DisplayName != "" {
		line(msg.T("status.label.name", "name"), reg.DisplayName)
	}
	line(msg.T("status.label.server", "Server"), cfg.ServerURL)
	if cfg.OrganizationName != "" || cfg.OrganizationID != "" {
		line(msg.T("status.label.organization", "Organization"), cfg.Organization())
	}
	// The state is the init system's own word for it, shown as it gave it.
	line(msg.T("status.label.service", "service"), fmt.Sprintf("%s (%s)", serviceName, service.State()))
	if tokenErr == nil {
		line(msg.T("status.label.token", "token"), msg.T("status.token.stored", "stored in {path}", "path", identity.TokenPath()))
	} else {
		line(msg.T("status.label.token", "token"), msg.T("status.token.missing", "missing, so this Agent cannot authenticate"))
	}
	line(msg.T("status.label.state", "state"), stateDetail)
	return nil
}

// serverState asks the Server what this Agent is right now, which a host cannot
// tell from its own files: it has no way to know it was removed in the web
// console. The read also carries the Agent's id and name, the only place the
// host learns them. Read-only, so status has no side effects.
//
// It returns a short stable code for machines and a sentence for people. The
// wire calls an authorized Agent "active", which next to a stopped systemd unit
// reads as if the Agent were running, so this says "Authorized" as the web
// console does.
func serverState(cfg identity.Config, token string, tokenErr error) (detail string, reg wire.RegistrationStatus) {
	if tokenErr != nil {
		return msg.T("status.state.no_token", "not registered (no local token)"), reg
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	api, err := serverapi.New(cfg.ServerURL)
	if err != nil {
		return msg.T("status.state.bad_url", "unknown ({err})", "err", err), reg
	}
	resp, err := api.RegistrationStatus(ctx, token)
	switch {
	case err == nil && resp.Status == wire.AgentStatusActive:
		return msg.T("status.state.authorized", "authorized"), resp
	case err == nil && resp.Status == wire.AgentStatusPending:
		return msg.T("status.state.pending", "pending authorization"), resp
	case err == nil:
		return resp.Status, resp
	case isUnknownToken(err):
		return msg.T("status.state.token_rejected", "not registered (the Server rejected this token; the Agent was deactivated or removed there)"), reg
	default:
		return msg.T("status.state.unreachable", "unknown (could not reach {server}: {err})", "server", cfg.ServerURL, "err", err), reg
	}
}

func isUnknownToken(err error) bool {
	apiErr, ok := errors.AsType[*serverapi.APIError](err)
	return ok && apiErr.Code == wire.CodeUnknownToken
}

// cmdPlugin dispatches the plugin subcommands. Plugins are fetched from the
// Server's Marketplace on demand; nothing is bundled into this binary.
func cmdPlugin(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return msg.Err.T("plugin.usage", "usage: easyssl-agent plugin <catalog|install|list> [flags]")
	}
	switch args[0] {
	case "catalog":
		return cmdPluginCatalog(ctx, args[1:])
	case "install":
		return cmdPluginInstall(ctx, args[1:])
	case "list":
		return cmdPluginList(args[1:])
	default:
		return msg.Err.T("plugin.unknown_command", "unknown plugin command \"{command}\" (want catalog, install or list)", "command", args[0])
	}
}

func cmdPluginInstall(ctx context.Context, args []string) error {
	fs := newFlagSet("plugin install")
	yes := fs.Bool("yes", false, msg.T("plugin.install.flag.yes", "install without the confirmation prompt"))
	_ = fs.Parse(args)
	if fs.NArg() == 0 {
		return msg.Err.T("plugin.install.usage", "usage: easyssl-agent plugin install <name>... [--yes]")
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

	// Said before anything is installed, because this is when the authorization is
	// given and it grants more than it looks like: a Plugin runs with this Agent's
	// privileges, root wherever the Agent is a system service, with no boundary
	// between the two past the digest check. Skipped for --yes, the person saying
	// they know.
	if !*yes {
		// One line per paragraph, wrapped by the terminal. A fixed width is a guess
		// about a window this program cannot see: on a narrower one every line folds
		// again a few words from its end.
		fmt.Fprintln(os.Stderr, msg.T("plugin.install.warning",
			"Installing {plugins} on this host.\n\n"+
				"A Plugin runs with this Agent's privileges, which is root wherever the "+
				"Agent runs as a system service. Authorizing this install authorizes code "+
				"execution at that level on this host: a Plugin can read and write private "+
				"key material and restart services. The Server's digest check is the only "+
				"boundary, and it answers whether the artifact is the one easySSL published, "+
				"not what it can do.\n",
			"plugins", strings.Join(names, ", ")))
		if !confirm(msg.T("plugin.install.confirm", "Install and run it with those privileges? [y/N] ")) {
			// An error, so a script that reached the prompt without --yes does not
			// read "nothing installed" as success.
			return msg.Err.T("plugin.install.declined", "Nothing installed.")
		}
	}

	api, err := serverapi.New(cfg.ServerURL)
	if err != nil {
		return err
	}
	mgr := pluginmgr.New(pluginmgr.HTTPCatalog{BaseURL: cfg.ServerURL}, agentLogger())
	// The host's own platform: an Agent installs for the machine it runs on,
	// never for another, so there is no flag to get this wrong.
	out := make([]pluginmgr.Installed, 0, len(names))
	var installErr error
	for _, name := range names {
		inst, ierr := mgr.Install(ctx, name, runtime.GOOS, runtime.GOARCH)
		if ierr != nil {
			// Whatever was installed before this one stays installed and is reported, so
			// a partial run says what it did.
			installErr = ierr
			break
		}
		out = append(out, inst)
	}
	// The service would send the inventory on its next check-in; sending it here
	// makes the web console current within one round trip rather than one cadence.
	// Best-effort: after a failure the service's next check-in disagrees with the
	// Server, which then asks for the document.
	var reportErr error
	if len(out) > 0 {
		inv, err := inventory.Collect(ctx, mgr)
		if err == nil {
			err = api.ReportInventory(ctx, token, inv)
		}
		reportErr = err
	}
	reported := msg.T("plugin.install.reported", "reported   to {server}", "server", cfg.ServerURL)
	if reportErr != nil {
		reported = msg.T("plugin.install.not_reported", "reported   not yet ({err}); the service reports on its next check-in", "err", reportErr)
	}
	printInstalled(out, reported)
	return installErr
}

// printInstalled prints each installed Plugin as labeled lines. Each line is
// one message, label included, so a translation keeps the values in one column
// with labels of its own length. reported is the last line, already worded by
// the caller.
func printInstalled(out []pluginmgr.Installed, reported string) {
	for _, inst := range out {
		fmt.Println(msg.T("plugin.install.done.installed", "installed  {id} v{version}", "id", inst.ID, "version", inst.Version))
		fmt.Println(msg.T("plugin.install.done.path", "path       {path}", "path", inst.Path))
		fmt.Println(msg.T("plugin.install.done.digest", "digest     sha256:{digest}", "digest", inst.Digest))
		fmt.Println(reported)
	}
}

// confirm asks a yes/no question on the terminal; the question carries its
// own hint, `[y/N]` in English. A closed stdin answers no: a non-interactive
// run that reached this prompt did not mean to install.
func confirm(question string) bool {
	fmt.Fprint(os.Stderr, question)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return false // no answer is not an answer of yes
	}
	return msg.Yes(line)
}

// cmdPluginCatalog lists what the Marketplace offers for this host, so a Plugin
// can be found and installed without knowing its name in advance.
func cmdPluginCatalog(ctx context.Context, args []string) error {
	fs := newFlagSet("plugin catalog")
	_ = fs.Parse(args)

	cfg, err := identity.LoadConfig()
	if err != nil {
		return stateError("plugin catalog", err)
	}
	offered, err := pluginmgr.HTTPCatalog{BaseURL: cfg.ServerURL}.Fetch(ctx)
	if err != nil {
		return err
	}
	// Only what this host could install: an entry with no build for its platform
	// would fail at install with nothing to show for it.
	var entries []catalog.Plugin
	for _, e := range offered.Plugins {
		if pluginmgr.HasArtifact(e, runtime.GOOS, runtime.GOARCH) {
			entries = append(entries, e)
		}
	}
	if len(entries) == 0 {
		fmt.Println(msg.T("plugin.catalog.empty", "The Marketplace offers no Plugins for this host's platform."))
		return nil
	}
	for _, e := range entries {
		fmt.Printf("%-16s v%-10s %s\n", e.ID, e.Version, e.Party)
		// The Plugin's own text, in this host's language when the Plugin
		// supplies it and in English otherwise.
		if description := e.Description.In(msg.Language()); description != "" {
			fmt.Printf("%-16s %s\n", "", description)
		}
		if e.Publisher != "" {
			fmt.Printf("%-16s %s\n", "", msg.T("plugin.catalog.publisher", "by {publisher}", "publisher", e.Publisher))
		}
		if e.SourceURL != "" {
			fmt.Printf("%-16s %s\n", "", e.SourceURL)
		}
		fmt.Println()
	}
	fmt.Println(msg.T("plugin.catalog.install_hint", "Install one with: easyssl-agent plugin install <name>"))
	return nil
}

func cmdPluginList(args []string) error {
	fs := newFlagSet("plugin list")
	_ = fs.Parse(args)

	// What the host inventory would carry now: the executables on disk and
	// what each answers, since that is the only record there is.
	installed, err := pluginmgr.New(nil, nil).Discover(context.Background())
	if err != nil {
		return err
	}
	if len(installed) == 0 {
		fmt.Println(msg.T("plugin.list.empty", "No Plugins installed. Install one with: easyssl-agent plugin install generic-cli"))
		return nil
	}
	for _, p := range installed {
		fmt.Println(pluginListLine(p))
	}
	return nil
}

func pluginListLine(p wire.PluginInventory) string {
	if p.Unobserved {
		return msg.T("plugin.list.unobserved", "{id} {version} sha256:{digest}  (did not answer discover)",
			"id", fmt.Sprintf("%-16s", p.ID), "version", fmt.Sprintf("%-11s", "?"), "digest", p.SHA256)
	}
	var desc plugincontract.DescribeResponse
	_ = json.Unmarshal(p.Describe, &desc) // checked already by Discover
	return fmt.Sprintf("%-16s v%-10s sha256:%s", p.ID, desc.Version, p.SHA256)
}
