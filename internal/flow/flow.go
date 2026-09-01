// Package flow drives the interactive line-based registration session.
// A host runs one Agent: the first run generates and persists the
// registers, stores the Server-minted Agent ID and token, installs the systemd unit, and waits
// for the operator to authorize from the web console. A later run on an
// already-registered host is idempotent: it refreshes the service onto the
// updated binary and reports state instead of registering a second Agent. It is
// plain stdin/stdout, no full-screen TUI shell in this slice.
package flow

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/easyssl-io/easyssl-agent/internal/hostinfo"
	"github.com/easyssl-io/easyssl-agent/internal/identity"
	"github.com/easyssl-io/easyssl-agent/internal/keystore"
	"github.com/easyssl-io/easyssl-agent/internal/pluginmgr"
	"github.com/easyssl-io/easyssl-agent/internal/serverapi"
	"github.com/easyssl-io/easyssl-agent/internal/sysd"
	"github.com/easyssl-io/easyssl-contract/wire"
)

// Version is the Agent version reported to the Server.
const Version = "0.0.1"

// Options configures a registration session.
type Options struct {
	ServerURL       string // required
	RegistrationKey string // from --key or REGISTRATION_KEY; prompted if empty and interactive
	Name            string // from --name or AGENT_NAME; else the hostname, editable at the prompt
}

// Register runs the registration session. If this host already has an Agent
// identity it takes the idempotent reinstall path; otherwise it registers a new
// Agent. A context cancellation (Ctrl-C) during the wait is not an error: the
// installed systemd service keeps polling, so authorization can complete later.
func Register(ctx context.Context, opts Options) error {
	// Check root before anything reaches the Server. Registering first and
	// failing afterwards on the config write would leave a pending Agent on
	// the Server for a host that never actually installed one, which an
	// operator then has to notice and clean up.
	if os.Geteuid() != 0 {
		return errors.New("register must run as root: use sudo, or run it from a root shell")
	}

	fmt.Printf("easySSL Agent installer · v%s\n", Version)
	fmt.Println("Registering this host to an easySSL Organization...")
	fmt.Println()

	t := openTerminal()
	if t != nil {
		defer t.close()
	}

	if cfg, err := identity.LoadConfig(); err == nil && cfg.AgentID != "" {
		return reinstall(ctx, t, opts, cfg)
	}
	return freshRegister(ctx, t, opts)
}

// freshRegister registers a host that has no Agent yet.
func freshRegister(ctx context.Context, t *terminal, opts Options) error {
	key, err := resolveKey(t, opts.RegistrationKey)
	if err != nil {
		return err
	}
	host, _ := os.Hostname()
	name, err := confirmName(t, opts.Name, proposedName(host), host)
	if err != nil {
		return err
	}
	// The whole hostname beside the name, because the case for trimming it is
	// that nothing is lost by doing so. Omitted when there is nothing
	// to add: a single-label hostname is already the name.
	if host != "" && host != name {
		fmt.Printf("✓ Agent name  %s  (host %s)\n", name, host)
	} else {
		fmt.Printf("✓ Agent name  %s\n", name)
	}

	api := serverapi.New(opts.ServerURL)
	resp, agentID, err := register(ctx, api, key, name, opts.ServerURL)
	if err != nil {
		return err
	}

	cfg := identity.Config{
		AgentID:          agentID,
		DisplayName:      name,
		ServerURL:        opts.ServerURL,
		OrganizationName: resp.OrganizationName,
		OrganizationID:   resp.OrganizationID,
	}
	if err := identity.SaveConfig(cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	if err := identity.SaveToken(resp.AgentToken); err != nil {
		return fmt.Errorf("save token: %w", err)
	}
	fmt.Printf("✓ Agent token stored in %s\n", identity.TokenPath())

	if err := sysd.Install(); err != nil {
		return fmt.Errorf("installing systemd unit: %w", err)
	}
	fmt.Printf("✓ systemd service installed: %s\n", identity.ServiceName())

	return awaitAuthorization(ctx, api, name, resp.AgentToken, resp.NextPollSeconds,
		marketplaceURL(opts.ServerURL, resp.MarketplaceURL))
}

// reinstall handles a host that is already registered. It reconciles the token
// (re-registering under the same Agent ID if it was removed from the web console),
// then refreshes and restarts the service onto the freshly installed binary, and
// reports state. Reconciling the token BEFORE the restart is essential: restarting
// first would run the service with the stale token, and a revoked token makes the
// service exit (systemd does not auto-restart a clean exit) before the new token
// is written, leaving nothing running even after the operator authorizes.
func reinstall(ctx context.Context, t *terminal, opts Options, cfg identity.Config) error {
	// An installer is downloaded from one Server and carries that Server's URL,
	// so a mismatch means this host belongs to a different one. Continuing
	// against the stored URL is the wrong answer twice over: the operator is
	// watching the web console they installed from, where this host will never
	// appear, and the registration key they supplied belongs to that web console
	// too. Moving the host is not done silently either, because it detaches
	// this host from whatever the old Server still deploys to it.
	if opts.ServerURL != "" && opts.ServerURL != cfg.ServerURL {
		return fmt.Errorf("this host is registered to %s, but this installer came from %s.\n"+
			"Nothing was changed. To move it, remove it from the old Server first:\n"+
			"    sudo easyssl-agent uninstall --yes\n"+
			"then run this installer again", cfg.ServerURL, opts.ServerURL)
	}

	fmt.Printf("This host is already registered as %q (instance %s) on %s.\n",
		cfg.DisplayName, cfg.AgentID, cfg.ServerURL)

	api := serverapi.New(cfg.ServerURL)
	token, status, poll, err := reconcileToken(ctx, t, api, opts, cfg)
	if err != nil {
		return err
	}

	// (Re)start the service now that a valid token is on disk, so it runs the
	// freshly installed binary and keeps polling regardless of whether the
	// operator waits below.
	if err := sysd.Install(); err != nil {
		return fmt.Errorf("updating systemd unit: %w", err)
	}
	fmt.Printf("✓ %s updated and restarted\n", identity.ServiceName())

	switch status {
	case wire.StatusActive:
		fmt.Printf("\n✓ %s is authorized and ACTIVE.\n", cfg.DisplayName)
		return nil
	case "":
		// The URL was checked against the installer's above, so this really is
		// the Server the operator is watching; it just could not be reached.
		fmt.Println("The service will keep polling it, so authorization completes once it is back.")
		return nil
	default: // pending
		return awaitAuthorization(ctx, api, cfg.DisplayName, token, poll,
			marketplaceURL(cfg.ServerURL, ""))
	}
}

// reconcileToken returns a token the service can run with, plus the Agent's
// current status and poll cadence. It checks in with the stored token; if that
// token is missing or was removed from the web console it re-registers under the same
// Agent ID. status is "" (poll unused) when the Server could not be reached.
func reconcileToken(ctx context.Context, t *terminal, api *serverapi.Client, opts Options, cfg identity.Config) (token, status string, poll int, err error) {
	if token, err = identity.LoadToken(); err == nil {
		resp, cerr := api.Checkin(ctx, token, wire.CheckinRequest{AgentVersion: Version})
		switch {
		case cerr == nil:
			return token, resp.Status, resp.NextPollSeconds, nil
		case isUnknownToken(cerr):
			fmt.Println("The previous registration was removed from the web console; re-registering this host.")
			// fall through to re-register
		default:
			// Keep the token and let the service retry: the Server may simply
			// be down. Name it and say why, because a Server that is briefly
			// down and one that no longer exists are indistinguishable to the
			// operator otherwise, and only the first resolves on its own.
			fmt.Printf("\nCould not reach %s: %v\n", cfg.ServerURL, cerr)
			return token, "", 0, nil
		}
	}
	return reregister(ctx, t, api, opts, cfg)
}

// reregister re-registers keeping the host's persisted Agent ID and name, and
// returns the new token with a pending status.
func reregister(ctx context.Context, t *terminal, api *serverapi.Client, opts Options, cfg identity.Config) (string, string, int, error) {
	key, err := resolveKey(t, opts.RegistrationKey)
	if err != nil {
		return "", "", 0, err
	}
	resp, err := api.Register(ctx, wire.RegistrationRequest{
		RegistrationKey: key,
		AgentID:         cfg.AgentID,
		ProposedName:    cfg.DisplayName,
		AgentVersion:    Version,
		ProtocolVersion: wire.ProtocolVersion,
		Diagnostics:     hostinfo.Collect(),
	})
	if err != nil {
		if apiErr, ok := errors.AsType[*serverapi.APIError](err); ok {
			switch apiErr.Code {
			case wire.CodeAgentIDTaken:
				return "", "", 0, errors.New("registration failed: this host is already registered; remove it from the web console, then reinstall")
			case wire.CodeUnknownAgentID:
				return "", "", 0, fmt.Errorf("registration failed: the Server does not know this Agent (%s). If the Server was reset, remove %s and register fresh", cfg.AgentID, identity.ConfigPath())
			case wire.CodeInvalidRegistrationKey:
				return "", "", 0, errors.New("registration failed: the registration key was not accepted")
			}
		}
		return "", "", 0, fmt.Errorf("registration failed: %w", err)
	}
	if err := identity.SaveToken(resp.AgentToken); err != nil {
		return "", "", 0, fmt.Errorf("save token: %w", err)
	}
	fmt.Printf("✓ re-registered, new Agent token stored in %s\n", identity.TokenPath())
	return resp.AgentToken, wire.StatusPending, resp.NextPollSeconds, nil
}

// awaitAuthorization waits for the operator to authorize, printing the outcome.
// An interrupt during the wait is reported as safe (the service keeps polling).
func awaitAuthorization(ctx context.Context, api *serverapi.Client, name, token string, pollSeconds int, marketplaceURL string) error {
	fmt.Println()
	fmt.Println(authorizationInstructions(marketplaceURL))

	organization, organizationID, err := waitForAuthorization(ctx, api, token, pollSeconds)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			fmt.Println("\n(installer interrupted; the systemd service keeps polling, so authorize any time)")
			return nil
		}
		return err
	}
	// The Organization is named here because this is the moment it becomes
	// true, and the installer's output is what the operator keeps.
	if organization != "" {
		rememberOrganization(organization, organizationID)
		cfg, _ := identity.LoadConfig()
		fmt.Printf("\n✓ %s was authorized and is now ACTIVE in %s.\n", name, cfg.Organization())
	} else {
		fmt.Printf("\n✓ %s was authorized and is now ACTIVE.\n", name)
	}
	fmt.Printf("  manage:  systemctl status %s\n", identity.ServiceName())
	return nil
}

// rememberOrganization records a name learned after the config was written:
// registration answers before the Agent is authorized, and an older Server
// sends nothing at all. Best effort, since the name is only ever a message.
func rememberOrganization(organization, organizationID string) {
	cfg, err := identity.LoadConfig()
	if err != nil || (cfg.OrganizationName == organization && cfg.OrganizationID == organizationID) {
		return
	}
	cfg.OrganizationName = organization
	if organizationID != "" {
		cfg.OrganizationID = organizationID
	}
	_ = identity.SaveConfig(cfg)
}

func marketplaceURL(serverURL, fromServer string) string {
	if fromServer != "" {
		return fromServer
	}
	return strings.TrimRight(serverURL, "/") + "/plugins/marketplace"
}

func authorizationInstructions(marketplaceURL string) string {
	return fmt.Sprintf("Visit the Plugin marketplace: %s\n\nWaiting for authorization from the web console (approve it at your web console › Agents)...", marketplaceURL)
}

// Uninstall removes the Agent from this host: it unregisters from the Server
// (best-effort), stops and removes the systemd unit, and deletes the config,
// token, and binary. Deliberately host-side only: the Server can never trigger
// it, so a compromised Server or account cannot wipe an Agent off a machine it
// does not own. Certificates and keys this Agent deployed are left alone,
// since removing them could take the host's services down.
func Uninstall(ctx context.Context, assumeYes bool) error {
	if os.Geteuid() != 0 {
		return errors.New("uninstall must run as root (use sudo)")
	}

	cfg, cfgErr := identity.LoadConfig()
	installed := cfgErr == nil && cfg.AgentID != ""
	if !installed {
		fmt.Println("No easySSL Agent registration found on this host; removing any leftover files.")
	} else {
		fmt.Printf("easySSL Agent %q (%s) is registered with %s in %s.\n", cfg.DisplayName, cfg.AgentID, cfg.ServerURL, cfg.Organization())
	}

	if !assumeYes && !confirmUninstall(installed, cfg.Organization()) {
		fmt.Println("Aborted; nothing was changed.")
		return nil
	}

	// Unregister first, while the token still exists on disk. Best-effort: an
	// unreachable Server must not block an operator from cleaning up a host,
	// so failure only leaves a row to remove from the web console.
	if installed {
		switch token, err := identity.LoadToken(); {
		case err != nil:
			fmt.Println("! no local token, so this host may still appear in the web console; remove it there")
		default:
			if err := serverapi.New(cfg.ServerURL).Unregister(ctx, token); err == nil || isUnknownToken(err) {
				fmt.Printf("✓ unregistered from %s\n", cfg.Organization())
			} else {
				fmt.Printf("! could not reach the Server (%v); remove this Agent from the web console\n", err)
			}
		}
	}

	// Note what is actually present first, so the summary claims only what this
	// run really removed rather than reporting deletions of absent files.
	hadUnit, hadState, hadBinary := exists(sysd.UnitPath()), exists(identity.BaseDir), exists(sysd.BinaryPath())

	if err := sysd.Uninstall(); err != nil {
		return fmt.Errorf("removing the systemd service: %w", err)
	}
	if hadUnit {
		fmt.Printf("✓ %s stopped and removed\n", identity.ServiceName())
	}

	if err := identity.RemoveAll(); err != nil {
		return fmt.Errorf("removing %s: %w", identity.BaseDir, err)
	}
	if hadState {
		fmt.Printf("✓ config and token deleted from %s\n", identity.BaseDir)
	}

	// Last, because it deletes the running program. Unlinking a running binary
	// is fine on Linux: the inode survives until this process exits.
	if err := os.Remove(sysd.BinaryPath()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing %s: %w", sysd.BinaryPath(), err)
	}
	if hadBinary {
		fmt.Printf("✓ %s deleted\n", sysd.BinaryPath())
	}

	if !hadUnit && !hadState && !hadBinary {
		fmt.Println("Nothing to remove; this host has no easySSL Agent installed.")
		return nil
	}
	fmt.Println("\neasySSL Agent uninstalled. Certificates it deployed were left in place.")
	reportKeysLeftBehind()
	reportPluginsLeftBehind()
	return nil
}

// reportPluginsLeftBehind names the Plugins still on the host, for the same
// reason the keys are named: uninstalling removes the Agent, not what it put
// on the machine. A Plugin is an executable this host will no longer run, since
// nothing is left to invoke it, but it is still there and someone
// decommissioning the machine should know rather than discover it.
func reportPluginsLeftBehind() {
	installed, err := pluginmgr.New(nil, nil).List()
	switch {
	case err != nil:
		fmt.Printf("\n! Plugins may remain in %s and were NOT deleted (listing them failed: %v).\n",
			pluginmgr.InstallDir, err)
	case len(installed) == 0:
		return
	default:
		fmt.Printf("\n! %d Plugin executable(s) remain in %s and were NOT deleted:\n",
			len(installed), pluginmgr.InstallDir)
		for _, p := range installed {
			fmt.Printf("    %s v%s\n", p.ID, p.Version)
		}
		fmt.Println("  Delete that directory by hand if this host is being decommissioned.")
	}
}

// reportKeysLeftBehind tells the operator that uninstalling did not remove the
// private keys.
//
// It is printed rather than offered as a choice because the Agent never deletes
// key material: each key is the only copy this host has, and an uninstall is too
// ordinary a command to destroy something unrecoverable. The consequence is that
// a machine someone believes they have decommissioned still holds every key it
// generated, so that is said here rather than left to be discovered.
// Only the number depends on the count succeeding. A keystore that cannot be
// counted is still a keystore left on the host, and it is also the case where
// something is already wrong, so a failure to count is the worst moment to say
// nothing.
func reportKeysLeftBehind() {
	n, err := keystore.Count()
	switch {
	case err != nil:
		fmt.Printf("\n! private keys may remain in %s and were NOT deleted (counting them failed: %v).\n", keystore.Dir(), err)
	case n == 0:
		return
	case n == 1:
		fmt.Printf("\n! 1 private key remains in %s and was NOT deleted.\n", keystore.Dir())
	default:
		fmt.Printf("\n! %d private keys remain in %s and were NOT deleted.\n", n, keystore.Dir())
	}
	fmt.Println("  They are the only copy on this host. Delete that directory by hand if this")
	fmt.Println("  machine is being decommissioned, and keep a copy first if the Certificates")
	fmt.Println("  using them are still in service.")
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// confirmUninstall asks before destroying local state. With no terminal (an
// automated run) it declines rather than assuming consent; --yes is the
// explicit way to say yes without one.
func confirmUninstall(registered bool, organization string) bool {
	t := openTerminal()
	if t == nil {
		fmt.Println("Refusing to uninstall without confirmation: re-run with --yes.")
		return false
	}
	defer t.close()
	what := "the Agent and its files"
	if registered {
		// Named, because an operator who administers several Organizations
		// cannot tell from "the Organization" which one they are removing this
		// host from.
		what = "this Agent from " + organization + ", and its files"
	}
	return strings.EqualFold(t.prompt(fmt.Sprintf("Remove %s? [y/N]: ", what)), "y")
}

func resolveKey(t *terminal, fromFlag string) (string, error) {
	if fromFlag != "" {
		return fromFlag, nil
	}
	if t == nil {
		return "", errors.New("no registration key: set the REGISTRATION_KEY environment variable or pass --key")
	}
	key := t.prompt("Paste your registration key: ")
	if key == "" {
		return "", errors.New("a registration key is required")
	}
	return key, nil
}

// confirmName resolves the Agent's name: an explicit --name
// wins, otherwise the operator edits the hostname-derived default at the
// prompt, and a non-interactive install keeps the default.
// proposedName trims a hostname to its first label, which is what the installer
// offers as the Agent name: `web-01` from `web-01.nw.internal`. A name
// shaped like a domain invites being read as an address, which an Agent name is
// not — it identifies nothing, the Server's own identifier does that, and it is
// edited freely. Nothing is lost by trimming: the whole hostname goes to the
// Server as a host diagnostic and is printed beside the name.
//
// Empty when the host reports no name, which is the caller's signal to ask.
func proposedName(hostname string) string {
	label, _, _ := strings.Cut(hostname, ".")
	return label
}

// confirmName settles the Agent name: the flag or environment value if one was
// given, otherwise the proposal, editable at the prompt. hostname is the whole
// one, shown beside the proposal when it differs so the reader can see what was
// trimmed.
//
// With no proposal and no terminal there is nothing to offer and nobody to ask,
// so this returns an error rather than a silent empty name that the Server would
// refuse later.
func confirmName(t *terminal, fromFlag, proposed, hostname string) (string, error) {
	if fromFlag != "" {
		return fromFlag, nil
	}
	label := "Agent name"
	if hostname != "" && hostname != proposed {
		label = fmt.Sprintf("Agent name (host %s)", hostname)
	}
	if t == nil {
		if proposed == "" {
			return "", errors.New("this host reports no hostname to name the Agent after: pass --name or set AGENT_NAME")
		}
		return proposed, nil
	}
	if proposed == "" {
		v := t.prompt(label + ": ")
		if v == "" {
			return "", errors.New("an Agent name is required: this host reports no hostname to propose one from")
		}
		return v, nil
	}
	v := t.prompt(fmt.Sprintf("%s [%s]: ", label, proposed))
	if v == "" {
		return proposed, nil
	}
	return v, nil
}

// register submits a fresh registration. No identifier goes with it: the
// Server mints one and returns it, and persisting that answer is what makes the
// next run of the installer a reinstall of this Agent rather than a second
// registration.
func register(ctx context.Context, api *serverapi.Client, key, name, serverURL string) (wire.RegistrationResponse, string, error) {
	diag := hostinfo.Collect()
	fmt.Printf("✓ host  %s · %s\n", diag.OS, diag.HostType)
	fmt.Printf("→ submitting registration to %s\n", serverURL)

	resp, err := api.Register(ctx, wire.RegistrationRequest{
		RegistrationKey: key,
		ProposedName:    name,
		AgentVersion:    Version,
		ProtocolVersion: wire.ProtocolVersion,
		Diagnostics:     diag,
	})
	if err != nil {
		if apiErr, ok := errors.AsType[*serverapi.APIError](err); ok {
			if apiErr.Code == wire.CodeInvalidRegistrationKey {
				return wire.RegistrationResponse{}, "", errors.New("registration failed: the registration key was not accepted")
			}
		}
		return wire.RegistrationResponse{}, "", fmt.Errorf("registration failed: %w", err)
	}
	if resp.AgentID == "" {
		return wire.RegistrationResponse{}, "", errors.New("registration failed: did not receive an Agent ID from the Server (is it older than this Agent?)")
	}
	return resp, resp.AgentID, nil
}

// waitForAuthorization polls until the Agent is active, the token is rejected,
// or the context is canceled. Transient network errors are retried.
// Returns the Organization's name, which the check-in carries and which is
// therefore known only once the Server answers.
func waitForAuthorization(ctx context.Context, api *serverapi.Client, token string, pollSeconds int) (name, id string, err error) {
	if pollSeconds <= 0 {
		pollSeconds = 3
	}
	for {
		resp, err := api.Checkin(ctx, token, wire.CheckinRequest{AgentVersion: Version})
		switch {
		case err == nil && resp.Status == wire.StatusActive:
			return resp.OrganizationName, resp.OrganizationID, nil
		case err == nil:
			pollSeconds = resp.NextPollSeconds
		default:
			if isUnknownToken(err) {
				return "", "", errors.New("registration was rejected (or the token was revoked)")
			}
			// transient error: keep the current cadence and retry
		}
		select {
		case <-ctx.Done():
			return "", "", ctx.Err()
		case <-time.After(time.Duration(pollSeconds) * time.Second):
		}
	}
}

// isUnknownToken reports whether err is the Server's unknown-token response.
func isUnknownToken(err error) bool {
	apiErr, ok := errors.AsType[*serverapi.APIError](err)
	return ok && apiErr.Code == wire.CodeUnknownToken
}

// --- small terminal helpers (stdlib only) ---

// terminal is the operator's input source. It is deliberately NOT os.Stdin in
// the common case: the one-line installer runs as `curl … | sudo bash`, so the
// process inherits the *script pipe* as stdin and reading it would consume the
// installer script rather than the operator's typing. Opening the controlling
// terminal /dev/tty reaches the human instead, which is what makes the key and
// name prompts work under `curl | bash` at all.
type terminal struct {
	in    *bufio.Reader
	out   io.Writer
	close func()
}

// openTerminal returns the operator's terminal, or nil when there is none
// (cron, cloud-init, a container without a TTY), in which case callers fall
// back to non-interactive defaults instead of blocking forever on a read.
func openTerminal() *terminal {
	if isTerminal(os.Stdin) {
		return &terminal{in: bufio.NewReader(os.Stdin), out: os.Stdout, close: func() {}}
	}
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil
	}
	// Prompts go to the tty too, so they stay visible even if stdout is piped.
	return &terminal{in: bufio.NewReader(f), out: f, close: func() { _ = f.Close() }}
}

// prompt writes the label and reads one line. A single reader is reused across
// prompts so buffered input is never dropped between them.
func (t *terminal) prompt(label string) string {
	fmt.Fprint(t.out, label)
	line, err := t.in.ReadString('\n')
	if err != nil && line == "" {
		return ""
	}
	return strings.TrimSpace(line)
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
