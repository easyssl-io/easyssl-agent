// Package flow drives the interactive line-based registration session.
// A host runs one Agent. The first run registers, stores the Server's token,
// installs the systemd unit, and waits for the operator to authorize from the
// web console; a run presenting a reactivation token resumes an Agent the
// web console deactivated, active at once. A later run on an already-registered
// host is idempotent: it refreshes the service onto the updated binary and
// reports state instead of registering a second Agent. It is plain
// stdin/stdout, no full-screen TUI shell in this slice.
//
// The host keeps no Agent ID and no name: the Server is the only namer of
// Agents, and what the host holds is its token, which is what proves it is
// the Agent the web console shows. Both are reported by the Server on demand.
package flow

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/easyssl-io/easyssl-agent/internal/hostinfo"
	"github.com/easyssl-io/easyssl-agent/internal/identity"
	"github.com/easyssl-io/easyssl-agent/internal/inventory"
	"github.com/easyssl-io/easyssl-agent/internal/keystore"
	"github.com/easyssl-io/easyssl-agent/internal/pluginmgr"
	"github.com/easyssl-io/easyssl-agent/internal/serverapi"
	"github.com/easyssl-io/easyssl-agent/internal/sysd"
	"github.com/easyssl-io/easyssl-contract/wire"
)

// Version is the Agent version reported to the Server.
const Version = "0.0.1"

// CheckinBody is what this host says about itself on every poll.
//
// It is a function rather than a struct literal at each caller because there
// are two callers, the installer and the long-running service, and they must
// report the same thing. A field added to the wire struct and filled in only
// one of them would leave the Server's record correct or stale depending on
// which process happened to check in last, which is not a difference anything
// would report.
//
// inventoryFingerprint is the service's, over the host inventory it computed
// for this check-in; the installer passes none, having computed no inventory,
// and the Server then asks the service on its next check-in.
func CheckinBody(inventoryFingerprint string) wire.CheckinRequest {
	return wire.CheckinRequest{AgentVersion: Version, ProtocolVersion: wire.ProtocolVersion, InventoryFingerprint: inventoryFingerprint}
}

// Options configures a registration session.
// Options is what the register command resolved from its flags and
// environment; anything empty is prompted for when there is a terminal.
type Options struct {
	ServerURL         string // required
	RegistrationKey   string // from --key or REGISTRATION_KEY; prompted if empty and interactive
	ReactivationToken string // from --reactivation-token or REACTIVATION_TOKEN; wins over the key
	Name              string // from --name or AGENT_NAME; else the hostname, editable at the prompt
}

// reactivationPrefix is how a reactivation token is told from a registration
// key when either is pasted at the one prompt: the Server mints them `esrt_`
// and keys `esrk_`.
const reactivationPrefix = "esrt_"

// Register is the entry point of the register command.
func Register(ctx context.Context, opts Options) error {
	// Check root before anything reaches the Server. Registering first and
	// failing afterwards on the config write would leave a pending Agent on
	// the Server for a host that never actually installed one, which an
	// operator then has to notice and clean up.
	if os.Geteuid() != 0 {
		return errors.New("register must run as root: use sudo, or run it from a root shell")
	}

	// Before the first prompt, so a --server this Agent will not talk to fails
	// while there is still nothing to lose: no key typed in, no token issued,
	// nothing written to disk. Options.ServerURL is required, and the register
	// command refuses an empty one, so this always has something to check.
	if err := serverapi.CheckBaseURL(opts.ServerURL); err != nil {
		return err
	}

	fmt.Printf("easySSL Agent installer · v%s\n", Version)
	fmt.Println("Registering this host to an easySSL Organization...")
	fmt.Println()

	t := openTerminal()
	if t != nil {
		defer t.close()
	}

	// Installed means a config and a token: uninstall deletes both, so one
	// without the other is a remnant, and a remnant is registered over.
	if cfg, err := identity.LoadConfig(); err == nil {
		if _, terr := identity.LoadToken(); terr == nil {
			return reinstall(ctx, t, opts, cfg)
		}
	}
	return freshRegister(ctx, t, opts)
}

// reinstall handles a host that already has a token: refresh the service onto
// the new binary and report the current state. The unit is (re)installed before
// the service is started, so an upgrade never races the old binary's clean
// service exit (systemd does not auto-restart a clean exit).
func reinstall(ctx context.Context, t *terminal, opts Options, cfg identity.Config) error {
	// An installer is downloaded from one Server and carries that Server's URL,
	// so a mismatch means this host belongs to a different one. Continuing
	// against the stored URL is the wrong answer twice over: the operator is
	// watching the web console they installed from, where this host will never
	// appear, and the credential they supplied belongs to that web console
	// too. Moving the host is not done silently either, because it detaches
	// this host from whatever the old Server still deploys to it.
	if opts.ServerURL != "" && opts.ServerURL != cfg.ServerURL {
		return fmt.Errorf("this host is registered to %s, but this installer came from %s.\n"+
			"Nothing was changed. To move it, uninstall it from the old Server first:\n"+
			"    sudo easyssl-agent uninstall\n"+
			"then run this installer again", cfg.ServerURL, opts.ServerURL)
	}

	fmt.Printf("This host is already registered on %s in %s.\n", cfg.ServerURL, cfg.Organization())

	api, err := serverapi.New(cfg.ServerURL)
	if err != nil {
		return err
	}
	token, err := identity.LoadToken()
	if err != nil {
		return err
	}
	resp, cerr := api.Checkin(ctx, token, CheckinBody(""))
	switch {
	case cerr == nil:
	case isUnknownToken(cerr):
		// Deactivated or removed in the web console. Either way the token is
		// dead and this host is registered again under whatever credential
		// the operator gave this run: a reactivation token to be the same
		// Agent, a registration key to be a new one.
		fmt.Println("The Server no longer accepts this host's token: the Agent was deactivated or removed from the web console.")
		fmt.Println("Registering this host again.")
		fmt.Println()
		return freshRegister(ctx, t, opts)
	default:
		// Keep the token and let the service retry: the Server may simply be
		// down. Name it and say why, because a Server that is briefly down and
		// one that no longer exists are indistinguishable to the operator
		// otherwise, and only the first resolves on its own.
		fmt.Printf("\nCould not reach %s: %v\n", cfg.ServerURL, cerr)
		if err := sysd.Install(); err != nil {
			return fmt.Errorf("updating systemd unit: %w", err)
		}
		fmt.Printf("✓ %s updated\n", identity.ServiceName())
		defer startServiceOnExit()
		fmt.Println("The service will keep polling it, so registration completes once it is back.")
		return nil
	}

	if err := sysd.Install(); err != nil {
		return fmt.Errorf("updating systemd unit: %w", err)
	}
	fmt.Printf("✓ %s updated\n", identity.ServiceName())
	defer startServiceOnExit()

	if resp.Status == wire.StatusActive {
		fmt.Printf("\n✓ %s is authorized and ACTIVE.\n", resp.DisplayName)
		return nil
	}
	return awaitAuthorization(ctx, api, resp.DisplayName, token, resp.NextPollSeconds,
		marketplaceURL(cfg.ServerURL, ""))
}

// freshRegister registers a host that has no live Agent. With a registration
// key it becomes a new pending Agent; with a reactivation token it becomes the
// deactivated Agent the token was minted for, active at once and under that
// Agent's name, so no name is asked for.
func freshRegister(ctx context.Context, t *terminal, opts Options) error {
	key, reactivation, err := resolveCredential(t, opts)
	if err != nil {
		return err
	}
	name := ""
	if reactivation == "" {
		host, _ := os.Hostname()
		name, err = confirmName(t, opts.Name, proposedName(host), host)
		if err != nil {
			return err
		}
		if host != "" && host != name {
			fmt.Printf("✓ Agent name  %s  (host %s)\n", name, host)
		} else {
			fmt.Printf("✓ Agent name  %s\n", name)
		}
	}

	api, err := serverapi.New(opts.ServerURL)
	if err != nil {
		return err
	}
	resp, err := register(ctx, api, key, reactivation, name, opts.ServerURL)
	if err != nil {
		return err
	}

	cfg := identity.Config{
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
	defer startServiceOnExit()

	if resp.Status == wire.StatusActive {
		fmt.Printf("\n✓ Reactivated as %s (%s), ACTIVE in %s.\n", resp.DisplayName, resp.AgentID, cfg.Organization())
		fmt.Printf("  manage:  systemctl status %s\n", identity.ServiceName())
		offerRequiredPlugins(ctx, t, api, resp.AgentToken, opts.ServerURL, resp.RequiredPlugins)
		return nil
	}
	return awaitAuthorization(ctx, api, name, resp.AgentToken, resp.NextPollSeconds,
		marketplaceURL(opts.ServerURL, resp.MarketplaceURL))
}

// offerRequiredPlugins installs, after confirmation, the Plugins the resumed
// Agent's Targets are configured with and this host lacks. A reactivated host
// is often a rebuilt one, and a Deployment pushed to it before the Plugin is
// back fails on the host for want of an executable; asking here is what puts
// that step before the first push rather than after it. Non-interactive runs
// are told what to install and left to it: a Plugin runs as root, and that
// consent is not inferred from an environment variable.
func offerRequiredPlugins(ctx context.Context, t *terminal, api *serverapi.Client, token, serverURL string, required []string) {
	if len(required) == 0 {
		return
	}
	mgr := pluginmgr.New(pluginmgr.HTTPCatalog{BaseURL: serverURL}, nil)
	missing := make([]string, 0, len(required))
	for _, id := range required {
		if _, ok, err := mgr.Find(id); err == nil && ok {
			continue
		}
		missing = append(missing, id)
	}
	if len(missing) == 0 {
		return
	}
	fmt.Printf("\nIts Targets use %d Plugin(s) this host does not have: %s\n", len(missing), strings.Join(missing, ", "))
	fmt.Println("A Deployment to those Targets fails until each is installed. A Plugin runs with")
	fmt.Println("this Agent's privileges, which is root: installing authorizes code execution at")
	fmt.Println("that level on this host.")
	if t == nil {
		fmt.Printf("Install them later with:  sudo easyssl-agent plugin install %s\n", strings.Join(missing, " "))
		return
	}
	if !strings.EqualFold(t.prompt("Install them now? [y/N]: "), "y") {
		fmt.Printf("Not installed. Later:  sudo easyssl-agent plugin install %s\n", strings.Join(missing, " "))
		return
	}
	installed := 0
	for _, id := range missing {
		inst, err := mgr.Install(ctx, id, runtime.GOOS, runtime.GOARCH)
		if err != nil {
			fmt.Printf("! %s: %v\n", id, err)
			continue
		}
		fmt.Printf("✓ installed %s v%s at %s\n", inst.ID, inst.Version, inst.Path)
		installed++
	}
	if installed == 0 {
		return
	}
	// Report at once, so the web console lists the Plugins before the service's
	// first check-in; if that fails the service reports on its own.
	if inv, err := inventory.Collect(ctx, mgr); err == nil {
		if err := api.ReportInventory(ctx, token, inv); err == nil {
			fmt.Println("✓ reported to the Server")
		}
	}
}

func startServiceOnExit() {
	if err := sysd.Start(); err != nil {
		fmt.Fprintf(os.Stderr,
			"! could not start %s: %v\n"+
				"  The unit is installed and enabled, so `systemctl start %s`, or a reboot, starts it.\n",
			identity.ServiceName(), err, identity.ServiceName())
	}
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

// Uninstall takes the Agent off this host. It deactivates the Agent on the
// Server (best effort: an unreachable Server must not stop an operator
// cleaning up a host), deletes the config and token either way, stops and
// removes the systemd unit and deletes the binary, then offers, each behind
// its own confirmation, to delete the installed Plugins and the private keys.
// Deliberately host-side only: the Server can never trigger it, so a
// compromised Server or account cannot wipe an Agent off a machine it does
// not own. Certificates the Agent deployed elsewhere on the host are never
// touched, since removing them could take the host's services down.
//
// Deactivating rather than removing is what keeps the Agent's Targets: the
// web console can hand out a reactivation command that brings the same Agent
// back, on this host after a reinstall or on another one.
func Uninstall(ctx context.Context, assumeYes bool) error {
	if os.Geteuid() != 0 {
		return errors.New("uninstall must run as root (use sudo)")
	}

	cfg, cfgErr := identity.LoadConfig()
	token, tokenErr := identity.LoadToken()
	installed := cfgErr == nil && tokenErr == nil
	if !installed {
		fmt.Println("No easySSL Agent registration found on this host; removing any leftover files.")
	} else {
		fmt.Printf("The easySSL Agent on this host is registered with %s in %s.\n", cfg.ServerURL, cfg.Organization())
	}

	t := openTerminal()
	if t != nil {
		defer t.close()
	}
	if !assumeYes && !confirmUninstall(t, installed, cfg.Organization()) {
		fmt.Println("Aborted; nothing was changed.")
		return nil
	}

	// Deactivate first, while the token still exists on disk.
	if installed {
		deactivateOnServer(ctx, cfg, token)
	}

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
	offerPluginRemoval(t)
	offerKeyRemoval(t)
	return nil
}

// deactivateOnServer tells the Server this token is done with. Every outcome
// is reported in words, because what the operator does next depends on it:
// a deactivated Agent needs nothing, and an Agent the Server still accepts
// has to be deactivated from the web console by hand.
func deactivateOnServer(ctx context.Context, cfg identity.Config, token string) {
	api, err := serverapi.New(cfg.ServerURL)
	if err != nil {
		fmt.Printf("! %v\n", err)
		fmt.Printf("  The Server still accepts this host's token: deactivate this Agent from the web console at %s\n", cfg.ServerURL)
		return
	}
	host, _ := os.Hostname()
	switch err := api.Unregister(ctx, token); {
	case err == nil:
		fmt.Printf("✓ deactivated in %s; its Targets are kept, and the web console can reactivate it on this or another host\n", cfg.Organization())
	case isUnknownToken(err):
		fmt.Println("✓ the Server no longer accepts this token (the Agent was already deactivated or removed)")
	default:
		fmt.Printf("! could not reach %s: %v\n", cfg.ServerURL, err)
		fmt.Printf("  The Server still accepts this host's token: deactivate this Agent from the web console at %s\n", cfg.ServerURL)
		fmt.Printf("  (Organization %s, host %s), which is where the Agents are listed.\n", cfg.Organization(), host)
	}
}

// offerPluginRemoval deletes the installed Plugin executables after a
// confirmation. Only with a terminal: --yes consents to uninstalling the
// Agent, not to everything it could take with it, so an unattended run
// leaves the Plugins and says where they are.
func offerPluginRemoval(t *terminal) {
	installed, err := pluginmgr.New(nil, nil).List()
	switch {
	case err != nil:
		fmt.Printf("\n! Plugins may remain in %s and were NOT deleted (listing them failed: %v).\n",
			pluginmgr.InstallDir, err)
		return
	case len(installed) == 0:
		return
	}
	fmt.Printf("\n%d Plugin executable(s) remain in %s:\n", len(installed), pluginmgr.InstallDir)
	for _, p := range installed {
		fmt.Printf("    %s\n", p.Path)
	}
	if t == nil {
		fmt.Println("  They were NOT deleted; delete that directory by hand if this host is being decommissioned.")
		return
	}
	if !strings.EqualFold(t.prompt(fmt.Sprintf("Delete %s? [y/N]: ", pluginmgr.InstallDir)), "y") {
		fmt.Println("  Kept.")
		return
	}
	if err := os.RemoveAll(pluginmgr.InstallDir); err != nil {
		fmt.Printf("! could not delete %s: %v\n", pluginmgr.InstallDir, err)
		return
	}
	fmt.Printf("✓ %s deleted\n", pluginmgr.InstallDir)
}

// offerKeyRemoval deletes the keystore after a confirmation that cannot be
// given by accident: the keys are the Agent's only copy of what every
// Certificate issued to this host is signed with, and nothing recovers them.
// Never through --yes, never by an empty answer, and never without a
// terminal: an uninstall is too ordinary a command to destroy something
// unrecoverable on a default.
func offerKeyRemoval(t *terminal) {
	n, err := keystore.Count()
	switch {
	case err != nil:
		fmt.Printf("\n! private keys may remain in %s and were NOT deleted (counting them failed: %v).\n", keystore.Dir(), err)
		return
	case n == 0:
		return
	case n == 1:
		fmt.Printf("\n1 private key remains in %s.\n", keystore.Dir())
	default:
		fmt.Printf("\n%d private keys remain in %s.\n", n, keystore.Dir())
	}
	fmt.Println("  This is the only copy easySSL has of them: a Certificate whose key is gone cannot be")
	fmt.Println("  deployed or renewed from this host again, and reactivating this Agent elsewhere needs")
	fmt.Println("  these files copied there first. Copies a Deployment installed elsewhere on this host")
	fmt.Println("  are left in place either way.")
	if t == nil {
		fmt.Println("  They were NOT deleted; delete the directory by hand if this machine is being decommissioned.")
		return
	}
	answer := t.prompt(fmt.Sprintf("Type 'delete keys' to delete %s, anything else keeps it: ", keystore.Dir()))
	if answer != "delete keys" {
		fmt.Println("  Kept.")
		return
	}
	if err := os.RemoveAll(keystore.Dir()); err != nil {
		fmt.Printf("! could not delete %s: %v\n", keystore.Dir(), err)
		return
	}
	fmt.Printf("✓ %s deleted\n", keystore.Dir())
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// confirmUninstall asks before destroying local state. With no terminal (an
// automated run) it declines rather than assuming consent; --yes is the
// explicit way to say yes without one.
func confirmUninstall(t *terminal, registered bool, organization string) bool {
	if t == nil {
		fmt.Println("Refusing to uninstall without confirmation: re-run with --yes.")
		return false
	}
	what := "the Agent and its files"
	if registered {
		what = "the Agent from this host, deactivating it in " + organization
	}
	return strings.EqualFold(t.prompt(fmt.Sprintf("Remove %s? [y/N]: ", what)), "y")
}

// resolveCredential returns the registration key or the reactivation token
// this run registers with, exactly one of them. A token given on the command
// line or in the environment wins, because it names one Agent where a key
// names none. At the prompt either may be pasted, and the prefix says which.
func resolveCredential(t *terminal, opts Options) (key, reactivation string, err error) {
	if opts.ReactivationToken != "" {
		return "", opts.ReactivationToken, nil
	}
	if opts.RegistrationKey != "" {
		if strings.HasPrefix(opts.RegistrationKey, reactivationPrefix) {
			return "", opts.RegistrationKey, nil
		}
		return opts.RegistrationKey, "", nil
	}
	if t == nil {
		return "", "", errors.New("no registration key: set the REGISTRATION_KEY environment variable or pass --key (or REACTIVATION_TOKEN / --reactivation-token to resume a deactivated Agent)")
	}
	v := t.prompt("Paste your registration key (or a reactivation token): ")
	switch {
	case v == "":
		return "", "", errors.New("a registration key is required")
	case strings.HasPrefix(v, reactivationPrefix):
		return "", v, nil
	}
	return v, "", nil
}

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

// register submits the registration. No identifier goes with it: the Server
// names Agents, and the answer carries the id and the name the web console
// shows, which is all the host ever learns of either.
func register(ctx context.Context, api *serverapi.Client, key, reactivation, name, serverURL string) (wire.RegistrationResponse, error) {
	diag := hostinfo.Collect()
	fmt.Printf("✓ host  %s · %s\n", diag.OS, diag.HostType)
	if reactivation != "" {
		fmt.Printf("→ submitting reactivation to %s\n", serverURL)
	} else {
		fmt.Printf("→ submitting registration to %s\n", serverURL)
	}

	resp, err := api.Register(ctx, wire.RegistrationRequest{
		RegistrationKey:   key,
		ReactivationToken: reactivation,
		ProposedName:      name,
		AgentVersion:      Version,
		ProtocolVersion:   wire.ProtocolVersion,
		Diagnostics:       diag,
	})
	if err != nil {
		if apiErr, ok := errors.AsType[*serverapi.APIError](err); ok {
			switch apiErr.Code {
			case wire.CodeInvalidRegistrationKey:
				return wire.RegistrationResponse{}, errors.New("registration failed: the registration key was not accepted")
			case wire.CodeInvalidReactivationToken:
				return wire.RegistrationResponse{}, errors.New("reactivation failed: the token was not accepted (unknown, expired, or already used). Generate another from the Agent's page in the web console")
			}
		}
		return wire.RegistrationResponse{}, fmt.Errorf("registration failed: %w", err)
	}
	if resp.AgentID == "" {
		return wire.RegistrationResponse{}, errors.New("registration failed: did not receive an Agent ID from the Server (is it older than this Agent?)")
	}
	return resp, nil
}

func waitForAuthorization(ctx context.Context, api *serverapi.Client, token string, pollSeconds int) (name, id string, err error) {
	if pollSeconds <= 0 {
		pollSeconds = 3
	}
	for {
		resp, err := api.RegistrationStatus(ctx, token)
		if err == nil && resp.Status == wire.StatusActive {
			return resp.OrganizationName, resp.OrganizationID, nil
		}
		if err != nil && isUnknownToken(err) {
			return "", "", errors.New("registration was rejected (or the token was revoked)")
		}
		// Still pending, or a transient error: wait and ask again.
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
