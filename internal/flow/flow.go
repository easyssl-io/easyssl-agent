// Package flow drives the interactive, line-based registration session over
// plain stdin and stdout. The first run registers, stores the Server's token,
// installs the systemd unit, and waits for the operator to authorize from the
// web console; a run presenting a reactivation token resumes an Agent the web
// console deactivated, active at once. A later run on an already-registered
// host is idempotent: it refreshes the service onto the updated binary and
// reports state instead of registering a second Agent.
//
// The host keeps no Agent ID and no name: the Server is the only namer of
// Agents, and the host holds its token, which is what proves it is the Agent
// the web console shows.
package flow

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/easyssl-io/easyssl-agent/internal/hostinfo"
	"github.com/easyssl-io/easyssl-agent/internal/identity"
	"github.com/easyssl-io/easyssl-agent/internal/inventory"
	"github.com/easyssl-io/easyssl-agent/internal/keystore"
	"github.com/easyssl-io/easyssl-agent/internal/msg"
	"github.com/easyssl-io/easyssl-agent/internal/pluginmgr"
	"github.com/easyssl-io/easyssl-agent/internal/serverapi"
	"github.com/easyssl-io/easyssl-agent/internal/service"
	"github.com/easyssl-io/easyssl-contract/l10n"
	"github.com/easyssl-io/easyssl-contract/wire"
)

// Version is the Agent version reported to the Server.
const Version = "0.0.1"

// CheckinBody is what this host says about itself on every poll. It is a
// function because its two callers, the installer and the long-running service,
// must report the same thing: a field filled in by only one of them would leave
// the Server's record correct or stale depending on which process checked in
// last, and nothing would report that.
//
// inventoryFingerprint is the service's, over the host inventory it computed
// for this check-in. The installer passes none, and the Server then asks the
// service on its next check-in.
func CheckinBody(inventoryFingerprint string) wire.CheckinRequest {
	return wire.CheckinRequest{AgentVersion: Version, ProtocolVersion: wire.ProtocolVersion, InventoryFingerprint: inventoryFingerprint}
}

// Options is what the register command resolved from its flags and environment;
// anything empty is prompted for when there is a terminal.
type Options struct {
	ServerURL         string // required
	RegistrationKey   string // from --key or REGISTRATION_KEY; prompted if empty and interactive
	ReactivationToken string // from --reactivation-token or REACTIVATION_TOKEN; wins over the key
	Name              string // from --name or AGENT_NAME; else the hostname, editable at the prompt
	Language          string // from --lang, which decides without asking; else the language step's answer
}

// reactivationPrefix is how a reactivation token is told from a registration
// key when either is pasted at the one prompt: the Server mints them `esrt_`
// and keys `esrk_`.
const reactivationPrefix = "esrt_"

// unchangedError is a registration that failed before it wrote anything to
// this host: no configuration, no token, no service unit. The install script
// puts back the Agent build it replaced only for this error, because after any
// write the host already runs, or will run on its next restart, with what the
// new build wrote.
type unchangedError struct{ error }

func (e unchangedError) Unwrap() error { return e.error }

// Unchanged reports whether err ended a registration before it changed this
// host.
func Unchanged(err error) bool {
	var u unchangedError
	return errors.As(err, &u)
}

// RefusedUnchanged marks err as a registration refused before anything was
// written to the host, for a refusal that happens before Register runs, such
// as a flag `register` does not know.
func RefusedUnchanged(err error) error { return unchangedError{err} }

// hostChanged is set by changingHost just before a registration first writes
// to this host.
var hostChanged bool

func changingHost() { hostChanged = true }

// markUnchanged wraps a registration's error as unchangedError when nothing
// was written to the host before it.
func markUnchanged(err error, changed bool) error {
	if err == nil || changed {
		return err
	}
	return unchangedError{err}
}

func Register(ctx context.Context, opts Options) (err error) {
	hostChanged = false
	defer func() { err = markUnchanged(err, hostChanged) }()
	// Check root before anything reaches the Server. Registering first and failing
	// on the config write would leave a pending Agent on the Server for a host
	// that never installed one.
	if os.Geteuid() != 0 {
		return msg.Err.T("register.not_root", "register must run as root: use sudo, or run it from a root shell")
	}

	t := openTerminal()
	if t != nil {
		defer t.close()
	}

	// The language first, ahead of every other step and of anything this
	// prints, so that all of it is read in the language chosen here.
	cfg, cfgErr := identity.LoadConfig()
	lang, err := settleLanguage(t, opts.Language, cfg.Language)
	if err != nil {
		return err
	}
	msg.SetLanguage(lang)

	// Before the next prompt, so a --server this Agent will not talk to fails
	// while there is nothing to lose: no key typed in, no token issued, nothing
	// written to disk.
	if err := serverapi.CheckBaseURL(opts.ServerURL); err != nil {
		return err
	}
	// Likewise an init system the service cannot be installed under: found
	// after registering, it would leave an Agent on the Server that never runs.
	if _, err := service.Detect(); err != nil {
		return err
	}

	fmt.Println(msg.T("register.banner", "easySSL Agent installer · v{version}", "version", Version))
	fmt.Println(msg.T("register.start", "Registering this host to an easySSL Organization..."))
	fmt.Println()

	// Installed means a config and a token: uninstall deletes both, so one
	// without the other is a remnant, and a remnant is registered over.
	if cfgErr == nil {
		if _, terr := identity.LoadToken(); terr == nil {
			return reinstall(ctx, t, opts, cfg)
		}
	}
	return freshRegister(ctx, t, opts)
}

// settleLanguage is the installer's language step. `--lang` decides without
// asking. Otherwise the default comes from msg.Resolve and the reader is asked
// when there is a terminal; without one the default is taken, since an
// unattended install must not block on a read.
func settleLanguage(t *terminal, flag, saved string) (string, error) {
	lang, decided, err := msg.Resolve(flag, os.Getenv(msg.EnvVar), saved, os.Getenv)
	if err != nil || decided || t == nil {
		return lang, err
	}
	return askLanguage(t, lang), nil
}

// askLanguage offers every supported language under its own name, numbered,
// with the default marked; Enter accepts it, and the number, the code or the
// name chooses another. Nothing here is a translated sentence, because the
// reader has not chosen a language yet: the heading is the one word in every
// language and the rest is names and numbers.
func askLanguage(t *terminal, def string) string {
	langs := l10n.Supported()
	fmt.Fprintln(t.out, msg.LanguageHeading())
	defaultNumber := 1
	for i, l := range langs {
		mark := " "
		if l == def {
			mark, defaultNumber = "*", i+1
		}
		fmt.Fprintf(t.out, "  %s %d  %s (%s)\n", mark, i+1, l10n.Name(l), l)
	}
	for {
		answer, ok := t.ask(fmt.Sprintf("[%d]: ", defaultNumber))
		if !ok || answer == "" {
			return def
		}
		if n, err := strconv.Atoi(answer); err == nil && n >= 1 && n <= len(langs) {
			return langs[n-1]
		}
		if l, ok := l10n.Base(answer); ok {
			return l
		}
		for _, l := range langs {
			if strings.EqualFold(answer, l10n.Name(l)) {
				return l
			}
		}
	}
}

// reinstall handles a host that already has a token: refresh the service onto
// the new binary and report the current state. The unit is (re)installed before
// the service is started, so an upgrade never races the old binary's clean
// service exit (systemd does not auto-restart a clean exit).
func reinstall(ctx context.Context, t *terminal, opts Options, cfg identity.Config) error {
	// An installer carries the URL of the Server it was downloaded from, so a
	// mismatch means this host belongs to a different one. Continuing against the
	// stored URL is wrong twice: the operator is watching the web console they
	// installed from, where this host will never appear, and the credential they
	// supplied belongs to that one too. Moving the host is not done silently
	// either, because it detaches this host from whatever the old Server still
	// deploys to it.
	if opts.ServerURL != "" && serverapi.NormalizeURL(opts.ServerURL) != serverapi.NormalizeURL(cfg.ServerURL) {
		return msg.Err.T("reinstall.other_server", "this host is registered to {registered}, but this installer came from {installer}.\n"+
			"Nothing was changed. To move it, uninstall it from the old Server first:\n"+
			"    sudo easyssl-agent uninstall\n"+
			"then run this installer again", "registered", cfg.ServerURL, "installer", opts.ServerURL)
	}

	// The language step's answer is kept even when nothing else about the
	// registration changes: re-running the installer is one way to change it.
	if cfg.Language != msg.Language() {
		cfg.Language = msg.Language()
		changingHost()
		if err := identity.SaveConfig(cfg); err != nil {
			return msg.Err.T("reinstall.save_language", "saving the language: {err}", "err", err)
		}
	}

	fmt.Println(msg.T("reinstall.already_registered", "This host is already registered on {server} in {organization}.",
		"server", cfg.ServerURL, "organization", cfg.Organization()))

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
		// Deactivated or removed in the web console. Either way the token is dead and
		// this host registers again under the credential this run was given: a
		// reactivation token to be the same Agent, a registration key to be a new
		// one.
		fmt.Println(msg.T("reinstall.token_refused", "The Server no longer accepts this host's token: the Agent was deactivated or removed from the web console."))
		fmt.Println(msg.T("reinstall.registering_again", "Registering this host again."))
		fmt.Println()
		return freshRegister(ctx, t, opts)
	default:
		// Keep the token and let the service retry: the Server may simply be down.
		// Name it and say why, because to the operator a Server that is briefly down
		// and one that no longer exists look the same, and only the first resolves on
		// its own.
		fmt.Println()
		fmt.Println(msg.T("reinstall.unreachable", "Could not reach {server}: {err}", "server", cfg.ServerURL, "err", cerr))
		changingHost()
		if err := service.Install(); err != nil {
			return msg.Err.T("reinstall.unreachable.update_service", "updating the service: {err}", "err", err)
		}
		fmt.Println(msg.T("reinstall.unreachable.service_updated", "✓ {service} updated", "service", serviceName()))
		defer startServiceOnExit()
		fmt.Println(msg.T("reinstall.unreachable.keeps_polling", "The service will keep polling it, so registration completes once it is back."))
		return nil
	}

	changingHost()
	if err := service.Install(); err != nil {
		return msg.Err.T("reinstall.update_service", "updating the service: {err}", "err", err)
	}
	fmt.Println(msg.T("reinstall.service_updated", "✓ {service} updated", "service", serviceName()))
	defer startServiceOnExit()

	if resp.Status == wire.StatusActive {
		fmt.Println()
		fmt.Println(msg.T("reinstall.active", "✓ {name} is authorized and ACTIVE.", "name", resp.DisplayName))
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
			fmt.Println(msg.T("register.name_with_host", "✓ Agent name  {name}  (host {host})", "name", name, "host", host))
		} else {
			fmt.Println(msg.T("register.name", "✓ Agent name  {name}", "name", name))
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
		ServerURL:        serverapi.NormalizeURL(opts.ServerURL),
		OrganizationName: resp.OrganizationName,
		OrganizationID:   resp.OrganizationID,
		Language:         msg.Language(),
	}
	changingHost()
	if err := identity.SaveConfig(cfg); err != nil {
		return msg.Err.T("register.save_config", "saving the configuration: {err}", "err", err)
	}
	if err := identity.SaveToken(resp.AgentToken); err != nil {
		return msg.Err.T("register.save_token", "saving the token: {err}", "err", err)
	}
	fmt.Println(msg.T("register.token_stored", "✓ Agent token stored in {path}", "path", identity.TokenPath()))

	if err := service.Install(); err != nil {
		return msg.Err.T("register.install_service", "installing the service: {err}", "err", err)
	}
	fmt.Println(msg.T("register.service_installed", "✓ service installed: {service}", "service", serviceName()))
	defer startServiceOnExit()

	if resp.Status == wire.StatusActive {
		fmt.Println()
		fmt.Println(msg.T("register.reactivated", "✓ Reactivated as {name} ({id}), ACTIVE in {organization}.",
			"name", resp.DisplayName, "id", resp.AgentID, "organization", cfg.Organization()))
		fmt.Println(msg.T("register.reactivated.manage", "  manage:  {command}", "command", statusHint()))
		offerRequiredPlugins(ctx, t, api, resp.AgentToken, opts.ServerURL, resp.RequiredPlugins)
		printNoPluginHint()
		return nil
	}
	return awaitAuthorization(ctx, api, name, resp.AgentToken, resp.NextPollSeconds,
		marketplaceURL(opts.ServerURL, resp.MarketplaceURL))
}

// offerRequiredPlugins installs, after confirmation, the Plugins the resumed
// Agent's Targets are configured with and this host lacks. A reactivated host
// is often a rebuilt one, and a Deployment pushed to it before the Plugin is
// back fails for want of an executable. Non-interactive runs are told what to
// install and left to it: a Plugin runs as root, and that consent is not
// inferred from an environment variable.
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
	fmt.Println()
	fmt.Println(msg.N("register.plugins.missing", len(missing),
		"Its Targets use 1 Plugin this host does not have: {plugins}",
		"Its Targets use {n} Plugins this host does not have: {plugins}",
		"plugins", strings.Join(missing, ", ")))
	// One line, wrapped by the terminal rather than here: a fixed width is a
	// guess about a window this program cannot see.
	fmt.Println(msg.T("register.plugins.consequence", "A Deployment to those Targets fails until each is installed. A Plugin runs with this Agent's privileges, which is root: installing authorizes code execution at that level on this host."))
	if t == nil {
		fmt.Println(msg.T("register.plugins.install_later", "Install them later with:  sudo easyssl-agent plugin install {plugins}", "plugins", strings.Join(missing, " ")))
		return
	}
	if !msg.Yes(t.prompt(msg.T("register.plugins.confirm", "Install them now? [y/N]: "))) {
		fmt.Println(msg.T("register.plugins.declined", "Not installed. Later:  sudo easyssl-agent plugin install {plugins}", "plugins", strings.Join(missing, " ")))
		return
	}
	installed := 0
	for _, id := range missing {
		inst, err := mgr.Install(ctx, id, runtime.GOOS, runtime.GOARCH)
		if err != nil {
			fmt.Printf("! %s: %v\n", id, err)
			continue
		}
		fmt.Println(msg.T("register.plugins.installed", "✓ installed {id} v{version} at {path}", "id", inst.ID, "version", inst.Version, "path", inst.Path))
		installed++
	}
	if installed == 0 {
		return
	}
	// Report at once, so the web console lists the Plugins before the service's
	// first check-in; if that fails the service reports on its own.
	if inv, err := inventory.Collect(ctx, mgr); err == nil {
		if err := api.ReportInventory(ctx, token, inv); err == nil {
			fmt.Println(msg.T("register.plugins.reported", "✓ reported to the Server"))
		}
	}
}

func startServiceOnExit() {
	if err := service.Start(); err != nil {
		fmt.Fprintln(os.Stderr, msg.T("register.start_failed",
			"! could not start {service}: {err}\n"+
				"  It is installed and enabled, so a reboot starts it; `{command}` shows its state.",
			"service", serviceName(), "err", err, "command", statusHint()))
	}
}

func serviceName() string {
	n, _, _ := service.Describe()
	return n
}

func statusHint() string {
	_, h, _ := service.Describe()
	return h
}

// awaitAuthorization waits for the operator to authorize, printing the outcome.
// An interrupt during the wait is reported as safe (the service keeps polling).
func awaitAuthorization(ctx context.Context, api *serverapi.Client, name, token string, pollSeconds int, marketplaceURL string) error {
	fmt.Println()
	fmt.Println(authorizationInstructions(marketplaceURL))

	organization, organizationID, err := waitForAuthorization(ctx, api, token, pollSeconds)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			fmt.Println()
			fmt.Println(msg.T("register.interrupted", "(installer interrupted; the service keeps polling, so authorize any time)"))
			return nil
		}
		return err
	}
	// The Organization is named here because this is the moment it becomes
	// true, and the installer's output is what the operator keeps.
	if organization != "" {
		rememberOrganization(organization, organizationID)
		cfg, _ := identity.LoadConfig()
		fmt.Println()
		fmt.Println(msg.T("register.authorized_in", "✓ {name} was authorized and is now ACTIVE in {organization}.", "name", name, "organization", cfg.Organization()))
	} else {
		fmt.Println()
		fmt.Println(msg.T("register.authorized", "✓ {name} was authorized and is now ACTIVE.", "name", name))
	}
	fmt.Println(msg.T("register.authorized.manage", "  manage:  {command}", "command", statusHint()))
	printNoPluginHint()
	return nil
}

// installerPluginsEnv names the Plugins the installer installs right after
// registering returns, so a run that has some coming says nothing about none.
const installerPluginsEnv = "EASYSSL_PLUGINS"

func printNoPluginHint() {
	if h := noPluginHint(pluginmgr.New(nil, nil).List, os.Getenv); h != "" {
		fmt.Println()
		fmt.Println(h)
	}
}

// noPluginHint tells the operator how to get a Plugin when the host ends a
// registration with none: the Agent finds and updates Certificates only
// through one, and the host is the one place that knows whether it has any.
// It is "" when the host has one, the installer is about to install some, or
// the Plugins cannot be listed.
func noPluginHint(list func() ([]pluginmgr.Installed, error), getenv func(string) string) string {
	if strings.TrimSpace(getenv(installerPluginsEnv)) != "" {
		return ""
	}
	if installed, err := list(); err != nil || len(installed) > 0 {
		return ""
	}
	return msg.T("register.no_plugin", "No Plugin is installed on this host, and the Agent finds and updates Certificates only through one.\n  see them:    sudo easyssl-agent plugin catalog\n  install one: sudo easyssl-agent plugin install <name>")
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
	return msg.T("register.awaiting_authorization", "Visit the Plugin marketplace: {url}\n\nWaiting for authorization from the web console (approve it at your web console › Agents)...", "url", marketplaceURL)
}

// Uninstall takes the Agent off this host. It deactivates the Agent on the
// Server (best effort: an unreachable Server must not stop an operator cleaning
// up a host), deletes the config and token either way, stops and removes the
// systemd unit and deletes the binary, then offers, each behind its own
// confirmation, to delete the installed Plugins and the private keys. It is
// host-side only: the Server can never trigger it, so a compromised Server or
// account cannot wipe an Agent off a machine it does not own. Certificates the
// Agent deployed elsewhere on the host are never touched, since removing them
// could take the host's services down.
//
// Deactivating rather than removing keeps the Agent's Targets: the web console
// can hand out a reactivation command that brings the same Agent back, on this
// host or on another one.
func Uninstall(ctx context.Context, assumeYes bool) error {
	if os.Geteuid() != 0 {
		return msg.Err.T("uninstall.not_root", "uninstall must run as root (use sudo)")
	}

	cfg, cfgErr := identity.LoadConfig()
	token, tokenErr := identity.LoadToken()
	installed := cfgErr == nil && tokenErr == nil
	if !installed {
		fmt.Println(msg.T("uninstall.not_registered", "No easySSL Agent registration found on this host; removing any leftover files."))
	} else {
		fmt.Println(msg.T("uninstall.registered", "The easySSL Agent on this host is registered with {server} in {organization}.",
			"server", cfg.ServerURL, "organization", cfg.Organization()))
	}

	t := openTerminal()
	if t != nil {
		defer t.close()
	}
	if !assumeYes && !confirmUninstall(t, installed, cfg.Organization()) {
		fmt.Println(msg.T("uninstall.aborted", "Aborted; nothing was changed."))
		return nil
	}

	// Deactivate first, while the token still exists on disk.
	if installed {
		deactivateOnServer(ctx, cfg, token)
	}

	hadUnit, hadState, hadBinary := service.Installed(), exists(identity.BaseDir), exists(service.BinaryPath)

	if err := service.Uninstall(); err != nil && !errors.Is(err, service.ErrUnsupportedInit) {
		return msg.Err.T("uninstall.remove_service", "removing the service: {err}", "err", err)
	}
	if hadUnit {
		fmt.Println(msg.T("uninstall.service_removed", "✓ {service} stopped and removed", "service", serviceName()))
	}

	if err := identity.RemoveAll(); err != nil {
		return msg.Err.T("uninstall.remove_state", "removing {path}: {err}", "path", identity.BaseDir, "err", err)
	}
	if hadState {
		fmt.Println(msg.T("uninstall.state_removed", "✓ config and token deleted from {path}", "path", identity.BaseDir))
	}

	if err := os.Remove(service.BinaryPath); err != nil && !os.IsNotExist(err) {
		return msg.Err.T("uninstall.remove_binary", "removing {path}: {err}", "path", service.BinaryPath, "err", err)
	}
	if hadBinary {
		fmt.Println(msg.T("uninstall.binary_removed", "✓ {path} deleted", "path", service.BinaryPath))
	}

	if !hadUnit && !hadState && !hadBinary {
		fmt.Println(msg.T("uninstall.nothing_to_remove", "Nothing to remove; this host has no easySSL Agent installed."))
		return nil
	}
	fmt.Println()
	fmt.Println(msg.T("uninstall.done", "easySSL Agent uninstalled. Certificates it deployed were left in place."))
	offerPluginRemoval(t)
	offerKeyRemoval(t)
	return nil
}

// deactivateOnServer tells the Server this token is done with. Every outcome is
// reported in words, because what the operator does next depends on it: a
// deactivated Agent needs nothing, and one the Server still accepts has to be
// deactivated from the web console by hand.
func deactivateOnServer(ctx context.Context, cfg identity.Config, token string) {
	api, err := serverapi.New(cfg.ServerURL)
	if err != nil {
		fmt.Printf("! %v\n", err)
		fmt.Println(msg.T("uninstall.deactivate.bad_url.by_hand", "  The Server still accepts this host's token: deactivate this Agent from the web console at {server}", "server", cfg.ServerURL))
		return
	}
	host, _ := os.Hostname()
	switch err := api.Unregister(ctx, token); {
	case err == nil:
		fmt.Println(msg.T("uninstall.deactivate.done", "✓ deactivated in {organization}; its Targets are kept, and the web console can reactivate it on this or another host", "organization", cfg.Organization()))
	case isUnknownToken(err):
		fmt.Println(msg.T("uninstall.deactivate.already", "✓ the Server no longer accepts this token (the Agent was already deactivated or removed)"))
	default:
		fmt.Println(msg.T("uninstall.deactivate.unreachable", "! could not reach {server}: {err}\n"+
			"  The Server still accepts this host's token: deactivate this Agent from the web console at {server}\n"+
			"  (Organization {organization}, host {host}), which is where the Agents are listed.",
			"server", cfg.ServerURL, "err", err, "organization", cfg.Organization(), "host", host))
	}
}

// offerPluginRemoval deletes the installed Plugin executables after a
// confirmation. Only with a terminal: --yes consents to uninstalling the Agent,
// not to everything it could take with it, so an unattended run leaves the
// Plugins and says where they are.
func offerPluginRemoval(t *terminal) {
	installed, err := pluginmgr.New(nil, nil).List()
	switch {
	case err != nil:
		fmt.Println()
		fmt.Println(msg.T("uninstall.plugins.list_failed", "! Plugins may remain in {path} and were NOT deleted (listing them failed: {err}).",
			"path", pluginmgr.InstallDir, "err", err))
		return
	case len(installed) == 0:
		return
	}
	fmt.Println()
	fmt.Println(msg.N("uninstall.plugins.remain", len(installed),
		"1 Plugin executable remains in {path}:",
		"{n} Plugin executables remain in {path}:",
		"path", pluginmgr.InstallDir))
	for _, p := range installed {
		fmt.Printf("    %s\n", p.Path)
	}
	if t == nil {
		fmt.Println(msg.T("uninstall.plugins.not_deleted", "  They were NOT deleted; delete that directory by hand if this host is being decommissioned."))
		return
	}
	if !msg.Yes(t.prompt(msg.T("uninstall.plugins.confirm", "Delete {path}? [y/N]: ", "path", pluginmgr.InstallDir))) {
		fmt.Println(msg.T("uninstall.plugins.kept", "  Kept."))
		return
	}
	if err := os.RemoveAll(pluginmgr.InstallDir); err != nil {
		fmt.Println(msg.T("uninstall.plugins.delete_failed", "! could not delete {path}: {err}", "path", pluginmgr.InstallDir, "err", err))
		return
	}
	fmt.Println(msg.T("uninstall.plugins.deleted", "✓ {path} deleted", "path", pluginmgr.InstallDir))
}

// offerKeyRemoval deletes the keystore after a confirmation that cannot be
// given by accident: the keys are the Agent's only copy of what every
// Certificate issued to this host is signed with, and nothing recovers them.
// Never through --yes, never by an empty answer, and never without a terminal.
func offerKeyRemoval(t *terminal) {
	n, err := keystore.Count()
	switch {
	case err != nil:
		fmt.Println()
		fmt.Println(msg.T("uninstall.keys.count_failed", "! private keys may remain in {path} and were NOT deleted (counting them failed: {err}).", "path", keystore.Dir(), "err", err))
		return
	case n == 0:
		return
	}
	fmt.Println()
	fmt.Println(msg.N("uninstall.keys_remain", n,
		"1 private key remains in {path}.",
		"{n} private keys remain in {path}.",
		"path", keystore.Dir()))
	// One line, wrapped by the terminal rather than here.
	fmt.Println(msg.T("uninstall.keys.only_copy", "  This is the only copy easySSL has of them: a Certificate whose key is gone cannot be deployed or renewed from this host again, and reactivating this Agent elsewhere needs these files copied there first. Copies a Deployment installed elsewhere on this host are left in place either way."))
	if t == nil {
		fmt.Println(msg.T("uninstall.keys.not_deleted", "  They were NOT deleted; delete the directory by hand if this machine is being decommissioned."))
		return
	}
	// The phrase is a message too: what has to be typed is what the prompt shows,
	// in its language, and it is long enough that no habit types it by accident.
	phrase := msg.T("uninstall.keys.phrase", "delete keys")
	answer := t.prompt(msg.T("uninstall.keys.confirm", "Type '{phrase}' to delete {path}, anything else keeps it: ", "phrase", phrase, "path", keystore.Dir()))
	if answer != phrase {
		fmt.Println(msg.T("uninstall.keys.kept", "  Kept."))
		return
	}
	if err := os.RemoveAll(keystore.Dir()); err != nil {
		fmt.Println(msg.T("uninstall.keys.delete_failed", "! could not delete {path}: {err}", "path", keystore.Dir(), "err", err))
		return
	}
	fmt.Println(msg.T("uninstall.keys.deleted", "✓ {path} deleted", "path", keystore.Dir()))
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
		fmt.Println(msg.T("uninstall.needs_confirmation", "Refusing to uninstall without confirmation: re-run with --yes."))
		return false
	}
	question := msg.T("uninstall.confirm.leftovers", "Remove the Agent and its files? [y/N]: ")
	if registered {
		question = msg.T("uninstall.confirm.registered", "Remove the Agent from this host, deactivating it in {organization}? [y/N]: ", "organization", organization)
	}
	return msg.Yes(t.prompt(question))
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
		return "", "", msg.Err.T("register.key.missing", "no registration key: set the REGISTRATION_KEY environment variable or pass --key (or REACTIVATION_TOKEN / --reactivation-token to resume a deactivated Agent)")
	}
	v := t.prompt(msg.T("register.key.prompt", "Paste your registration key (or a reactivation token): "))
	switch {
	case v == "":
		return "", "", msg.Err.T("register.key.empty", "a registration key is required")
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
// With no proposal and no terminal this returns an error rather than a silent
// empty name that the Server would refuse later.
func confirmName(t *terminal, fromFlag, proposed, hostname string) (string, error) {
	if fromFlag != "" {
		return fromFlag, nil
	}
	if t == nil {
		if proposed == "" {
			return "", msg.Err.T("register.name.no_hostname", "this host reports no hostname to name the Agent after: pass --name or set AGENT_NAME")
		}
		return proposed, nil
	}
	if proposed == "" {
		v := t.prompt(msg.T("register.name.prompt_empty", "Agent name: "))
		if v == "" {
			return "", msg.Err.T("register.name.empty", "an Agent name is required: this host reports no hostname to propose one from")
		}
		return v, nil
	}
	question := msg.T("register.name.prompt", "Agent name [{proposed}]: ", "proposed", proposed)
	if hostname != "" && hostname != proposed {
		question = msg.T("register.name.prompt_with_host", "Agent name (host {host}) [{proposed}]: ", "host", hostname, "proposed", proposed)
	}
	v := t.prompt(question)
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
	fmt.Println(msg.T("register.host", "✓ host  {os} · {type}", "os", diag.OS, "type", diag.HostType))
	if reactivation != "" {
		fmt.Println(msg.T("register.submitting_reactivation", "→ submitting reactivation to {server}", "server", serverURL))
	} else {
		fmt.Println(msg.T("register.submitting", "→ submitting registration to {server}", "server", serverURL))
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
				return wire.RegistrationResponse{}, msg.Err.T("register.refused.key", "registration failed: the registration key was not accepted")
			case wire.CodeInvalidReactivationToken:
				return wire.RegistrationResponse{}, msg.Err.T("register.refused.reactivation_token", "reactivation failed: the token was not accepted (unknown, expired, or already used). Generate another from the Agent's page in the web console")
			}
		}
		return wire.RegistrationResponse{}, msg.Err.T("register.failed", "registration failed: {err}", "err", err)
	}
	if resp.AgentID == "" {
		return wire.RegistrationResponse{}, msg.Err.T("register.no_agent_id", "registration failed: did not receive an Agent ID from the Server (is it older than this Agent?)")
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
			return "", "", msg.Err.T("register.rejected", "registration was rejected (or the token was revoked)")
		}
		// Still pending, or a transient error: wait and ask again.
		select {
		case <-ctx.Done():
			return "", "", ctx.Err()
		case <-time.After(time.Duration(pollSeconds) * time.Second):
		}
	}
}

func isUnknownToken(err error) bool {
	apiErr, ok := errors.AsType[*serverapi.APIError](err)
	return ok && apiErr.Code == wire.CodeUnknownToken
}

// terminal is the operator's input source. It is deliberately not os.Stdin in
// the common case: the one-line installer runs as `curl … | sudo bash`, so
// stdin is the script pipe and reading it would consume the installer script
// rather than the operator's typing. Opening the controlling terminal /dev/tty
// reaches the human instead.
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

// ask is prompt for a question that is asked again until its answer is one it
// accepts: ok is false once nothing more can be read, which prompt cannot
// tell from an empty answer and which would otherwise ask forever.
func (t *terminal) ask(label string) (answer string, ok bool) {
	fmt.Fprint(t.out, label)
	line, err := t.in.ReadString('\n')
	if err != nil && line == "" {
		return "", false
	}
	return strings.TrimSpace(line), true
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
