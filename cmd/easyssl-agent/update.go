package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/easyssl-io/easyssl-agent/internal/buildinfo"
	"github.com/easyssl-io/easyssl-agent/internal/identity"
	"github.com/easyssl-io/easyssl-agent/internal/inventory"
	"github.com/easyssl-io/easyssl-agent/internal/msg"
	"github.com/easyssl-io/easyssl-agent/internal/pluginmgr"
	"github.com/easyssl-io/easyssl-agent/internal/selfupdate"
	"github.com/easyssl-io/easyssl-agent/internal/serverapi"
	"github.com/easyssl-io/easyssl-agent/internal/service"
	"github.com/easyssl-io/easyssl-contract/plugincontract"
	"github.com/easyssl-io/easyssl-contract/wire"
)

// cmdVersion prints this build's version alone, which `update` reads from a
// downloaded build to know it runs on this host before it replaces this one.
// With --contracts it prints instead the breaking contract versions this
// build accepts from a Plugin, which `update` reads to know which installed
// Plugins the new build would refuse; with --contract the contract version it
// speaks, which a release records.
func cmdVersion(args []string) error {
	fs := newFlagSet("version")
	contracts := fs.Bool("contracts", false, msg.T("version.flag.contracts", "print the contract versions this Agent accepts from a Plugin"))
	contract := fs.Bool("contract", false, msg.T("version.flag.contract", "print the contract version this Agent speaks"))
	_ = fs.Parse(args)
	if *contract {
		fmt.Println(wire.ContractVersion)
		return nil
	}
	if *contracts {
		fmt.Println(strings.Join(pluginmgr.AcceptedContracts(), " "))
		return nil
	}
	fmt.Println(buildinfo.Version)
	return nil
}

// cmdUpdate brings the Agent, then its Plugins, to the builds the Server's
// catalog offers. The Agent goes first, because an Agent too old for the
// current Plugins refuses them; the Plugins are then updated by the new Agent.
// --agent-only leaves the Plugins alone, and --check changes nothing.
func cmdUpdate(ctx context.Context, args []string) error {
	fs := newFlagSet("update")
	yes := fs.Bool("yes", false, msg.T("update.flag.yes", "update without the confirmation prompt"))
	check := fs.Bool("check", false, msg.T("update.flag.check", "only say what would be updated"))
	agentOnly := fs.Bool("agent-only", false, msg.T("update.flag.agent_only", "update the Agent and leave the Plugins as they are"))
	_ = fs.Parse(args)
	// Taken before the installed build is read and held through the Plugins'
	// update and any rollback, which runs in this process; --check changes
	// nothing and takes none.
	if !*check {
		unlock, err := selfupdate.Lock(identity.UpdateLockPath())
		if err != nil {
			return err
		}
		defer unlock()
	}

	cfg, err := identity.LoadConfig()
	if err != nil {
		return stateError("update", err)
	}
	api, err := serverapi.New(cfg.ServerURL)
	if err != nil {
		return err
	}
	cat, err := api.Catalog(ctx)
	if err != nil {
		return msg.Err.T("plugin.install.catalog_failed", "reading the Marketplace catalog: {err}", "err", err)
	}
	digest, err := digestOf(service.BinaryPath)
	if err != nil {
		return err
	}
	plan, err := selfupdate.Decide(cat.Agent, runtime.GOOS, runtime.GOARCH, buildinfo.Version, digest)
	if err != nil {
		return err
	}
	if plan.Needed {
		fmt.Println(msg.T("update.agent.planned", "Agent: {current} → {offered}", "current", plan.Current, "offered", plan.Offered))
	} else {
		fmt.Println(msg.T("update.agent.current", "Agent: {current}, up to date", "current", plan.Current))
	}
	var plugins []pluginmgr.PluginUpdate
	if !*agentOnly {
		if plugins, err = pluginmgr.New(api, agentLogger()).PlanUpdates(ctx, nil, runtime.GOOS, runtime.GOARCH); err != nil {
			return err
		}
		printPluginPlan(plugins)
	}
	pluginsNeeded := countNeeded(plugins)
	// A Plugin whose offered build this Agent does not run may be run by the
	// new one, which plans again after it replaces this one.
	pending := map[string]string{}
	if plan.Needed {
		for _, p := range plugins {
			if p.State == pluginmgr.UpdateNeedsAgent {
				pending[p.ID] = p.OfferedContract
			}
		}
	}
	if *check {
		return nil
	}
	if !plan.Needed && pluginsNeeded == 0 {
		fmt.Println(msg.T("update.nothing", "Nothing to update."))
		return nil
	}
	if !*yes && !confirm(msg.T("update.confirm", "Update? [y/N] ")) {
		return msg.Err.T("update.declined", "Nothing updated.")
	}

	if !plan.Needed {
		return updatePlugins(ctx, cfg, api, nil)
	}
	// Each Plugin about to be updated, to the contract its new build was made
	// against: under the new Agent, that build is the one that runs.
	updating := map[string]string{}
	if !*agentOnly {
		for _, p := range plugins {
			if p.State == pluginmgr.UpdateNeeded {
				updating[p.ID] = p.OfferedContract
			}
		}
	}
	if err := updateAgent(ctx, api, plan, updating, pending, *agentOnly); err != nil {
		return err
	}
	if pluginsNeeded == 0 && len(pending) == 0 {
		return nil
	}
	// The new build installs the Plugins: it is the one that runs them, and the
	// one whose contract version they were built for.
	// #nosec G204 -- the installed Agent binary, just verified and swapped in.
	run := exec.CommandContext(ctx, service.BinaryPath, "plugin", "update", "--yes")
	run.Env = append(os.Environ(), selfupdate.LockHeldEnv+"=1")
	run.Stdin, run.Stdout, run.Stderr = os.Stdin, os.Stdout, os.Stderr
	return run.Run()
}

// updateAgent replaces the installed Agent with the planned build and restarts
// the service, putting the previous build back if the service does not stay
// up on the new one. It refuses, before replacing anything, a build that
// would refuse an installed Plugin not in updating. A Plugin in pending, whose
// offered build this Agent does not run, counts as updated when the new build
// runs that build, since it will then install it, and as left otherwise.
func updateAgent(ctx context.Context, api *serverapi.Client, plan selfupdate.Plan, updating, pending map[string]string, agentOnly bool) error {
	staged, err := selfupdate.Stage(ctx, api, plan, service.BinaryPath)
	if err != nil {
		return err
	}
	contracts, err := pluginmgr.New(api, agentLogger()).Contracts(ctx)
	if err != nil {
		_ = os.Remove(staged)
		return err
	}
	accepts := selfupdate.Accepts(ctx, staged)
	for id, contract := range pending {
		if breaking, ok := plugincontract.BreakingVersion(contract); ok && slices.Contains(accepts, breaking) {
			updating[id] = contract
		}
	}
	if stranded := selfupdate.Strands(accepts, contracts, updating); len(stranded) > 0 {
		_ = os.Remove(staged)
		names := strings.Join(stranded, ", ")
		if agentOnly {
			return msg.Err.T("update.strands.agent_only", "Agent {version} would refuse {plugins}, built against a contract it no longer speaks, so nothing was changed. Update the Agent and its Plugins together: sudo easyssl-agent update", "version", plan.Offered, "plugins", names)
		}
		return msg.Err.T("update.strands", "Agent {version} would refuse {plugins}, built against a contract it no longer speaks, and the Marketplace offers no build of them it runs, so nothing was changed", "version", plan.Offered, "plugins", names)
	}
	if err := selfupdate.Swap(service.BinaryPath, staged); err != nil {
		_ = os.Remove(staged)
		return err
	}
	restarted := time.Now()
	err = service.Start()
	if err == nil {
		fmt.Println(msg.T("update.agent.watching", "Agent {version} started; waiting for its first check-in…", "version", plan.Offered))
	}
	if err != nil || !selfupdate.Settle(ctx, service.State, func() bool { return identity.CheckedInSince(plan.Offered, restarted) }, time.Second, 15*time.Second) {
		if rerr := selfupdate.Restore(service.BinaryPath); rerr != nil {
			return msg.Err.T("update.restore_failed", "the new Agent did not stay up, and putting the previous one back failed: {err}; it is kept as {path}", "err", rerr, "path", service.BinaryPath+".prev")
		}
		_ = service.Start()
		return msg.Err.T("update.rolled_back", "the service did not stay up on Agent {version}, so the previous build ({previous}) is back", "version", plan.Offered, "previous", plan.Current)
	}
	fmt.Println(msg.T("update.agent.done", "✓ Agent updated to {version}; the service restarted on it", "version", plan.Offered))
	return nil
}

// cmdPluginUpdate installs the catalog's build of each installed Plugin, or of
// those named, whose bytes differ from it.
func cmdPluginUpdate(ctx context.Context, args []string) error {
	fs := newFlagSet("plugin update")
	yes := fs.Bool("yes", false, msg.T("plugin.update.flag.yes", "update without the confirmation prompt"))
	check := fs.Bool("check", false, msg.T("update.flag.check", "only say what would be updated"))
	downgrade := fs.Bool("allow-downgrade", false, msg.T("plugin.update.flag.allow_downgrade", "also install a Marketplace build older than the installed one"))
	_ = fs.Parse(args)
	// Run by an `update` that holds the lock for it, it takes none.
	if !*check && os.Getenv(selfupdate.LockHeldEnv) == "" {
		unlock, err := selfupdate.Lock(identity.UpdateLockPath())
		if err != nil {
			return err
		}
		defer unlock()
	}
	cfg, err := identity.LoadConfig()
	if err != nil {
		return stateError("plugin update", err)
	}
	api, err := serverapi.New(cfg.ServerURL)
	if err != nil {
		return err
	}
	plugins, err := pluginmgr.New(api, agentLogger()).PlanUpdates(ctx, fs.Args(), runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return err
	}
	if *downgrade {
		pluginmgr.AllowDowngrade(plugins)
	}
	printPluginPlan(plugins)
	if *check {
		return nil
	}
	if countNeeded(plugins) == 0 {
		fmt.Println(msg.T("update.nothing", "Nothing to update."))
		return nil
	}
	if !*yes && !confirm(msg.T("update.confirm", "Update? [y/N] ")) {
		return msg.Err.T("update.declined", "Nothing updated.")
	}
	return updatePlugins(ctx, cfg, api, plugins)
}

// updatePlugins installs every Plugin plugins marks as needing it, planning
// again when plugins is nil, and reports the inventory once, as install does.
func updatePlugins(ctx context.Context, cfg identity.Config, api *serverapi.Client, plugins []pluginmgr.PluginUpdate) error {
	mgr := pluginmgr.New(api, agentLogger())
	if plugins == nil {
		var err error
		if plugins, err = mgr.PlanUpdates(ctx, nil, runtime.GOOS, runtime.GOARCH); err != nil {
			return err
		}
	}
	var updated int
	for _, p := range plugins {
		if p.State != pluginmgr.UpdateNeeded {
			continue
		}
		inst, err := mgr.Install(ctx, p.ID, runtime.GOOS, runtime.GOARCH)
		if err != nil {
			return msg.Err.T("plugin.update.failed", "updating {plugin}: {err}", "plugin", p.ID, "err", err)
		}
		updated++
		fmt.Println(msg.T("plugin.update.done", "✓ {plugin} updated to {version}", "plugin", inst.ID, "version", inst.Version))
	}
	if updated == 0 {
		return nil
	}
	// As after an install: the web console is current within one round trip.
	if token, err := identity.LoadToken(); err == nil {
		if inv, err := inventory.Collect(ctx, mgr); err == nil {
			_ = api.ReportInventory(ctx, token, inv)
		}
	}
	return nil
}

func printPluginPlan(plugins []pluginmgr.PluginUpdate) {
	for _, p := range plugins {
		switch p.State {
		case pluginmgr.UpdateNeeded:
			fmt.Println(msg.T("update.plugin.planned", "Plugin {plugin}: {current} → {offered}", "plugin", p.ID, "current", orUnknown(p.Current), "offered", p.Offered))
		case pluginmgr.UpdateCurrent:
			fmt.Println(msg.T("update.plugin.current", "Plugin {plugin}: {offered}, up to date", "plugin", p.ID, "offered", p.Offered))
		case pluginmgr.UpdateNotOffered:
			fmt.Println(msg.T("update.plugin.not_offered", "Plugin {plugin}: no longer offered by the Server, left as it is", "plugin", p.ID))
		case pluginmgr.UpdateNoBuild:
			fmt.Println(msg.T("update.plugin.no_build", "Plugin {plugin}: no build for this host's platform, left as it is", "plugin", p.ID))
		case pluginmgr.UpdateNeedsAgent:
			fmt.Println(msg.T("update.plugin.needs_agent", "Plugin {plugin}: {current}, left as it is; the Marketplace's {offered} is built against contract {contract}, which this Agent does not run (it runs {accepted}), so it needs a newer Agent",
				"plugin", p.ID, "current", orUnknown(p.Current), "offered", p.Offered, "contract", p.OfferedContract, "accepted", strings.Join(pluginmgr.AcceptedContracts(), ", ")))
		case pluginmgr.UpdateOlder:
			fmt.Println(msg.T("update.plugin.older", "Plugin {plugin}: {current}, newer than the Marketplace's {offered}, left as it is; `sudo easyssl-agent plugin update --allow-downgrade {plugin}` installs it", "plugin", p.ID, "current", p.Current, "offered", p.Offered))
		}
	}
}

// orUnknown stands in for a version a Plugin did not give.
func orUnknown(v string) string {
	if v == "" {
		return "?"
	}
	return v
}

func countNeeded(plugins []pluginmgr.PluginUpdate) int {
	n := 0
	for _, p := range plugins {
		if p.State == pluginmgr.UpdateNeeded {
			n++
		}
	}
	return n
}

func digestOf(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
