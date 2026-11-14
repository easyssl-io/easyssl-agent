package pluginmgr

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/easyssl-io/easyssl-contract/catalog"
	"github.com/easyssl-io/easyssl-contract/plugincontract"
)

// Each installed Plugin is compared with the catalog by digest: the catalog's
// own bytes are current, others are updated, and one the catalog no longer
// offers is left alone. Each carries the version its build answers with. Naming one not installed is refused, since an update
// installs nothing new.
func TestPlanUpdatesComparesByDigest(t *testing.T) {
	m := newManager(t, newMarketplace(t, ""), answer(), nil)
	if err := os.MkdirAll(m.installDir, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(id, body string) {
		if err := os.WriteFile(filepath.Join(m.installDir, id), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write("generic-cli", "an older build\n")
	write("retired", "a Plugin the catalog dropped\n")

	plan, err := m.PlanUpdates(context.Background(), nil, "linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]UpdateState{}
	for _, p := range plan {
		got[p.ID] = p.State
	}
	if got["generic-cli"] != UpdateNeeded || got["retired"] != UpdateNotOffered || len(got) != 2 {
		t.Fatalf("plan = %+v", plan)
	}
	// The installed build's own version, for the plan to show what it
	// replaces.
	for _, p := range plan {
		if p.ID == "generic-cli" && p.Current != answer().Version {
			t.Fatalf("current = %q, want the installed build's %q", p.Current, answer().Version)
		}
	}

	write("generic-cli", artifactBody)
	if plan, _ = m.PlanUpdates(context.Background(), []string{"generic-cli"}, "linux", "amd64"); len(plan) != 1 || plan[0].State != UpdateCurrent {
		t.Fatalf("the catalog's own bytes: %+v", plan)
	}
	if plan, _ = m.PlanUpdates(context.Background(), []string{"generic-cli"}, "linux", "arm64"); plan[0].State != UpdateNoBuild {
		t.Fatalf("no build for the platform: %+v", plan)
	}
	if _, err := m.PlanUpdates(context.Background(), []string{"nginx"}, "linux", "amd64"); err == nil || !strings.Contains(err.Error(), "not installed") {
		t.Fatalf("naming one not installed = %v", err)
	}
}

// A Marketplace build at a lower version than the installed one is left as it
// is, as the Agent never downgrades itself, unless a downgrade is asked for.
func TestPlanUpdatesLeavesANewerInstalledBuild(t *testing.T) {
	newer := answer()
	newer.Version = "10.0.0" // the catalog offers 9.9.9-catalog-says
	m := newManager(t, newMarketplace(t, ""), newer, nil)
	if err := os.MkdirAll(m.installDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(m.installDir, "generic-cli"), []byte("a later build\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	plan, err := m.PlanUpdates(context.Background(), nil, "linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != 1 || plan[0].State != UpdateOlder || plan[0].Current != "10.0.0" {
		t.Fatalf("plan = %+v, want generic-cli left as older", plan)
	}
	AllowDowngrade(plan)
	if plan[0].State != UpdateNeeded {
		t.Fatalf("after AllowDowngrade = %+v, want it updated", plan)
	}
}

// A Marketplace build speaking a contract this Agent does not run is left
// as it is, and neither planning nor installing downloads it, nor does
// `plugin install` get as far as asking; the refusal names the contract this
// Agent speaks and those it runs.
func TestABuildOnAContractThisAgentDoesNotRunIsNeverDownloaded(t *testing.T) {
	m := newManager(t, newMarketplaceSpeaking(t, "", catalog.PartyFirst, "99.0.0"), answer(), nil)
	if err := os.MkdirAll(m.installDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(m.installDir, "generic-cli"), []byte("an older build\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	plan, err := m.PlanUpdates(context.Background(), nil, "linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != 1 || plan[0].State != UpdateNeedsAgent || plan[0].OfferedContract != "99.0.0" {
		t.Fatalf("plan = %+v, want generic-cli left for a newer Agent", plan)
	}
	// What `plugin install` checks before it asks for authorization.
	if err := m.Installable(context.Background(), []string{"generic-cli"}, "linux", "amd64"); err == nil || !strings.Contains(err.Error(), `"99.0.0"`) {
		t.Fatalf("installable = %v, want the contract refused", err)
	}
	_, err = m.Install(context.Background(), "generic-cli", "linux", "amd64")
	if err == nil || !strings.Contains(err.Error(), `"99.0.0"`) || !strings.Contains(err.Error(), "speaks contract "+plugincontract.ContractVersion) ||
		!strings.Contains(err.Error(), strings.Join(AcceptedContracts(), ", ")) {
		t.Fatalf("install = %v, want a refusal naming both contracts", err)
	}
}
