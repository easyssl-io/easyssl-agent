package pluginmgr

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
