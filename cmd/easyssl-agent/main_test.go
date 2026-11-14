package main

import (
	"context"
	"encoding/json"
	"github.com/easyssl-io/easyssl-contract/plugincontract"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/easyssl-io/easyssl-agent/internal/flow"
	"github.com/easyssl-io/easyssl-agent/internal/identity"
	"github.com/easyssl-io/easyssl-agent/internal/pluginmgr"
	"github.com/easyssl-io/easyssl-contract/catalog"
	"github.com/easyssl-io/easyssl-contract/wire"
)

func TestPluginListLineShowsContractAndFullSHA256(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	got := pluginListLine(wire.PluginInventory{ID: "generic-cli", Describe: []byte(`{"contractVersion":"0.2.0","version":"0.0.1"}`), SHA256: digest})
	want := "generic-cli      v0.0.1      contract 0.2.0   sha256:" + digest
	if got != want {
		t.Fatalf("plugin list line = %q, want %q", got, want)
	}
	// A build older than the field names no contract.
	if got := pluginListLine(wire.PluginInventory{ID: "generic-cli", Describe: []byte(`{"version":"0.0.1"}`), SHA256: digest}); !strings.Contains(got, "contract ?") {
		t.Fatalf("no contract: %q", got)
	}
	unobserved := pluginListLine(wire.PluginInventory{ID: "generic-cli", SHA256: digest, Unobserved: true})
	if !strings.Contains(unobserved, "did not answer discover") || !strings.Contains(unobserved, digest) {
		t.Fatalf("unobserved line = %q", unobserved)
	}
}

func TestRootPreflightCoversEveryOperationalCommand(t *testing.T) {
	tests := []struct {
		args []string
		cmd  string
	}{
		{[]string{"register", "--server", "https://example.test"}, "register"},
		{[]string{"run"}, "run"},
		{[]string{"status"}, "status"},
		{[]string{"uninstall", "--yes"}, "uninstall"},
		{[]string{"migrate"}, "migrate"},
		{[]string{"plugin", "catalog"}, "plugin catalog"},
		{[]string{"plugin", "install", "generic-cli"}, "plugin install"},
		{[]string{"plugin", "list"}, "plugin list"},
		{[]string{"plugin", "update"}, "plugin update"},
		{[]string{"update", "--check"}, "update"},
		{[]string{"language", "es"}, "language"},
	}
	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			err := rootPreflight(tt.args, 1000)
			if err == nil {
				t.Fatal("non-root preflight returned no error")
			}
			if tt.cmd == "register" {
				return
			}
			want := "this command requires root; re-run as root with \"sudo easyssl-agent " + tt.cmd + "\""
			if err.Error() != want {
				t.Fatalf("error = %q, want %q", err, want)
			}
		})
	}
}

func TestRootPreflightAllowsRootAndNonOperationalCommands(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
		euid int
	}{
		{"root", []string{"plugin", "install", "generic-cli"}, 0},
		{"help", []string{"help"}, 1000},
		{"unknown", []string{"unknown"}, 1000},
		{"plugin usage", []string{"plugin"}, 1000},
		{"unknown plugin command", []string{"plugin", "unknown"}, 1000},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := rootPreflight(tt.args, tt.euid); err != nil {
				t.Fatalf("preflight = %v, want no error", err)
			}
		})
	}
}

// A `register` refused before it reaches the registration wrote nothing, so it
// must read as unchanged: the install script puts the replaced build back only
// then.
func TestRegisterRefusedFlagsAreUnchanged(t *testing.T) {
	for _, args := range [][]string{{"--no-such-flag"}, {}} {
		if err := cmdRegister(context.Background(), args); !flow.Unchanged(err) {
			t.Errorf("register %v = %v, want an unchanged error", args, err)
		}
	}
	if err := cmdRegister(context.Background(), []string{"--help"}); err != nil {
		t.Errorf("register --help = %v, want nil", err)
	}
}

// A Server that no longer speaks this Agent's contract version is not a Server
// that cannot be reached: status says it refuses the Agent and what to do.
func TestStatusNamesAContractRefusal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(wire.ErrorResponse{Code: wire.CodeContractUnsupported, Message: "this Server speaks contract version 0.3.0"})
	}))
	defer srv.Close()
	detail, _ := serverState(identity.Config{ServerURL: srv.URL}, "token", nil)
	if !strings.HasPrefix(detail, "refused (the Server answered, but no longer speaks this Agent's contract "+wire.ContractVersion) {
		t.Fatalf("status = %q", detail)
	}
}

// What `version --contracts` prints is what this build's contract check lets
// through, so a newer Agent's answer can be trusted by the one it replaces.
func TestAcceptedContractsAreWhatCompatibleAccepts(t *testing.T) {
	got := pluginmgr.AcceptedContracts()
	if len(got) == 0 {
		t.Fatal("no accepted contracts")
	}
	for _, breaking := range got {
		if !plugincontract.Compatible(breaking + ".0") {
			t.Errorf("%s.0 is listed but not Compatible", breaking)
		}
	}
	current, _ := plugincontract.BreakingVersion(plugincontract.ContractVersion)
	if got[0] != current {
		t.Errorf("first = %s, want this build's own %s", got[0], current)
	}
}

// A catalog entry heads with its version and contract, not with its party,
// which "by <publisher>" below already says.
func TestCatalogEntryLineShowsTheContractAndNotTheParty(t *testing.T) {
	got := catalogEntryLine(catalog.Plugin{ID: "nginx", Version: "0.2.0", ContractVersion: "0.2.0", Party: catalog.PartyFirst})
	if want := "nginx            v0.2.0      contract 0.2.0"; got != want {
		t.Fatalf("catalog line = %q, want %q", got, want)
	}
	if got := catalogEntryLine(catalog.Plugin{ID: "nginx", Version: "0.2.0"}); strings.Contains(got, "contract") {
		t.Fatalf("no contract: %q", got)
	}
}

// A command's help says how to call it and what it does, and lists flags
// under a heading only when there are some: `language -help` once printed
// a heading and nothing under it.
func TestHelpSaysWhatTheCommandDoes(t *testing.T) {
	help := func(withFlag bool) string {
		fs := newFlagSet("x", "usage: easyssl-agent x [<arg>]", "Does x.")
		if withFlag {
			fs.Bool("yes", false, "skip the prompt")
		}
		var b strings.Builder
		fs.SetOutput(&b)
		fs.Usage()
		return b.String()
	}
	if got := help(false); got != "usage: easyssl-agent x [<arg>]\nDoes x.\n" {
		t.Errorf("help without flags = %q, want the usage and the summary alone", got)
	}
	if got := help(true); !strings.HasPrefix(got, "usage: easyssl-agent x [<arg>]\nDoes x.\n\nFlags:\n") || !strings.Contains(got, "-yes") {
		t.Errorf("help with a flag = %q, want the usage, the summary, then the flags under their heading", got)
	}
}
