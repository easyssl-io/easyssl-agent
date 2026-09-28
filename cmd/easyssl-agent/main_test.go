package main

import (
	"strings"
	"testing"

	"github.com/easyssl-io/easyssl-contract/wire"
)

func TestPluginListLineShowsFullSHA256(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	got := pluginListLine(wire.PluginInventory{ID: "generic-cli", Version: "0.0.1", Digest: digest})
	want := "generic-cli      v0.0.1      sha256:" + digest
	if got != want {
		t.Fatalf("plugin list line = %q, want %q", got, want)
	}
	unobserved := pluginListLine(wire.PluginInventory{ID: "generic-cli", Digest: digest, Unobserved: true})
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
		{[]string{"status", "--json"}, "status"},
		{[]string{"uninstall", "--yes"}, "uninstall"},
		{[]string{"plugin", "catalog"}, "plugin catalog"},
		{[]string{"plugin", "install", "generic-cli"}, "plugin install"},
		{[]string{"plugin", "list", "--json"}, "plugin list"},
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
