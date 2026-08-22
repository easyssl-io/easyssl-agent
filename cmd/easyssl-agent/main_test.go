package main

import (
	"strings"
	"testing"

	"github.com/easyssl-io/easyssl-agent/internal/pluginmgr"
)

func TestPluginListLineShowsFullSHA256(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	got := pluginListLine(pluginmgr.Installed{
		ID:      "generic-cli",
		Version: "0.1.0",
		Digest:  digest,
	})
	want := "generic-cli      v0.1.0      sha256:" + digest
	if got != want {
		t.Fatalf("plugin list line = %q, want %q", got, want)
	}
}
