package selfupdate

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

// A new Agent that would refuse an installed Plugin strands it, unless the
// update about to follow brings that Plugin a new build; a build that cannot
// say what it accepts strands nothing.
func TestStrands(t *testing.T) {
	plugins := map[string]string{"nginx": "0.1.0", "apache": "0.2.1", "generic-cli": "0.3.0", "odd": "x"}
	for _, c := range []struct {
		name     string
		accepts  []string
		updating map[string]bool
		want     []string
	}{
		{"the same range", []string{"0.3", "0.2"}, nil, []string{"nginx", "odd"}},
		{"the stranded one is being updated", []string{"0.3", "0.2"}, map[string]bool{"nginx": true}, []string{"odd"}},
		{"an older range", []string{"0.2", "0.1"}, nil, []string{"generic-cli", "odd"}},
		{"a build that cannot say", nil, nil, nil},
	} {
		if got := Strands(c.accepts, plugins, c.updating); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: Strands = %v, want %v", c.name, got, c.want)
		}
	}
}

// Accepts reads `version --contracts` from the staged build, and gives nothing
// for a build that does not know the flag.
func TestAccepts(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a shell script stands in for the build")
	}
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	knows := write("knows", `[ "$1 $2" = "version --contracts" ] && echo "0.3 0.2" && exit 0; exit 2`)
	older := write("older", `echo "flag provided but not defined: -contracts" >&2; exit 2`)
	if got := Accepts(context.Background(), knows); !reflect.DeepEqual(got, []string{"0.3", "0.2"}) {
		t.Errorf("Accepts = %v, want [0.3 0.2]", got)
	}
	if got := Accepts(context.Background(), older); got != nil {
		t.Errorf("Accepts of an older build = %v, want nil", got)
	}
}
