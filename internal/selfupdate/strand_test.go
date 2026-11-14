package selfupdate

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

// A new Agent that would refuse a Plugin strands it: the installed build, or
// the catalog's build an update is about to replace it with. A build that
// cannot say what it accepts strands nothing.
func TestStrands(t *testing.T) {
	installed := map[string]string{"nginx": "0.1.0", "apache": "0.2.1", "generic-cli": "0.3.0", "odd": "x"}
	for _, c := range []struct {
		name    string
		accepts []string
		updates map[string]string
		want    []string
	}{
		{"the same range", []string{"0.3", "0.2"}, nil, []string{"nginx", "odd"}},
		{"its update runs under the new Agent", []string{"0.3", "0.2"}, map[string]string{"nginx": "0.3.0"}, []string{"odd"}},
		{"its update does not", []string{"0.3", "0.2"}, map[string]string{"nginx": "0.1.1"}, []string{"nginx", "odd"}},
		{"an update to a running build is judged by its build", []string{"0.3", "0.2"}, map[string]string{"apache": "0.1.0"}, []string{"apache", "nginx", "odd"}},
		{"a catalog that does not say", []string{"0.3", "0.2"}, map[string]string{"nginx": ""}, []string{"odd"}},
		{"an older range", []string{"0.2", "0.1"}, nil, []string{"generic-cli", "odd"}},
		{"a build that cannot say", nil, nil, nil},
	} {
		if got := Strands(c.accepts, installed, c.updates); !reflect.DeepEqual(got, c.want) {
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
