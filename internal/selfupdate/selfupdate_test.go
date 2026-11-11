package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/easyssl-io/easyssl-contract/catalog"
)

func digest(b string) string {
	s := sha256.Sum256([]byte(b))
	return hex.EncodeToString(s[:])
}

func entry(version, sha string) *catalog.Agent {
	return &catalog.Agent{Version: version, Artifacts: []catalog.Artifact{{OS: "linux", Arch: "amd64", SHA256: sha, URL: "/api/v1/download/easyssl-agent/linux/amd64"}}}
}

// The digest decides whether to update; a build offered at a lower version is
// never taken, and nothing is taken without a digest to check.
func TestDecide(t *testing.T) {
	for _, c := range []struct {
		name     string
		entry    *catalog.Agent
		goarch   string
		current  string
		digest   string
		needed   bool
		errMatch string
	}{
		{"newer release", entry("0.2.2", "aa"), "amd64", "0.2.1", "bb", true, ""},
		{"same bytes", entry("0.2.2", "aa"), "amd64", "0.2.2", "aa", false, ""},
		{"another build of the same release", entry("0.2.2+dev.bbbbbbbbbbbb", "aa"), "amd64", "0.2.2+dev.aaaaaaaaaaaa", "bb", true, ""},
		{"no downgrade", entry("0.2.1", "aa"), "amd64", "0.2.2", "bb", false, ""},
		{"no Agent in the catalog", nil, "amd64", "0.2.1", "bb", false, "offers no Agent"},
		{"no build for the platform", entry("0.2.2", "aa"), "arm64", "0.2.1", "bb", false, "no Agent build"},
		{"no digest", entry("0.2.2", ""), "amd64", "0.2.1", "bb", false, "no digest"},
	} {
		t.Run(c.name, func(t *testing.T) {
			p, err := Decide(c.entry, "linux", c.goarch, c.current, c.digest)
			if c.errMatch != "" {
				if err == nil || !strings.Contains(err.Error(), c.errMatch) {
					t.Fatalf("err = %v", err)
				}
				return
			}
			if err != nil || p.Needed != c.needed {
				t.Fatalf("plan = %+v, %v", p, err)
			}
		})
	}
}

func TestOlder(t *testing.T) {
	for _, c := range []struct {
		v, than string
		want    bool
	}{
		{"0.2.1", "0.2.2", true},
		{"0.2.2+dev.aaaaaaaaaaaa", "0.2.2", false},
		{"0.10.0", "0.9.0", false},
		{"0.2.2-rc1", "0.2.2", true},
		{"0.0.0", "0.2.1", true},
		{"", "0.2.1", false},
		{"0.2.1", "x", false},
	} {
		if got := Older(c.v, c.than); got != c.want {
			t.Errorf("Older(%q, %q) = %v", c.v, c.than, got)
		}
	}
}

type fakeDownloader string

func (f fakeDownloader) Download(context.Context, string) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader(string(f))), nil
}

// A build is staged beside the installed one, checked by digest and by
// running it, swapped in keeping the previous build, and put back on request.
func TestStageSwapRestore(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "easyssl-agent")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\necho 0.2.1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	newBuild := "#!/bin/sh\necho 0.2.2\n"
	plan := Plan{Current: "0.2.1", Offered: "0.2.2", Needed: true, Artifact: catalog.Artifact{SHA256: digest(newBuild), URL: "/x"}}

	if _, err := Stage(context.Background(), fakeDownloader("tampered"), plan, binary); err == nil || !strings.Contains(err.Error(), "catalog published") {
		t.Fatalf("a download not matching the digest = %v", err)
	}
	wrong := "#!/bin/sh\necho 9.9.9\n"
	if _, err := Stage(context.Background(), fakeDownloader(wrong), Plan{Offered: "0.2.2", Artifact: catalog.Artifact{SHA256: digest(wrong)}}, binary); err == nil || !strings.Contains(err.Error(), "does not run") {
		t.Fatalf("a build reporting another version = %v", err)
	}
	if _, err := os.Stat(binary + ".new"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused build was left staged: %v", err)
	}

	staged, err := Stage(context.Background(), fakeDownloader(newBuild), plan, binary)
	if err != nil {
		t.Fatal(err)
	}
	if err := Swap(binary, staged); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(binary); string(b) != newBuild {
		t.Fatalf("installed = %q", b)
	}
	if b, _ := os.ReadFile(binary + ".prev"); !strings.Contains(string(b), "0.2.1") {
		t.Fatalf("previous = %q", b)
	}
	if err := Restore(binary); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(binary); !strings.Contains(string(b), "0.2.1") {
		t.Fatalf("restored = %q", b)
	}
}
