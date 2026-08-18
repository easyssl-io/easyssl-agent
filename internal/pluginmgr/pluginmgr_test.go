package pluginmgr

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/easyssl-io/easyssl-contract/plugincontract"
	"github.com/easyssl-io/easyssl-contract/wire"
)

// The install-and-report boundary test: against a real HTTP server standing in
// for the Marketplace, installing a Plugin puts the artifact on disk, records
// what went there, and reports the version and declaration the Plugin gave for
// itself — not what the catalog claimed. Covers the refusals that must not
// leave a half-installed Plugin behind.

const artifactBody = "#!/bin/false\nplugin bytes\n"

type recordedReport struct {
	token    string
	pluginID string
	report   wire.PluginReport
}

type fakeReporter struct {
	got []recordedReport
	err error
}

func (f *fakeReporter) ReportPlugin(_ context.Context, token, pluginID string, rep wire.PluginReport) error {
	f.got = append(f.got, recordedReport{token, pluginID, rep})
	return f.err
}

// newMarketplace serves a catalog and one artifact, with the digest the caller
// wants published (empty means "publish the true one").
func newMarketplace(t *testing.T, publishDigest string) *httptest.Server {
	t.Helper()
	sum := sha256.Sum256([]byte(artifactBody))
	trueDigest := hex.EncodeToString(sum[:])
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/marketplace/catalog", func(w http.ResponseWriter, _ *http.Request) {
		digest := publishDigest
		if digest == "" {
			digest = trueDigest
		}
		_ = json.NewEncoder(w).Encode(CatalogResponse{Plugins: []CatalogPlugin{{
			ID: "generic-cli", Version: "9.9.9-catalog-says", Party: "first",
			Platforms: []string{"linux/amd64"},
			Artifacts: []CatalogArtifact{{
				OS: "linux", Arch: "amd64", Digest: digest,
				URL: srv.URL + "/download/plugins/generic-cli/linux/amd64",
			}},
		}}})
	})
	mux.HandleFunc("/download/plugins/generic-cli/linux/amd64", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(artifactBody))
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// newManager wires a Manager onto temp directories with a describe that answers
// without executing anything, so the test runs anywhere.
func newManager(t *testing.T, srv *httptest.Server, rep Reporter, desc plugincontract.DescribeResponse, descErr error) *Manager {
	t.Helper()
	dir := t.TempDir()
	return &Manager{
		catalog:    HTTPCatalog{BaseURL: srv.URL},
		reporter:   rep,
		installDir: filepath.Join(dir, "plugins"),
		recordPath: filepath.Join(dir, "plugins.json"),
		runDescribe: func(_ context.Context, _ string) (plugincontract.DescribeResponse, error) {
			return desc, descErr
		},
	}
}

func declaration() plugincontract.DescribeResponse {
	return plugincontract.DescribeResponse{
		ContractVersion: plugincontract.ContractVersion,
		Name:            "generic-cli",
		Version:         "0.1.0",
		Settings: []plugincontract.SettingDeclaration{{
			Key: "reload", Label: "Reload command", Type: plugincontract.SettingTypeCommand,
			Default: "echo hi", Required: true,
		}},
	}
}

func TestInstallRecordsAndReportsWhatThePluginSaid(t *testing.T) {
	srv := newMarketplace(t, "")
	rep := &fakeReporter{}
	m := newManager(t, srv, rep, declaration(), nil)

	inst, err := m.Install(context.Background(), "esat_token", "generic-cli", "linux", "amd64")
	if err != nil {
		t.Fatalf("install: %v", err)
	}

	sum := sha256.Sum256([]byte(artifactBody))
	wantDigest := hex.EncodeToString(sum[:])

	// The version recorded is the Plugin's own, from describe, not the
	// catalog's advisory one: what a host runs is what the host said it runs.
	if inst.Version != "0.1.0" {
		t.Fatalf("recorded version = %q, want the plugin's own 0.1.0 rather than the catalog's", inst.Version)
	}
	if inst.Digest != wantDigest {
		t.Fatalf("recorded digest = %q, want the hash of the bytes downloaded", inst.Digest)
	}

	// The artifact is on disk and executable.
	info, err := os.Stat(inst.Path)
	if err != nil {
		t.Fatalf("artifact not installed: %v", err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("artifact mode = %v, want 0755", info.Mode().Perm())
	}
	if body, _ := os.ReadFile(inst.Path); string(body) != artifactBody {
		t.Fatal("the installed file is not the bytes served")
	}
	// And no temporary download is left beside it.
	entries, _ := os.ReadDir(m.installDir)
	if len(entries) != 1 {
		t.Fatalf("install dir holds %d entries, want only the plugin", len(entries))
	}

	// Reported once, with the declaration verbatim.
	if len(rep.got) != 1 {
		t.Fatalf("reported %d times, want once", len(rep.got))
	}
	r := rep.got[0]
	if r.token != "esat_token" || r.pluginID != "generic-cli" {
		t.Fatalf("reported as %q/%q", r.token, r.pluginID)
	}
	if r.report.Version != "0.1.0" || r.report.Digest != wantDigest {
		t.Fatalf("report = %+v", r.report)
	}
	if len(r.report.Declarations) != 1 || r.report.Declarations[0].Key != "reload" {
		t.Fatalf("declarations = %+v, want the plugin's own", r.report.Declarations)
	}

	// And List reads it back.
	list, err := m.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != "generic-cli" || list[0].Version != "0.1.0" {
		t.Fatalf("list = %+v", list)
	}
}

// A re-install replaces the entry rather than adding a second: a host holds one
// version of each Plugin, which is what the Server stores too.
func TestReinstallReplacesTheRecord(t *testing.T) {
	srv := newMarketplace(t, "")
	rep := &fakeReporter{}
	m := newManager(t, srv, rep, declaration(), nil)
	if _, err := m.Install(context.Background(), "t", "generic-cli", "linux", "amd64"); err != nil {
		t.Fatal(err)
	}
	upgraded := declaration()
	upgraded.Version = "0.2.0"
	m.runDescribe = func(context.Context, string) (plugincontract.DescribeResponse, error) { return upgraded, nil }
	if _, err := m.Install(context.Background(), "t", "generic-cli", "linux", "amd64"); err != nil {
		t.Fatal(err)
	}
	list, _ := m.List()
	if len(list) != 1 || list[0].Version != "0.2.0" {
		t.Fatalf("list after upgrade = %+v, want one entry at 0.2.0", list)
	}
}

// A download that is not what the catalog published is refused, and nothing is
// left on disk or reported. Integrity rather than authentication: it catches a
// truncated, stale or wrong-architecture artifact.
func TestDigestMismatchInstallsNothing(t *testing.T) {
	srv := newMarketplace(t, strings.Repeat("a", 64))
	rep := &fakeReporter{}
	m := newManager(t, srv, rep, declaration(), nil)

	_, err := m.Install(context.Background(), "t", "generic-cli", "linux", "amd64")
	var mismatch DigestMismatchError
	if !asDigestMismatch(err, &mismatch) {
		t.Fatalf("install with a wrong published digest = %v, want a mismatch refusal", err)
	}
	assertNothingInstalled(t, m, rep)
}

// A Plugin that cannot describe itself is not installed: the Server would have
// no declaration to resolve settings against, so a Target of it could never be
// configured.
func TestDescribeFailureInstallsNothing(t *testing.T) {
	srv := newMarketplace(t, "")
	rep := &fakeReporter{}
	m := newManager(t, srv, rep, plugincontract.DescribeResponse{}, errBoom)

	if _, err := m.Install(context.Background(), "t", "generic-cli", "linux", "amd64"); err == nil {
		t.Fatal("install succeeded despite describe failing")
	}
	assertNothingInstalled(t, m, rep)
}

// An artifact that calls itself something else is refused: the name is identity
// on the Server, and settings are stored against it.
func TestWrongNameInstallsNothing(t *testing.T) {
	srv := newMarketplace(t, "")
	rep := &fakeReporter{}
	desc := declaration()
	desc.Name = "something-else"
	m := newManager(t, srv, rep, desc, nil)

	if _, err := m.Install(context.Background(), "t", "generic-cli", "linux", "amd64"); err == nil {
		t.Fatal("install succeeded despite the artifact naming itself differently")
	}
	assertNothingInstalled(t, m, rep)
}

// The catalog is the whole offer: a Plugin it does not list, and a platform it
// does not build for, are both refusals rather than a guessed URL.
func TestRefusesWhatTheCatalogDoesNotOffer(t *testing.T) {
	srv := newMarketplace(t, "")
	m := newManager(t, srv, &fakeReporter{}, declaration(), nil)

	if _, err := m.Install(context.Background(), "t", "nginx", "linux", "amd64"); err != ErrNotInCatalog {
		t.Fatalf("unknown plugin = %v, want ErrNotInCatalog", err)
	}
	if _, err := m.Install(context.Background(), "t", "generic-cli", "linux", "arm64"); err != ErrNoArtifact {
		t.Fatalf("unbuilt platform = %v, want ErrNoArtifact", err)
	}
	// And a name that could reach outside the install directory never becomes a
	// path at all.
	if _, err := m.Install(context.Background(), "t", "../../etc/passwd", "linux", "amd64"); err == nil {
		t.Fatal("a traversing plugin name was accepted")
	}
}

// Installed but unreported is reported as such: the host has the Plugin and the
// Server does not know, which is a different fact from nothing having happened.
func TestReportFailureStillReportsTheInstall(t *testing.T) {
	srv := newMarketplace(t, "")
	rep := &fakeReporter{err: errBoom}
	m := newManager(t, srv, rep, declaration(), nil)

	inst, err := m.Install(context.Background(), "t", "generic-cli", "linux", "amd64")
	if err == nil {
		t.Fatal("a failed report was not surfaced")
	}
	if inst.ID != "generic-cli" {
		t.Fatal("the installed plugin was not returned alongside the reporting error")
	}
	if !strings.Contains(err.Error(), "installed") {
		t.Fatalf("error does not say the plugin did land: %v", err)
	}
	if list, _ := m.List(); len(list) != 1 {
		t.Fatal("the installation was not recorded")
	}
}

func assertNothingInstalled(t *testing.T, m *Manager, rep *fakeReporter) {
	t.Helper()
	if entries, err := os.ReadDir(m.installDir); err == nil && len(entries) != 0 {
		t.Fatalf("install dir holds %d entries after a refusal, want none", len(entries))
	}
	if list, _ := m.List(); len(list) != 0 {
		t.Fatalf("recorded %d plugins after a refusal, want none", len(list))
	}
	if len(rep.got) != 0 {
		t.Fatalf("reported %d times after a refusal, want none", len(rep.got))
	}
}

var errBoom = errBoomType{}

type errBoomType struct{}

func (errBoomType) Error() string { return "boom" }

func asDigestMismatch(err error, out *DigestMismatchError) bool {
	m, ok := err.(DigestMismatchError)
	if ok {
		*out = m
	}
	return ok
}
