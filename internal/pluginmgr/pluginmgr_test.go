package pluginmgr

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/easyssl-io/easyssl-agent/internal/acmeclients"
	"github.com/easyssl-io/easyssl-agent/internal/serverapi"
	"github.com/easyssl-io/easyssl-contract/catalog"
	"github.com/easyssl-io/easyssl-contract/l10n"
	"github.com/easyssl-io/easyssl-contract/plugincontract"
	"github.com/easyssl-io/easyssl-contract/wire"
)

// The tests use a fake Marketplace and a fake describe and discover, so no
// Plugin binary is run: what is checked is what the Manager does around the
// executable.

const artifactBody = "#!/bin/false\nplugin bytes\n"

func trueDigest() string {
	sum := sha256.Sum256([]byte(artifactBody))
	return hex.EncodeToString(sum[:])
}

func newMarketplace(t *testing.T, publishDigest string) *httptest.Server {
	t.Helper()
	return newMarketplaceOf(t, publishDigest, catalog.PartyFirst)
}

func newMarketplaceOf(t *testing.T, publishDigest, party string) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc(wire.APIPrefix+catalog.RouteCatalog, func(w http.ResponseWriter, _ *http.Request) {
		digest := publishDigest
		switch digest {
		case "":
			digest = trueDigest()
		case "none":
			digest = ""
		}
		_ = json.NewEncoder(w).Encode(catalog.Response{Plugins: []catalog.Plugin{{
			ID: "generic-cli", Version: "9.9.9-catalog-says", Party: party,
			Artifacts: []catalog.Artifact{{
				OS: "linux", Arch: "amd64", SHA256: digest,
				URL: wire.APIPrefix + catalog.PluginArtifactPath("generic-cli", "linux", "amd64"),
			}},
		}}})
	})
	mux.HandleFunc(wire.APIPrefix+catalog.PluginArtifactPath("generic-cli", "linux", "amd64"), func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(artifactBody))
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func newManager(t *testing.T, srv *httptest.Server, desc plugincontract.DescribeResponse, descErr error) *Manager {
	t.Helper()
	m := New(nil, nil)
	if srv != nil {
		api, err := serverapi.New(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		m.catalog = api
	}
	m.installDir = filepath.Join(t.TempDir(), "plugins")
	// An empty host, so no test reads this machine's certbot directories.
	m.acme = acmeclients.Host{Root: t.TempDir()}
	m.runDescribe = func(_ context.Context, _ string) ([]byte, error) {
		if descErr != nil {
			return nil, descErr
		}
		return mustJSON(desc), nil
	}
	m.runDiscover = func(_ context.Context, _ string) ([]byte, error) {
		return mustJSON(found()), nil
	}
	return m
}

func answer() plugincontract.DescribeResponse {
	return plugincontract.DescribeResponse{
		ContractVersion: plugincontract.ContractVersion,
		Version:         "0.0.1",
		Description:     l10n.Text{"en": "Installs by running a command you write.", "es": "Instala ejecutando un comando que tú escribes."},
		Declarations: []plugincontract.SettingDeclaration{{
			Key: "install", Label: l10n.Text{"en": "Install command"}, Type: plugincontract.SettingTypeCommand,
			Default: "echo hi", Required: true,
		}},
	}
}

func found() plugincontract.DiscoverResponse {
	return plugincontract.DiscoverResponse{
		ContractVersion:   plugincontract.ContractVersion,
		DiscoveredTargets: []plugincontract.DiscoveredTarget{},
		Warnings:          []l10n.Text{{"en": "a warning", "es": "una advertencia"}},
	}
}

func TestInstallPlacesTheArtifactAndAnswersFromIt(t *testing.T) {
	m := newManager(t, newMarketplace(t, ""), answer(), nil)
	inst, err := m.Install(context.Background(), "generic-cli", "linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if inst.ID != "generic-cli" || inst.Version != "0.0.1" || inst.Digest != trueDigest() {
		t.Fatalf("installed = %+v", inst)
	}
	body, err := os.ReadFile(inst.Path)
	if err != nil || string(body) != artifactBody {
		t.Fatalf("artifact on disk = %q, %v", body, err)
	}
	// No record file anywhere under the install dir's parent: the executable
	// is the record.
	if entries, _ := os.ReadDir(filepath.Dir(m.installDir)); len(entries) != 1 {
		t.Fatalf("something besides the plugin directory was written: %v", entries)
	}
}

func TestListAndDiscoverReadTheDirectory(t *testing.T) {
	m := newManager(t, newMarketplace(t, ""), answer(), nil)
	if _, err := m.Install(context.Background(), "generic-cli", "linux", "amd64"); err != nil {
		t.Fatal(err)
	}
	// A stray file whose name is not a Plugin name is not a Plugin.
	if err := os.WriteFile(filepath.Join(m.installDir, "notes.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	installed, err := m.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(installed) != 1 || installed[0].ID != "generic-cli" || installed[0].Digest != trueDigest() {
		t.Fatalf("List = %+v", installed)
	}

	inv, err := m.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Both answers as the Plugin printed them, in one entry.
	if len(inv) != 1 || inv[0].Unobserved || inv[0].SHA256 != trueDigest() || len(inv[0].Warnings) != 0 ||
		string(inv[0].Describe) != string(mustJSON(answer())) || string(inv[0].Discover) != string(mustJSON(found())) {
		t.Fatalf("Discover = %+v", inv)
	}

	// Either operation failing leaves the Plugin present but unobserved, with
	// a warning in this Agent's own words that names the operation and the
	// failure. Whoever reads it on the Server may read any language, so it
	// carries every one of them.
	unobserved := func(t *testing.T, op string) {
		t.Helper()
		inv, err := m.Discover(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(inv) != 1 || !inv[0].Unobserved || inv[0].Describe != nil || inv[0].Discover != nil || len(inv[0].Warnings) != 1 {
			t.Fatalf("Discover after failure = %+v", inv)
		}
		warning := inv[0].Warnings[0]
		if err := warning.Validate(); err != nil {
			t.Fatalf("warning = %v: %v", warning, err)
		}
		for _, lang := range l10n.Supported() {
			if !strings.Contains(warning[lang], "`"+op+"`") {
				t.Errorf("warning in %s = %q, want it to name %s", lang, warning[lang], op)
			}
		}
		if warning["en"] == warning["es"] {
			t.Errorf("warning reads %q in both languages", warning["en"])
		}
	}
	restore := func() {
		m.runDescribe = func(context.Context, string) ([]byte, error) { return mustJSON(answer()), nil }
		m.runDiscover = func(context.Context, string) ([]byte, error) { return mustJSON(found()), nil }
	}

	t.Run("a Plugin that fails describe is present but unobserved", func(t *testing.T) {
		defer restore()
		m.runDescribe = func(context.Context, string) ([]byte, error) {
			return nil, errors.New("exit status 1")
		}
		unobserved(t, plugincontract.OpDescribe)
	})

	t.Run("a Plugin that fails discover is present but unobserved", func(t *testing.T) {
		defer restore()
		m.runDiscover = func(context.Context, string) ([]byte, error) {
			return nil, errors.New("exit status 1")
		}
		unobserved(t, plugincontract.OpDiscover)
	})

	// A field this Agent does not know reaches the Server, since the answer is
	// forwarded as printed, not re-encoded through the Agent's own structs.
	t.Run("an answer is forwarded with fields this Agent does not know", func(t *testing.T) {
		defer restore()
		withNew := []byte(`{"contractVersion":"` + plugincontract.ContractVersion + `","discoveredTargets":[],"warnings":[],"aFieldFromTheFuture":{"x":1}}`)
		m.runDiscover = func(context.Context, string) ([]byte, error) { return withNew, nil }
		inv, err := m.Discover(context.Background())
		if err != nil || len(inv) != 1 || inv[0].Unobserved || string(inv[0].Discover) != string(withNew) {
			t.Fatalf("Discover = %+v, %v; want the answer as printed", inv, err)
		}
	})

	// A Plugin built against another breaking version is refused by name.
	t.Run("a Plugin built against another breaking contract version is unobserved", func(t *testing.T) {
		defer restore()
		m.runDescribe = func(context.Context, string) ([]byte, error) {
			d := answer()
			d.ContractVersion = "99.0.0"
			return mustJSON(d), nil
		}
		unobserved(t, plugincontract.OpDescribe)
	})

	// A finding that names a setting the same build never declared is checked
	// against describe's declarations.
	t.Run("a discover answer that does not fit describe's declarations is unobserved", func(t *testing.T) {
		defer restore()
		m.runDiscover = func(context.Context, string) ([]byte, error) {
			d := found()
			d.DiscoveredTargets = []plugincontract.DiscoveredTarget{{Settings: map[string]string{"bogus": "x"}}}
			return mustJSON(d), nil
		}
		unobserved(t, plugincontract.OpDiscover)
	})

	// The two answers come from two processes; a binary replaced between them
	// would mix one build's declarations with another's findings.
	t.Run("an executable that changes between describe and discover is unobserved", func(t *testing.T) {
		path := filepath.Join(m.installDir, "generic-cli")
		defer func() {
			restore()
			_ = os.WriteFile(path, []byte(artifactBody), 0o755)
		}()
		m.runDiscover = func(context.Context, string) ([]byte, error) {
			if err := os.WriteFile(path, []byte("#!/bin/false\nanother build\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			return mustJSON(found()), nil
		}
		unobserved(t, plugincontract.OpDiscover)
	})

	t.Run("Find reports the executable and the version it answers", func(t *testing.T) {
		m.runDescribe = func(context.Context, string) ([]byte, error) { return mustJSON(answer()), nil }
		inst, found, err := m.Find("generic-cli")
		if err != nil || !found || inst.Version != "0.0.1" || inst.Path != filepath.Join(m.installDir, "generic-cli") {
			t.Fatalf("Find = %+v %v %v", inst, found, err)
		}
		if _, found, _ := m.Find("nginx"); found {
			t.Fatal("found a Plugin that is not there")
		}
	})
}

func TestReinstallReplacesTheExecutable(t *testing.T) {
	m := newManager(t, newMarketplace(t, ""), answer(), nil)
	if _, err := m.Install(context.Background(), "generic-cli", "linux", "amd64"); err != nil {
		t.Fatal(err)
	}
	upgraded := answer()
	upgraded.Version = "0.0.2"
	m.runDescribe = func(context.Context, string) ([]byte, error) { return mustJSON(upgraded), nil }
	inst, err := m.Install(context.Background(), "generic-cli", "linux", "amd64")
	if err != nil || inst.Version != "0.0.2" {
		t.Fatalf("reinstall = %+v, %v", inst, err)
	}
	if installed, _ := m.List(); len(installed) != 1 {
		t.Fatalf("List after reinstall = %+v, want one", installed)
	}
}

func TestDigestMismatchInstallsNothing(t *testing.T) {
	m := newManager(t, newMarketplace(t, strings.Repeat("0", 64)), answer(), nil)
	_, err := m.Install(context.Background(), "generic-cli", "linux", "amd64")
	var mismatch DigestMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("err = %v, want DigestMismatchError", err)
	}
	if installed, _ := m.List(); len(installed) != 0 {
		t.Fatalf("something was installed: %+v", installed)
	}
}

func TestDescribeFailureInstallsNothing(t *testing.T) {
	m := newManager(t, newMarketplace(t, ""), plugincontract.DescribeResponse{}, errors.New("exit status 2"))
	if _, err := m.Install(context.Background(), "generic-cli", "linux", "amd64"); err == nil {
		t.Fatal("installed a Plugin that did not answer describe")
	}
	if installed, _ := m.List(); len(installed) != 0 {
		t.Fatalf("something was installed: %+v", installed)
	}
}

func TestRefusesWhatTheCatalogDoesNotOffer(t *testing.T) {
	m := newManager(t, newMarketplace(t, ""), answer(), nil)
	if _, err := m.Install(context.Background(), "nginx", "linux", "amd64"); !errors.Is(err, ErrNotInCatalog) {
		t.Fatalf("err = %v, want ErrNotInCatalog", err)
	}
	if _, err := m.Install(context.Background(), "generic-cli", "plan9", "mips"); !errors.Is(err, ErrNoArtifact) {
		t.Fatalf("err = %v, want ErrNoArtifact", err)
	}
	if _, err := m.Install(context.Background(), "../etc", "linux", "amd64"); err == nil {
		t.Fatal("a name that is a path was accepted")
	}
}

func TestInstallRefusesAnUnusableAnswer(t *testing.T) {
	d := answer()
	d.Declarations = append(d.Declarations,
		plugincontract.SettingDeclaration{Key: "a", Type: plugincontract.SettingTypeText, Label: l10n.Text{"en": "A"}, Summary: true},
		plugincontract.SettingDeclaration{Key: "b", Type: plugincontract.SettingTypeText, Label: l10n.Text{"en": "B"}, Summary: true})
	m := newManager(t, newMarketplace(t, ""), d, nil)
	if _, err := m.Install(context.Background(), "generic-cli", "linux", "amd64"); err == nil {
		t.Fatal("two summary settings were accepted")
	}
	if installed, _ := m.List(); len(installed) != 0 {
		t.Fatalf("something was installed: %+v", installed)
	}
}

// A Plugin whose answer runs past the output bound is refused rather than read
// whole into memory.
func TestRunByExecRefusesAnOversizedAnswer(t *testing.T) {
	script := filepath.Join(t.TempDir(), "flood")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nhead -c 600000 /dev/zero | tr '\\\\0' x\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := runByExec(context.Background(), script, plugincontract.OpDiscover, slog.New(slog.DiscardHandler)); err == nil ||
		!strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err = %v, want the answer refused as too large", err)
	}
}

// A failed upgrade leaves the build that was working: the download is checked
// beside it and replaces it only once every check passes.
func TestAFailedUpgradeKeepsTheInstalledPlugin(t *testing.T) {
	m := newManager(t, newMarketplace(t, strings.Repeat("0", 64)), answer(), nil)
	if err := os.MkdirAll(m.installDir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(m.installDir, "generic-cli")
	if err := os.WriteFile(path, []byte("working build"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Install(context.Background(), "generic-cli", "linux", "amd64"); err == nil {
		t.Fatal("an upgrade whose digest does not match was installed")
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "working build" {
		t.Fatalf("the installed Plugin is now %q (%v), want the working build kept", got, err)
	}
	if installed, _ := m.List(); len(installed) != 1 {
		t.Fatalf("List = %+v, want only the working build, no temporary file", installed)
	}
}

// A catalog entry without a digest would skip the only check, so it is refused.
func TestAMissingDigestInstallsNothing(t *testing.T) {
	m := newManager(t, newMarketplace(t, "none"), answer(), nil)
	if _, err := m.Install(context.Background(), "generic-cli", "linux", "amd64"); err == nil {
		t.Fatal("installed a Plugin the catalog published no digest for")
	}
	if entries, _ := os.ReadDir(m.installDir); len(entries) != 0 {
		t.Fatalf("left %d files behind", len(entries))
	}
}

// At deploy time the describe answer passes the same checks an inventory
// applies, so a Deployment never records a version from an answer that failed
// them.
func TestFindAppliesTheDescribeChecks(t *testing.T) {
	d := answer()
	d.Version = ""
	m := newManager(t, nil, d, nil)
	if err := os.MkdirAll(m.installDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(m.installDir, "generic-cli"), []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, found, err := m.Find("generic-cli"); !found || err == nil {
		t.Fatalf("Find = found %v, err %v; want found with an error", found, err)
	}
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// A third-party Plugin would need a signature this Agent cannot check, so a
// catalog entry naming one installs nothing.
func TestAThirdPartyPluginInstallsNothing(t *testing.T) {
	m := newManager(t, newMarketplaceOf(t, "", "third"), answer(), nil)
	if _, err := m.Install(context.Background(), "generic-cli", "linux", "amd64"); err == nil {
		t.Fatal("a third-party Plugin was installed")
	}
	if entries, _ := os.ReadDir(m.installDir); len(entries) != 0 {
		t.Fatalf("left %d files behind", len(entries))
	}
}

// fileAnswer is a describe answer declaring two path settings, the way a
// Plugin that writes files does.
func fileAnswer() plugincontract.DescribeResponse {
	return plugincontract.DescribeResponse{
		ContractVersion: plugincontract.ContractVersion,
		Version:         "0.0.2",
		Declarations: []plugincontract.SettingDeclaration{
			{Key: "cert", Label: l10n.Text{"en": "Certificate"}, Type: plugincontract.SettingTypePath, Required: true, Identity: true},
			{Key: "key", Label: l10n.Text{"en": "Key"}, Type: plugincontract.SettingTypePath, Required: true},
		},
	}
}

func TestDiscoverMarksTargetsOnManagedPaths(t *testing.T) {
	m := newManager(t, newMarketplace(t, ""), fileAnswer(), nil)
	if _, err := m.Install(context.Background(), "generic-cli", "linux", "amd64"); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(m.acme.Root, "etc/letsencrypt/live/example.com"), 0o755); err != nil {
		t.Fatal(err)
	}
	// As a Plugin prints it, with fields this build does not know at both
	// levels, one Target in certbot's directory and one outside every client's,
	// and the in-certbot one from a Plugin too old to send warnings.
	raw := `{"contractVersion":"0.1.1","future":{"x":1},"warnings":[],"discoveredTargets":[` +
		`{"settings":{"cert":"/etc/letsencrypt/live/example.com/fullchain.pem","key":"/etc/letsencrypt/live/example.com/privkey.pem"},"extraData":[],"references":[],"newField":"kept"},` +
		`{"settings":{"cert":"/etc/ssl/a.pem","key":"/etc/ssl/a.key"},"extraData":[],"references":[],"warnings":[{"en":"a Plugin warning"}]}]}`
	m.runDiscover = func(context.Context, string) ([]byte, error) { return []byte(raw), nil }

	got, err := m.Discover(context.Background())
	if err != nil || len(got) != 1 || got[0].Unobserved {
		t.Fatalf("discover = %+v, %v", got, err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(got[0].Discover, &top); err != nil {
		t.Fatal(err)
	}
	if string(top["future"]) != `{"x":1}` {
		t.Fatalf("an unknown top-level field was lost: %s", got[0].Discover)
	}
	var disc struct {
		DiscoveredTargets []struct {
			NewField string      `json:"newField"`
			Warnings []l10n.Text `json:"warnings"`
		} `json:"discoveredTargets"`
	}
	if err := json.Unmarshal(got[0].Discover, &disc); err != nil {
		t.Fatal(err)
	}
	ts := disc.DiscoveredTargets
	if len(ts) != 2 || ts[0].NewField != "kept" || len(ts[0].Warnings) != 1 {
		t.Fatalf("targets = %+v", ts)
	}
	if w := ts[0].Warnings[0]; !strings.Contains(w["en"], "certbot's directory `/etc/letsencrypt`") || w["es"] == "" {
		t.Fatalf("warning = %v", w)
	}
	// The other Target keeps exactly the Plugin's own warning.
	if len(ts[1].Warnings) != 1 || ts[1].Warnings[0]["en"] != "a Plugin warning" {
		t.Fatalf("unmanaged Target's warnings = %+v", ts[1].Warnings)
	}
}

func TestMarkManagedLeavesAnUnmanagedAnswerAsPrinted(t *testing.T) {
	raw := []byte(`{"contractVersion":"0.1.1",  "discoveredTargets":[]}`)
	got, err := MarkManaged(fileAnswer(), raw, [][]acmeclients.Finding{})
	if err != nil || string(got) != string(raw) {
		t.Fatalf("marked = %s, %v", got, err)
	}
}
