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

	"github.com/easyssl-io/easyssl-contract/l10n"
	"github.com/easyssl-io/easyssl-contract/plugincontract"
)

// The tests exercise the flow against a fake Marketplace and a fake discover,
// so no Plugin binary is run: what is checked is what the Manager does around
// the executable, which is what it owns.

const artifactBody = "#!/bin/false\nplugin bytes\n"

func trueDigest() string {
	sum := sha256.Sum256([]byte(artifactBody))
	return hex.EncodeToString(sum[:])
}

func newMarketplace(t *testing.T, publishDigest string) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/marketplace/catalog", func(w http.ResponseWriter, _ *http.Request) {
		digest := publishDigest
		if digest == "" {
			digest = trueDigest()
		}
		_ = json.NewEncoder(w).Encode(CatalogResponse{Plugins: []CatalogPlugin{{
			ID: "generic-cli", Version: "9.9.9-catalog-says", Party: "first",
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

func newManager(t *testing.T, srv *httptest.Server, desc plugincontract.DiscoverResponse, descErr error) *Manager {
	t.Helper()
	m := New(nil, nil)
	if srv != nil {
		m.catalog = HTTPCatalog{BaseURL: srv.URL}
	}
	m.installDir = filepath.Join(t.TempDir(), "plugins")
	m.runDiscover = func(_ context.Context, _ string) (plugincontract.DiscoverResponse, error) {
		return desc, descErr
	}
	return m
}

func answer() plugincontract.DiscoverResponse {
	return plugincontract.DiscoverResponse{
		ContractVersion: plugincontract.ContractVersion,
		Name:            "generic-cli",
		Version:         "0.0.1",
		Description:     l10n.Text{"en": "Installs by running a command you write.", "es": "Instala ejecutando un comando que tú escribes."},
		Settings: []plugincontract.SettingDeclaration{{
			Key: "install", Label: l10n.Text{"en": "Install command"}, Type: plugincontract.SettingTypeCommand,
			Default: "echo hi", Required: true,
		}},
		DiscoveredTargets: []plugincontract.DiscoveredTarget{},
		Warnings:          []l10n.Text{},
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
	if len(inv) != 1 || inv[0].Unobserved || inv[0].Version != "0.0.1" || len(inv[0].Declarations) != 1 || inv[0].Digest != trueDigest() {
		t.Fatalf("Discover = %+v", inv)
	}

	t.Run("a Plugin that fails discover is present but unobserved", func(t *testing.T) {
		m.runDiscover = func(context.Context, string) (plugincontract.DiscoverResponse, error) {
			return plugincontract.DiscoverResponse{}, errors.New("exit status 1")
		}
		inv, err := m.Discover(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(inv) != 1 || !inv[0].Unobserved || inv[0].Version != "" || len(inv[0].Warnings) != 1 {
			t.Fatalf("Discover after failure = %+v", inv)
		}
		// The warning is this Agent's own text, and whoever reads it on the
		// Server may read any language, so it carries every one of them.
		warning := inv[0].Warnings[0]
		if err := warning.Validate(); err != nil {
			t.Fatalf("warning = %v: %v", warning, err)
		}
		for _, lang := range l10n.Supported() {
			if !strings.Contains(warning[lang], "exit status 1") {
				t.Errorf("warning in %s = %q, want it to name the failure", lang, warning[lang])
			}
		}
		if warning["en"] == warning["es"] {
			t.Errorf("warning reads %q in both languages", warning["en"])
		}
	})

	t.Run("Find reports the executable and the version it answers", func(t *testing.T) {
		m.runDiscover = func(context.Context, string) (plugincontract.DiscoverResponse, error) { return answer(), nil }
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
	m.runDiscover = func(context.Context, string) (plugincontract.DiscoverResponse, error) { return upgraded, nil }
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

func TestDiscoverFailureInstallsNothing(t *testing.T) {
	m := newManager(t, newMarketplace(t, ""), plugincontract.DiscoverResponse{}, errors.New("exit status 2"))
	if _, err := m.Install(context.Background(), "generic-cli", "linux", "amd64"); err == nil {
		t.Fatal("installed a Plugin that did not answer discover")
	}
	if installed, _ := m.List(); len(installed) != 0 {
		t.Fatalf("something was installed: %+v", installed)
	}
}

func TestWrongNameInstallsNothing(t *testing.T) {
	d := answer()
	d.Name = "something-else"
	m := newManager(t, newMarketplace(t, ""), d, nil)
	if _, err := m.Install(context.Background(), "generic-cli", "linux", "amd64"); err == nil {
		t.Fatal("installed an artifact that calls itself another Plugin")
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
	d.Settings = append(d.Settings, plugincontract.SettingDeclaration{Key: "a", Summary: true}, plugincontract.SettingDeclaration{Key: "b", Summary: true})
	m := newManager(t, newMarketplace(t, ""), d, nil)
	if _, err := m.Install(context.Background(), "generic-cli", "linux", "amd64"); err == nil {
		t.Fatal("two summary settings were accepted")
	}
	if installed, _ := m.List(); len(installed) != 0 {
		t.Fatalf("something was installed: %+v", installed)
	}
}

// A Plugin whose discover answer runs past the output bound is refused rather
// than read whole into memory.
func TestDiscoverRefusesAnOversizedAnswer(t *testing.T) {
	script := filepath.Join(t.TempDir(), "flood")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nhead -c 600000 /dev/zero | tr '\\\\0' x\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := discoverByExec(context.Background(), script, slog.New(slog.DiscardHandler)); err == nil ||
		!strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err = %v, want the answer refused as too large", err)
	}
}
