package serverapi

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/easyssl-io/easyssl-agent/internal/buildinfo"
	"github.com/easyssl-io/easyssl-contract/catalog"
	"github.com/easyssl-io/easyssl-contract/wire"
)

// The catalog and a Plugin artifact are read like every other Server call:
// with this build's versions, so the Server knows which contract a host
// installing a Plugin speaks.
func TestMarketplaceCarriesTheVersions(t *testing.T) {
	artifact := wire.APIPrefix + catalog.PluginArtifactPath("generic-cli", "linux", "amd64")
	var seen []string
	mux := http.NewServeMux()
	check := func(r *http.Request) {
		seen = append(seen, r.URL.Path)
		if got := r.Header.Get(wire.HeaderContractVersion); got != wire.ContractVersion {
			t.Errorf("%s: contract version %q, want %q", r.URL.Path, got, wire.ContractVersion)
		}
		if got := r.Header.Get("User-Agent"); got != wire.UserAgentPrefix+buildinfo.Version {
			t.Errorf("%s: User-Agent %q", r.URL.Path, got)
		}
	}
	mux.HandleFunc(wire.APIPrefix+catalog.RouteCatalog, func(w http.ResponseWriter, r *http.Request) {
		check(r)
		_, _ = w.Write([]byte(`{"plugins":[]}`))
	})
	mux.HandleFunc(artifact, func(w http.ResponseWriter, r *http.Request) {
		check(r)
		_, _ = w.Write([]byte("binary"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c, err := New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Catalog(context.Background()); err != nil {
		t.Fatalf("catalog: %v", err)
	}
	body, err := c.Download(context.Background(), artifact)
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	b, _ := io.ReadAll(body)
	body.Close()
	if string(b) != "binary" || len(seen) != 2 {
		t.Fatalf("body %q, requests %v", b, seen)
	}
}

// The catalog names artifacts by path on the Server: a URL naming any other
// origin is refused, and so is a redirect to one.
func TestDownloadStaysOnTheServer(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("someone else's code"))
	}))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/plugin", http.StatusFound)
	}))
	defer srv.Close()
	c, err := New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Download(context.Background(), "https://elsewhere.example/plugin"); err == nil {
		t.Fatal("a URL on another origin was followed")
	}
	if body, err := c.Download(context.Background(), "/api/v1/download/plugins/x/linux/amd64"); err == nil {
		b, _ := io.ReadAll(body)
		body.Close()
		if strings.Contains(string(b), "someone else") {
			t.Fatal("a redirect to another origin was followed")
		}
		t.Fatalf("a redirect to another origin answered %q, want a refusal", b)
	}
}
