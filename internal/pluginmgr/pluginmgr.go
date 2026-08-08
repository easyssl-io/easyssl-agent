// Package pluginmgr installs Plugins on this host and tells the Server what is
// installed. Nothing is bundled into the Client binary: a Plugin is fetched
// from the Server's Marketplace on demand, placed under InstallDir, asked to
// describe itself, and reported.
//
// The report is what makes a Plugin configurable from the web console without
// anything ever querying this host: the Server keeps the declaration and
// resolves every value from it, so a Plugin nobody published is as configurable
// as one that was.
package pluginmgr

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/easyssl-io/easyssl-contract/plugincontract"
	"github.com/easyssl-io/easyssl-contract/wire"
)

// InstallDir is where Plugin executables live on the host, and RecordPath is
// the Client's own record of what it put there. Both are root-owned: a Plugin
// is executed by the Client, which runs as root, so anything that could write
// here could run code as root.
const (
	InstallDir = "/var/lib/easyssl/plugins"
	RecordPath = "/etc/easyssl/plugins.json"
)

// maxArtifact bounds a download. A plugin is a static Go binary of a few
// megabytes; this is generous while refusing to write an unbounded stream to
// the host's disk.
const maxArtifact = 128 << 20

// describeTimeout bounds the one call made at install time. `describe` reads
// nothing and computes nothing, so a Plugin that has not answered in this long
// is not going to.
const describeTimeout = 30 * time.Second

// validPluginID is the Plugin naming rule, matching what the Server accepts on
// the report route. It is checked before the name reaches a file path, so a
// catalog entry cannot name a file outside InstallDir.
var validPluginID = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$`)

// Installed is one Plugin this host has, as recorded by the Client.
type Installed struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	// Digest is the SHA-256 of the artifact as downloaded, recorded from the
	// catalog entry it came from and verified against the bytes received.
	Digest      string    `json:"digest"`
	InstalledAt time.Time `json:"installedAt"`
	Path        string    `json:"path"`
}

// Record is the Client's list of installed Plugins.
type Record struct {
	Plugins []Installed `json:"plugins"`
}

// Reporter is the Server call this package makes: what was installed, with the
// declaration the Plugin gave for itself.
type Reporter interface {
	ReportPlugin(ctx context.Context, token, pluginID string, rep wire.PluginReport) error
}

// Catalog is the Marketplace read. Separate from Reporter because the catalog
// needs no token: it is the same bytes for everyone.
type Catalog interface {
	Fetch(ctx context.Context) (CatalogResponse, error)
	Download(ctx context.Context, url string) (io.ReadCloser, error)
}

// Manager installs and lists Plugins.
type Manager struct {
	catalog  Catalog
	reporter Reporter
	// installDir and recordPath are fields rather than the constants directly
	// so a test can work somewhere it may write.
	installDir string
	recordPath string
	// runDescribe executes a Plugin's describe operation. A field so a test can
	// exercise the flow without a real binary; production runs the executable.
	runDescribe func(ctx context.Context, path string) (plugincontract.DescribeResponse, error)
}

// New builds a Manager writing to the host's real locations.
func New(catalog Catalog, reporter Reporter) *Manager {
	return &Manager{
		catalog: catalog, reporter: reporter,
		installDir: InstallDir, recordPath: RecordPath,
		runDescribe: describeByExec,
	}
}

// ErrNotInCatalog: the Server's Marketplace does not offer this Plugin.
var ErrNotInCatalog = errors.New("pluginmgr: the Server's Marketplace does not offer this plugin")

// ErrNoArtifact: the Plugin is offered but not for this host's platform.
var ErrNoArtifact = errors.New("pluginmgr: no build of this plugin for this platform")

// DigestMismatchError reports an artifact whose bytes are not what the catalog
// said they would be.
type DigestMismatchError struct {
	PluginID string
	Want     string
	Got      string
}

func (e DigestMismatchError) Error() string {
	return fmt.Sprintf("pluginmgr: %s downloaded as %s but the catalog published %s", e.PluginID, e.Got, e.Want)
}

// Install fetches a Plugin, places it, asks it to describe itself, records what
// went in, and reports it to the Server.
//
// The order matters. `describe` runs against the file that was actually
// installed rather than against the catalog, so the version reported is the one
// the host will run; and the report is last, so the Server never learns of a
// Plugin that failed to land.
func (m *Manager) Install(ctx context.Context, token, pluginID, goos, goarch string) (Installed, error) {
	if !validPluginID.MatchString(pluginID) {
		return Installed{}, fmt.Errorf("pluginmgr: %q is not a valid plugin name", pluginID)
	}
	cat, err := m.catalog.Fetch(ctx)
	if err != nil {
		return Installed{}, fmt.Errorf("reading the Marketplace catalog: %w", err)
	}
	entry, ok := cat.find(pluginID)
	if !ok {
		return Installed{}, ErrNotInCatalog
	}
	artifact, ok := entry.artifact(goos, goarch)
	if !ok {
		return Installed{}, ErrNoArtifact
	}

	path := filepath.Join(m.installDir, pluginID)
	digest, err := m.fetchTo(ctx, artifact.URL, path)
	if err != nil {
		return Installed{}, err
	}
	// The catalog said which bytes these would be, so a mismatch means the
	// download was not what was offered. Refuse rather than install it: this is
	// integrity, not authentication — it catches a truncated, stale or
	// wrong-architecture artifact, and it is the plumbing FR-008's verification
	// slice will build on.
	if artifact.Digest != "" && digest != artifact.Digest {
		_ = os.Remove(path)
		return Installed{}, DigestMismatchError{PluginID: pluginID, Want: artifact.Digest, Got: digest}
	}

	dctx, cancel := context.WithTimeout(ctx, describeTimeout)
	defer cancel()
	desc, err := m.runDescribe(dctx, path)
	if err != nil {
		_ = os.Remove(path)
		return Installed{}, fmt.Errorf("the plugin did not describe itself, so it was not installed: %w", err)
	}
	if desc.Name != "" && desc.Name != pluginID {
		_ = os.Remove(path)
		return Installed{}, fmt.Errorf("pluginmgr: the artifact for %q calls itself %q", pluginID, desc.Name)
	}

	inst := Installed{
		ID: pluginID, Version: desc.Version, Digest: digest,
		InstalledAt: time.Now().UTC(), Path: path,
	}
	if err := m.record(inst); err != nil {
		return Installed{}, fmt.Errorf("recording the installation: %w", err)
	}
	if err := m.reporter.ReportPlugin(ctx, token, pluginID, wire.PluginReport{
		Version:      desc.Version,
		Digest:       digest,
		Declarations: desc.Settings,
	}); err != nil {
		// Installed but unreported: the host has the Plugin and the Server does
		// not know, which the next install or check-in can correct. Say so
		// rather than implying nothing happened.
		return inst, fmt.Errorf("installed, but reporting it to the Server failed: %w", err)
	}
	return inst, nil
}

// List reads what this host recorded as installed. It reports what the Client
// put there, not what is on disk: a file someone dropped into the install
// directory by hand was never installed by anything and is not a Plugin this
// Client will run.
func (m *Manager) List() ([]Installed, error) {
	rec, err := m.load()
	if err != nil {
		return nil, err
	}
	sort.Slice(rec.Plugins, func(i, j int) bool { return rec.Plugins[i].ID < rec.Plugins[j].ID })
	return rec.Plugins, nil
}

// fetchTo downloads url to path (0755, root-owned by virtue of the Client
// running as root) and returns the SHA-256 of what was written. It writes to a
// temporary file in the same directory and renames, so a failed download never
// half-replaces a working Plugin and an upgrade of a Plugin currently running
// cannot hit ETXTBSY.
func (m *Manager) fetchTo(ctx context.Context, url, path string) (string, error) {
	if err := os.MkdirAll(m.installDir, 0o755); err != nil {
		return "", err
	}
	body, err := m.catalog.Download(ctx, url)
	if err != nil {
		return "", fmt.Errorf("downloading the plugin: %w", err)
	}
	defer body.Close()

	tmp, err := os.CreateTemp(m.installDir, ".download-*")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	defer func() {
		tmp.Close()
		_ = os.Remove(tmpName) // no-op once renamed
	}()

	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(body, maxArtifact)); err != nil {
		return "", fmt.Errorf("writing the plugin to disk: %w", err)
	}
	if err := tmp.Chmod(0o755); err != nil {
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// record adds or replaces this Plugin's entry. One entry per Plugin: a new
// version replaces the row rather than adding a second, matching what the
// Server stores.
func (m *Manager) record(inst Installed) error {
	rec, err := m.load()
	if err != nil {
		return err
	}
	replaced := false
	for i := range rec.Plugins {
		if rec.Plugins[i].ID == inst.ID {
			rec.Plugins[i] = inst
			replaced = true
			break
		}
	}
	if !replaced {
		rec.Plugins = append(rec.Plugins, inst)
	}
	if err := os.MkdirAll(filepath.Dir(m.recordPath), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.recordPath, append(data, '\n'), 0o600)
}

// load reads the record, treating an absent file as an empty one: a host that
// has installed nothing is not an error.
func (m *Manager) load() (Record, error) {
	var rec Record
	data, err := os.ReadFile(m.recordPath)
	if errors.Is(err, os.ErrNotExist) {
		return rec, nil
	}
	if err != nil {
		return rec, err
	}
	if err := json.Unmarshal(data, &rec); err != nil {
		return rec, fmt.Errorf("%s is not readable as a plugin record: %w", m.recordPath, err)
	}
	return rec, nil
}

// describeByExec runs the Plugin's describe operation the way every operation
// runs: the name on argv, JSON on stdout. Nothing is written to its stdin,
// describe taking no request.
func describeByExec(ctx context.Context, path string) (plugincontract.DescribeResponse, error) {
	var out plugincontract.DescribeResponse
	// #nosec G204 -- path is InstallDir joined with a name matched against
	// validPluginID, so it names a file this Client just wrote.
	cmd := exec.CommandContext(ctx, path, plugincontract.OpDescribe)
	stdout, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
			return out, fmt.Errorf("%w: %s", err, exitErr.Stderr)
		}
		return out, err
	}
	if err := json.Unmarshal(stdout, &out); err != nil {
		return out, fmt.Errorf("the plugin's describe output is not JSON: %w", err)
	}
	return out, nil
}

// --- catalog shapes ---------------------------------------------------------

// CatalogArtifact and CatalogPlugin mirror what the Server publishes
// (contracts/server-api.md). They live here rather than in the wire package
// because the Marketplace is a Server-to-anyone surface rather than part of the
// Client↔Server protocol: a browser reads the same JSON.
type CatalogArtifact struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	Digest string `json:"digest"`
	URL    string `json:"url"`
}

type CatalogPlugin struct {
	ID          string            `json:"id"`
	Version     string            `json:"version"`
	Description string            `json:"description"`
	Party       string            `json:"party"`
	Publisher   string            `json:"publisher"`
	SourceURL   string            `json:"sourceUrl"`
	Platforms   []string          `json:"platforms"`
	Artifacts   []CatalogArtifact `json:"artifacts"`
}

type CatalogResponse struct {
	Plugins []CatalogPlugin `json:"plugins"`
}

func (c CatalogResponse) find(id string) (CatalogPlugin, bool) {
	for _, p := range c.Plugins {
		if p.ID == id {
			return p, true
		}
	}
	return CatalogPlugin{}, false
}

func (p CatalogPlugin) artifact(goos, goarch string) (CatalogArtifact, bool) {
	for _, a := range p.Artifacts {
		if a.OS == goos && a.Arch == goarch {
			return a, true
		}
	}
	return CatalogArtifact{}, false
}

// HTTPCatalog reads the Marketplace over HTTP. No token: the catalog and the
// artifacts are public.
type HTTPCatalog struct {
	BaseURL string
	HTTP    *http.Client
}

func (c HTTPCatalog) client() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

func (c HTTPCatalog) Fetch(ctx context.Context) (CatalogResponse, error) {
	var out CatalogResponse
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/marketplace/catalog", nil)
	if err != nil {
		return out, err
	}
	res, err := c.client().Do(req)
	if err != nil {
		return out, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return out, fmt.Errorf("the Server answered %s for the catalog", res.Status)
	}
	return out, json.NewDecoder(res.Body).Decode(&out)
}

func (c HTTPCatalog) Download(ctx context.Context, url string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	res, err := c.client().Do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		res.Body.Close()
		return nil, fmt.Errorf("the Server answered %s for the artifact", res.Status)
	}
	return res.Body, nil
}

// Find returns the installed Plugin with this id, or false. It reads the
// Client's own record rather than the directory: a file someone dropped into
// the install directory by hand was never installed by anything, and running it
// because the name matched is how a host ends up executing something nobody
// fetched.
func (m *Manager) Find(id string) (Installed, bool, error) {
	rec, err := m.load()
	if err != nil {
		return Installed{}, false, err
	}
	for _, p := range rec.Plugins {
		if p.ID == id {
			return p, true, nil
		}
	}
	return Installed{}, false, nil
}
