// Package pluginmgr installs Plugins on this host and asks each what it is and
// what it sees. Nothing is bundled into the Agent binary: a Plugin is fetched
// from the Server's Marketplace on demand and placed under InstallDir, and
// that directory is the whole record of what is installed. Everything else
// about a Plugin, its version, its declarations and the installation points it
// found, is what the executable answers to discover, asked afresh on every
// check-in and carried to the Server in the host inventory; the Agent keeps
// no copy, because a copy is what goes stale and is then reported as fact.
package pluginmgr

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/easyssl-io/easyssl-agent/internal/plugintrace"
	"github.com/easyssl-io/easyssl-contract/plugincontract"
	"github.com/easyssl-io/easyssl-contract/wire"
)

// InstallDir is where Plugin executables live on the host. Root-owned: a
// Plugin is executed by the Agent, which runs as root, so anything that could
// write here could run code as root.
const InstallDir = "/var/lib/easyssl/plugins"

// maxArtifact bounds a download. A plugin is a static Go binary of a few
// megabytes; this is generous while refusing to write an unbounded stream to
// the host's disk.
const maxArtifact = 128 << 20

// discoverTimeout bounds one discover execution. It runs on every check-in and
// must be shorter than the check-in interval, or a hung Plugin (an `nginx -t`
// stuck on a broken host) would delay the check-in it rides on and the Agent
// would go Offline for a reason nothing names. A Plugin that exceeds it is
// reported as present but unobserved this run.
const discoverTimeout = 10 * time.Second

// validPluginID is the Plugin naming rule, matching what the Server accepts on
// the report route. It is checked before the name reaches a file path, so a
// catalog entry cannot name a file outside InstallDir.
var validPluginID = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$`)

// Installed is one Plugin executable on this host, as it is now.
type Installed struct {
	ID string `json:"id"`
	// Version is what the executable answered to discover, empty when it did
	// not answer.
	Version string `json:"version,omitempty"`
	// Digest is the SHA-256 of the executable as it is on disk now.
	Digest string `json:"digest"`
	Path   string `json:"path"`
}

// Catalog is the Marketplace read. Separate from Reporter because the catalog
// needs no token: it is the same bytes for everyone.
type Catalog interface {
	Fetch(ctx context.Context) (CatalogResponse, error)
	Download(ctx context.Context, url string) (io.ReadCloser, error)
}

// Manager installs, lists and discovers Plugins.
type Manager struct {
	catalog Catalog
	// installDir is a field rather than the constant so a test can work
	// somewhere it may write.
	installDir string
	logger     *slog.Logger
	// runDiscover executes a Plugin's discover operation. A field so a test
	// can exercise the flow without a real binary; production runs the
	// executable.
	runDiscover func(ctx context.Context, path string) (plugincontract.DiscoverResponse, error)
}

// New builds a Manager over the host's real Plugin directory. catalog may be
// nil for a caller that only lists or discovers; logger may be nil.
func New(catalog Catalog, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Manager{
		catalog: catalog, installDir: InstallDir, logger: logger,
		runDiscover: func(ctx context.Context, path string) (plugincontract.DiscoverResponse, error) {
			return discoverByExec(ctx, path, logger)
		},
	}
}

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

// Install fetches a Plugin, verifies it against the catalog, places it, and
// asks it to discover once so an artifact that cannot answer as the Plugin it
// was fetched as is refused now rather than reported unobserved later.
//
// Nothing is recorded and nothing is reported from here: the executable on
// disk is the record, and the host inventory the caller sends next is the
// report, which asks every Plugin, this one included.
func (m *Manager) Install(ctx context.Context, pluginID, goos, goarch string) (Installed, error) {
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
	// wrong-architecture artifact and provides the digest comparison that later
	// installed-build verification can reuse.
	if artifact.Digest != "" && digest != artifact.Digest {
		_ = os.Remove(path)
		return Installed{}, DigestMismatchError{PluginID: pluginID, Want: artifact.Digest, Got: digest}
	}

	dctx, cancel := context.WithTimeout(ctx, discoverTimeout)
	defer cancel()
	desc, err := m.runDiscover(dctx, path)
	if err != nil {
		_ = os.Remove(path)
		return Installed{}, fmt.Errorf("the plugin did not answer discover, so it was not installed: %w", err)
	}
	if desc.Name != "" && desc.Name != pluginID {
		_ = os.Remove(path)
		return Installed{}, fmt.Errorf("pluginmgr: the artifact for %q calls itself %q", pluginID, desc.Name)
	}
	if err := plugincontract.ValidateDiscover(desc); err != nil {
		_ = os.Remove(path)
		return Installed{}, fmt.Errorf("the plugin's answer is not usable, so it was not installed: %w", err)
	}
	return Installed{ID: pluginID, Version: desc.Version, Digest: digest, Path: path}, nil
}

// List is the installed set: every executable in the Plugin directory, with
// the digest of its bytes now. Versions are not filled here, since that means
// running each Plugin; Discover does that.
func (m *Manager) List() ([]Installed, error) {
	entries, err := os.ReadDir(m.installDir)
	if errors.Is(err, os.ErrNotExist) {
		return []Installed{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("pluginmgr: listing %s: %w", m.installDir, err)
	}
	out := make([]Installed, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !validPluginID.MatchString(e.Name()) {
			continue
		}
		path := filepath.Join(m.installDir, e.Name())
		digest, err := fileDigest(path)
		if err != nil {
			return nil, fmt.Errorf("pluginmgr: %s: %w", path, err)
		}
		out = append(out, Installed{ID: e.Name(), Digest: digest, Path: path})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Discover runs every installed Plugin's discover under the timeout and
// returns what the host inventory carries for each (S2 FR-026): the digest of
// the bytes on disk and the answer, or, when a Plugin exits non-zero, times
// out or answers something unusable, the Plugin as present but unobserved
// with a warning naming the failure. A Plugin's failure to answer is not this
// method's failure: the inventory must still say the Plugin is there, or it
// would look uninstalled. Only the directory being unreadable is an error,
// since then nothing can be said about any Plugin and a report must not claim
// the host has none.
func (m *Manager) Discover(ctx context.Context) ([]wire.PluginInventory, error) {
	installed, err := m.List()
	if err != nil {
		return nil, err
	}
	out := make([]wire.PluginInventory, 0, len(installed))
	for _, p := range installed {
		entry := wire.PluginInventory{ID: p.ID, Digest: p.Digest}
		dctx, cancel := context.WithTimeout(ctx, discoverTimeout)
		desc, err := m.runDiscover(dctx, p.Path)
		cancel()
		if err == nil && desc.Name != "" && desc.Name != p.ID {
			err = fmt.Errorf("the executable calls itself %q", desc.Name)
		}
		if err == nil {
			err = plugincontract.ValidateDiscover(desc)
		}
		if err != nil {
			entry.Unobserved = true
			entry.Warnings = []string{fmt.Sprintf("`discover` produced nothing this run: %v", err)}
			m.logger.Warn("plugin unobserved", "plugin", p.ID, "err", err)
		} else {
			entry.Version, entry.Description = desc.Version, desc.Description
			entry.Declarations, entry.DiscoveredTargets, entry.Warnings = desc.Settings, desc.DiscoveredTargets, desc.Warnings
			if entry.Declarations == nil {
				entry.Declarations = []plugincontract.SettingDeclaration{}
			}
		}
		out = append(out, entry)
	}
	return out, nil
}

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

// discoverByExec runs the Plugin's discover operation the way every operation
// runs: the name on argv, JSON on stdout. Nothing is written to its stdin,
// discover taking no request.
//
// Recorded through plugintrace like an install, and worth it for the same
// reason: what a build declares about itself is where a Plugin under
// development most often disagrees with what it meant to declare, and nothing
// else on the host shows the answer it actually gave.
func discoverByExec(ctx context.Context, path string, logger *slog.Logger) (plugincontract.DiscoverResponse, error) {
	var out plugincontract.DiscoverResponse
	// #nosec G204 -- path is InstallDir joined with a name matched against
	// validPluginID, so it names a file this Agent just wrote.
	cmd := exec.CommandContext(ctx, path, plugincontract.OpDiscover)
	// Bounded like the install path's. A Plugin describing itself is the same
	// arbitrary code, and an unbounded buffer here meant one that flooded
	// stderr was limited by nothing but this Agent's memory.
	cap := &plugintrace.Capture{Max: plugintrace.MaxPluginOutput}
	stderr := cap.Writer(plugintrace.StreamStderr)
	cmd.Stderr = stderr
	started := time.Now()
	stdout, err := cmd.Output()
	stderr.Flush()
	code := 0
	if cmd.ProcessState != nil {
		code = cmd.ProcessState.ExitCode()
	}
	plugintrace.Record(logger, plugintrace.Exchange{
		Op: plugincontract.OpDiscover, Path: path, Args: []string{plugincontract.OpDiscover},
		Stdout: stdout, Stderr: []byte(cap.Text(plugintrace.StreamStderr)), ExitCode: code,
		Duration: time.Since(started), Err: err,
	})
	if err != nil {
		if diag := cap.Text(plugintrace.StreamStderr); diag != "" {
			return out, fmt.Errorf("%w: %s", err, diag)
		}
		return out, err
	}
	if err := json.Unmarshal(stdout, &out); err != nil {
		return out, fmt.Errorf("the plugin's discover output is not JSON: %w", err)
	}
	return out, nil
}

// --- catalog shapes ---------------------------------------------------------

// CatalogArtifact and CatalogPlugin mirror what the Server publishes
// (contracts/server-api.md). They live here rather than in the wire package
// because the Marketplace is a Server-to-anyone surface rather than part of the
// Agent↔Server protocol: a browser reads the same JSON.
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

// Find reports whether a Plugin executable is on this host, with the digest
// of its bytes and the version it answers now, which a Deployment records.
func (m *Manager) Find(id string) (Installed, bool, error) {
	if !validPluginID.MatchString(id) {
		return Installed{}, false, nil
	}
	path := filepath.Join(m.installDir, id)
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return Installed{}, false, nil
	} else if err != nil {
		return Installed{}, false, err
	}
	digest, err := fileDigest(path)
	if err != nil {
		return Installed{}, false, err
	}
	inst := Installed{ID: id, Digest: digest, Path: path}
	ctx, cancel := context.WithTimeout(context.Background(), discoverTimeout)
	defer cancel()
	if desc, err := m.runDiscover(ctx, path); err == nil {
		inst.Version = desc.Version
	}
	return inst, true, nil
}

// fileDigest is the SHA-256 of a file, lowercase hex, the same form the
// catalog publishes and the Server compares against.
func fileDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
