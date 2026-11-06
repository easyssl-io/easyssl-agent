// Package pluginmgr installs Plugins on this host and asks each what it is and
// what it sees. Nothing is bundled into the Agent binary: a Plugin is fetched
// from the Server's Marketplace on demand and placed under InstallDir, and that
// directory is the whole record of what is installed. A Plugin's version,
// declarations and installation points are what the executable answers to
// discover, asked afresh on every check-in; the Agent keeps no copy, because a
// copy goes stale and is then reported as fact.
package pluginmgr

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/easyssl-io/easyssl-agent/internal/msg"
	"github.com/easyssl-io/easyssl-agent/internal/plugintrace"
	"github.com/easyssl-io/easyssl-contract/l10n"
	"github.com/easyssl-io/easyssl-contract/plugincontract"
	"github.com/easyssl-io/easyssl-contract/wire"
)

// InstallDir is where Plugin executables live on the host. Root-owned: a
// Plugin is executed by the Agent, which runs as root, so anything that could
// write here could run code as root.
const InstallDir = "/var/lib/easyssl/plugins"

// maxArtifact bounds a download. A Plugin is a static Go binary of a few
// megabytes, so this is generous while refusing to write an unbounded stream to
// the host's disk.
const maxArtifact = 128 << 20

// pipeWaitDelay is how long a Plugin's pipes may stay open after it exits or
// is killed. A process it started in the background and that kept them would
// otherwise hold the Agent's wait forever.
const pipeWaitDelay = 5 * time.Second

// validPluginID is the Plugin naming rule, matching what the Server accepts on
// the report route. It is checked before the name reaches a file path, so a
// catalog entry cannot name a file outside InstallDir.
var validPluginID = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$`)

// Installed is one Plugin executable on this host, as it is now.
type Installed struct {
	ID string `json:"id"`
	// Version is what the executable answered to describe, empty when it did
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

type Manager struct {
	catalog Catalog
	// installDir is a field rather than the constant so a test can work
	// somewhere it may write.
	installDir string
	logger     *slog.Logger
	// runDescribe and runDiscover execute a Plugin's two answering operations.
	// Fields so a test can exercise the flow without a real binary.
	runDescribe func(ctx context.Context, path string) (plugincontract.DescribeResponse, error)
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
		runDescribe: func(ctx context.Context, path string) (plugincontract.DescribeResponse, error) {
			var out plugincontract.DescribeResponse
			return out, runByExec(ctx, path, plugincontract.OpDescribe, logger, &out)
		},
		runDiscover: func(ctx context.Context, path string) (plugincontract.DiscoverResponse, error) {
			var out plugincontract.DiscoverResponse
			return out, runByExec(ctx, path, plugincontract.OpDiscover, logger, &out)
		},
	}
}

var ErrNotInCatalog = msg.Err.T("plugin.install.not_in_catalog", "the Server's Marketplace does not offer this Plugin")

// ErrNoArtifact: the Plugin is offered but not for this host's platform.
var ErrNoArtifact = msg.Err.T("plugin.install.no_artifact", "the Marketplace has no build of this Plugin for this host's platform")

// DigestMismatchError reports an artifact whose bytes are not what the catalog
// said they would be.
type DigestMismatchError struct {
	PluginID string
	Want     string
	Got      string
}

func (e DigestMismatchError) Error() string {
	return msg.T("plugin.install.digest_mismatch", "{plugin} downloaded as {got} but the catalog published {want}", "plugin", e.PluginID, "got", e.Got, "want", e.Want)
}

// Install fetches a Plugin, verifies it against the catalog, places it, and
// asks it to describe itself once, so an artifact that cannot answer as the
// Plugin it was fetched as is refused now rather than reported unobserved
// later. describe reads nothing from the host, so installing does not wait on
// a scan.
//
// Nothing is recorded or reported from here: the executable on disk is the
// record, and the host inventory the caller sends next is the report.
func (m *Manager) Install(ctx context.Context, pluginID, goos, goarch string) (Installed, error) {
	if !validPluginID.MatchString(pluginID) {
		return Installed{}, msg.Err.T("plugin.install.invalid_name", "\"{plugin}\" is not a valid Plugin name", "plugin", pluginID)
	}
	cat, err := m.catalog.Fetch(ctx)
	if err != nil {
		return Installed{}, msg.Err.T("plugin.install.catalog_failed", "reading the Marketplace catalog: {err}", "err", err)
	}
	entry, ok := cat.find(pluginID)
	if !ok {
		return Installed{}, ErrNotInCatalog
	}
	artifact, ok := entry.artifact(goos, goarch)
	if !ok {
		return Installed{}, ErrNoArtifact
	}

	// A catalog entry with no digest would turn off the only check below, so it
	// is refused rather than trusted.
	if artifact.Digest == "" {
		return Installed{}, msg.Err.T("plugin.install.no_digest", "the catalog publishes no digest for {plugin}, so it was not installed", "plugin", pluginID)
	}

	// Everything is checked on a temporary file beside the installed one, which
	// replaces it only once the checks pass: a download that fails them, such as
	// one from a Server mid-upgrade, leaves the working build in place.
	tmp, digest, err := m.download(ctx, artifact.URL)
	if err != nil {
		return Installed{}, err
	}
	defer os.Remove(tmp) // a no-op once renamed
	// A mismatch means the download was not what the catalog offered. This is
	// integrity, not authentication: it catches a truncated, stale or
	// wrong-architecture artifact.
	if digest != artifact.Digest {
		return Installed{}, DigestMismatchError{PluginID: pluginID, Want: artifact.Digest, Got: digest}
	}
	desc, err := m.describe(ctx, tmp, pluginID)
	if err != nil {
		return Installed{}, msg.Err.T("plugin.install.unusable_answer", "the Plugin's answer is not usable, so it was not installed: {err}", "err", err)
	}
	path := filepath.Join(m.installDir, pluginID)
	if err := os.Rename(tmp, path); err != nil {
		return Installed{}, err
	}
	return Installed{ID: pluginID, Version: desc.Version, Digest: digest, Path: path}, nil
}

// describe runs a Plugin's describe and applies every check an answer must
// pass, the same for an install, an inventory and a Deployment: an answer, the
// executable's own name, and the contract's rules.
func (m *Manager) describe(ctx context.Context, path, pluginID string) (plugincontract.DescribeResponse, error) {
	dctx, cancel := context.WithTimeout(ctx, plugincontract.AnswerTimeout)
	defer cancel()
	desc, err := m.runDescribe(dctx, path)
	if err != nil {
		return desc, err
	}
	if desc.Name != "" && desc.Name != pluginID {
		return desc, msg.Err.T("plugin.describe.other_name", "the executable calls itself \"{name}\"", "name", desc.Name)
	}
	return desc, plugincontract.ValidateDescribe(desc)
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
		return nil, msg.Err.T("plugin.list.failed", "listing {path}: {err}", "path", m.installDir, "err", err)
	}
	out := make([]Installed, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !validPluginID.MatchString(e.Name()) {
			continue
		}
		path := filepath.Join(m.installDir, e.Name())
		digest, err := fileDigest(path)
		if err != nil {
			return nil, msg.Err.T("plugin.list.unreadable", "reading {path}: {err}", "path", path, "err", err)
		}
		out = append(out, Installed{ID: e.Name(), Digest: digest, Path: path})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Discover runs every installed Plugin's describe and then its discover, each
// under the timeout, and returns what the host inventory carries for each: the
// digest of the bytes on disk and the two answers merged. A Plugin that exits
// non-zero, times out or answers something unusable is returned as present but
// unobserved, with a warning naming the failure, because otherwise it would
// look uninstalled. Only an unreadable directory is an error, since a report
// must not then claim the host has no Plugins.
func (m *Manager) Discover(ctx context.Context) ([]wire.PluginInventory, error) {
	installed, err := m.List()
	if err != nil {
		return nil, err
	}
	// Each Plugin is observed at once, so the pass takes as long as the slowest
	// Plugin rather than the sum of all of them, and stays within the check-in
	// interval however many are installed.
	out := make([]wire.PluginInventory, len(installed))
	var wg sync.WaitGroup
	for i, p := range installed {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out[i] = m.inventoryEntry(ctx, p)
		}()
	}
	wg.Wait()
	return out, nil
}

// inventoryEntry is what the host inventory carries for one installed Plugin.
func (m *Manager) inventoryEntry(ctx context.Context, p Installed) wire.PluginInventory {
	entry := wire.PluginInventory{ID: p.ID, Digest: p.Digest}
	desc, disc, op, err := m.observe(ctx, p)
	if err != nil {
		entry.Unobserved = true
		// Written by this Agent rather than by the Plugin, and read on the
		// Server by people of any language, so it carries every one.
		entry.Warnings = []l10n.Text{msg.Text("plugin.inventory.unobserved", "`{op}` produced nothing usable this run: {err}", "op", op, "err", err)}
		m.logger.Warn("plugin unobserved", "plugin", p.ID, "op", op, "err", err)
	} else {
		entry.Version, entry.Description = desc.Version, desc.Description
		entry.Declarations, entry.DiscoveredTargets, entry.Warnings = desc.Settings, disc.DiscoveredTargets, disc.Warnings
		if entry.Declarations == nil {
			entry.Declarations = []plugincontract.SettingDeclaration{}
		}
	}
	return entry
}

// observe runs one Plugin's describe and discover and checks both answers,
// returning the operation that failed alongside the error. The two run as
// separate processes, so the executable is hashed again afterwards: a binary
// replaced between them would otherwise report one build's declarations with
// another's findings.
func (m *Manager) observe(ctx context.Context, p Installed) (plugincontract.DescribeResponse, plugincontract.DiscoverResponse, string, error) {
	var disc plugincontract.DiscoverResponse
	desc, err := m.describe(ctx, p.Path, p.ID)
	if err != nil {
		return desc, disc, plugincontract.OpDescribe, err
	}
	dctx, cancel := context.WithTimeout(ctx, plugincontract.AnswerTimeout)
	disc, err = m.runDiscover(dctx, p.Path)
	cancel()
	if err == nil {
		err = plugincontract.ValidateDiscover(desc.Settings, disc)
	}
	if err != nil {
		return desc, disc, plugincontract.OpDiscover, err
	}
	if now, err := fileDigest(p.Path); err != nil || now != p.Digest {
		return desc, disc, plugincontract.OpDiscover, msg.Err.T("plugin.inventory.changed", "the executable changed while it was being read")
	}
	return desc, disc, "", nil
}

// download writes an artifact to a temporary executable in the Plugin
// directory, whose name no Plugin can have, and returns its path and digest.
// The caller renames it into place or removes it.
func (m *Manager) download(ctx context.Context, url string) (path, digest string, err error) {
	if err := os.MkdirAll(m.installDir, 0o755); err != nil {
		return "", "", err
	}
	body, err := m.catalog.Download(ctx, url)
	if err != nil {
		return "", "", msg.Err.T("plugin.install.download_failed", "downloading the Plugin: {err}", "err", err)
	}
	defer body.Close()

	tmp, err := os.CreateTemp(m.installDir, ".download-*")
	if err != nil {
		return "", "", err
	}
	defer func() {
		tmp.Close()
		if err != nil {
			_ = os.Remove(tmp.Name())
		}
	}()
	h := sha256.New()
	if _, err = io.Copy(io.MultiWriter(tmp, h), io.LimitReader(body, maxArtifact)); err != nil {
		return "", "", msg.Err.T("plugin.install.write_failed", "writing the Plugin to disk: {err}", "err", err)
	}
	if err = tmp.Chmod(0o755); err != nil {
		return "", "", err
	}
	if err = tmp.Close(); err != nil {
		return "", "", err
	}
	return tmp.Name(), hex.EncodeToString(h.Sum(nil)), nil
}

// runByExec runs one of the Plugin's answering operations, describe or
// discover, the way every operation runs: the name on argv, JSON on stdout
// decoded into out, and nothing on stdin, neither taking a request.
//
// Recorded through plugintrace: what a build declares about itself is where a
// Plugin under development most often disagrees with what it meant to declare,
// and nothing else on the host shows the answer it gave.
func runByExec(ctx context.Context, path, op string, logger *slog.Logger, out any) error {
	// #nosec G204 -- path is InstallDir joined with a name matched against
	// validPluginID, so it names a file this Agent just wrote, and op is one of
	// the contract's constants.
	cmd := exec.CommandContext(ctx, path, op)
	// Its own process group, killed whole when the answer is late, so what the
	// Plugin started (an `nginx -t`) does not outlive it; and a bounded wait for
	// its pipes, so a child that keeps them open cannot hold this call.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = pipeWaitDelay
	// Bounded like the install path's. A Plugin describing itself is the same
	// arbitrary code, and one that flooded stderr would otherwise be limited only
	// by this Agent's memory.
	cap := &plugintrace.Capture{Max: plugintrace.MaxPluginOutput}
	stderr := cap.Writer(plugintrace.StreamStderr)
	cmd.Stderr = stderr
	// Stdout is bounded too: a broken Plugin printing without end would otherwise
	// grow this Agent's memory on every inventory pass. Past the bound it is
	// drained and dropped, so the Plugin is not blocked, and the answer is refused
	// below.
	answer := &boundedBuffer{max: plugintrace.MaxPluginOutput}
	cmd.Stdout = answer
	started := time.Now()
	err := cmd.Run()
	stdout := answer.buf.Bytes()
	stderr.Flush()
	code := 0
	if cmd.ProcessState != nil {
		code = cmd.ProcessState.ExitCode()
	}
	plugintrace.Record(logger, plugintrace.Exchange{
		Op: op, Path: path, Args: []string{op},
		Stdout: stdout, Stderr: []byte(cap.Text(plugintrace.StreamStderr)), ExitCode: code,
		Duration: time.Since(started), Err: err,
	})
	if err != nil {
		if diag := cap.Text(plugintrace.StreamStderr); diag != "" {
			return fmt.Errorf("%w: %s", err, diag)
		}
		return err
	}
	if answer.over {
		return msg.Err.T("plugin.op.too_large", "the `{op}` answer exceeds {bytes} bytes", "op", op, "bytes", plugintrace.MaxPluginOutput)
	}
	if err := json.Unmarshal(stdout, out); err != nil {
		return msg.Err.T("plugin.op.not_json", "the Plugin's `{op}` output is not JSON: {err}", "op", op, "err", err)
	}
	return nil
}

// CatalogArtifact and CatalogPlugin mirror what the Server publishes. They live
// here rather than in the wire package because the Marketplace is a
// Server-to-anyone surface, not part of the Agent↔Server protocol: a browser
// reads the same JSON.
type CatalogArtifact struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	Digest string `json:"digest"`
	URL    string `json:"url"`
}

type CatalogPlugin struct {
	ID          string            `json:"id"`
	Version     string            `json:"version"`
	Description l10n.Text         `json:"description"`
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

// HasArtifact reports whether the entry offers a build for this platform.
func (p CatalogPlugin) HasArtifact(goos, goarch string) bool {
	_, ok := p.artifact(goos, goarch)
	return ok
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
	return &http.Client{
		Timeout: 10 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 || !sameOrigin(via[0].URL, req.URL) {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
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
		return out, msg.Err.T("plugin.catalog.http_status", "the Server answered {status} for the catalog", "status", res.Status)
	}
	return out, json.NewDecoder(res.Body).Decode(&out)
}

// Download fetches an artifact by the URL the catalog names, a path resolved
// against BaseURL. A URL naming any other origin is refused, as is a redirect
// to one: the Agent downloads code only from the Server it is registered to.
func (c HTTPCatalog) Download(ctx context.Context, ref string) (io.ReadCloser, error) {
	base, err := url.Parse(c.BaseURL)
	if err != nil {
		return nil, err
	}
	target, err := base.Parse(ref)
	if err != nil {
		return nil, err
	}
	if !sameOrigin(base, target) {
		return nil, msg.Err.T("plugin.install.other_origin", "the catalog names {url}, which is not on the Server", "url", target.String())
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, err
	}
	res, err := c.client().Do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		res.Body.Close()
		return nil, msg.Err.T("plugin.install.http_status", "the Server answered {status} for the artifact", "status", res.Status)
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
	// The same checks an inventory applies, so a Deployment records a version
	// only from an answer that passed them.
	desc, err := m.describe(context.Background(), path, id)
	if err != nil {
		return Installed{}, true, msg.Err.T("plugin.find.unusable_answer", "{plugin} did not answer `describe` usably: {err}", "plugin", id, "err", err)
	}
	return Installed{ID: id, Digest: digest, Path: path, Version: desc.Version}, true, nil
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

// boundedBuffer keeps at most max bytes and records that more arrived, while
// still accepting everything written so the writer is never blocked.
type boundedBuffer struct {
	buf  bytes.Buffer
	max  int
	over bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.buf.Len(); room < len(p) {
		b.over = true
		if room > 0 {
			b.buf.Write(p[:room])
		}
		return len(p), nil
	}
	return b.buf.Write(p)
}
