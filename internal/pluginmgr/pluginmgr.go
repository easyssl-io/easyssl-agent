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
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/easyssl-io/easyssl-agent/internal/acmeclients"
	"github.com/easyssl-io/easyssl-agent/internal/identity"
	"github.com/easyssl-io/easyssl-agent/internal/msg"
	"github.com/easyssl-io/easyssl-agent/internal/plugintrace"
	"github.com/easyssl-io/easyssl-contract/catalog"
	"github.com/easyssl-io/easyssl-contract/l10n"
	"github.com/easyssl-io/easyssl-contract/plugincontract"
	"github.com/easyssl-io/easyssl-contract/wire"
)

// InstallDir is where Plugin executables live on the host. Root-owned: a
// Plugin is executed by the Agent, which runs as root, so anything that could
// write here could run code as root.
const InstallDir = identity.StateDir + "/plugins"

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
	// Declarations are the settings the executable declared, filled by Find,
	// which a Deployment reads to know which values are paths.
	Declarations []plugincontract.SettingDeclaration `json:"-"`
}

// Catalog is the Marketplace read. Separate from Reporter because the catalog
// needs no token: it is the same bytes for everyone.
type Catalog interface {
	Catalog(ctx context.Context) (catalog.Response, error)
	Download(ctx context.Context, url string) (io.ReadCloser, error)
}

type Manager struct {
	catalog Catalog
	// installDir is a field rather than the constant so a test can work
	// somewhere it may write.
	installDir string
	logger     *slog.Logger
	// runDescribe and runDiscover execute a Plugin's two answering operations
	// and return its answer as printed. Fields so a test can exercise the flow
	// without a real binary.
	runDescribe func(ctx context.Context, path string) ([]byte, error)
	runDiscover func(ctx context.Context, path string) ([]byte, error)
	// acme is the host the managed-path rule reads; a field so a test can lay
	// out certbot's directories somewhere it may write.
	acme acmeclients.Host
}

// New builds a Manager over the host's real Plugin directory. catalog may be
// nil for a caller that only lists or discovers; logger may be nil.
func New(catalog Catalog, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Manager{
		catalog: catalog, installDir: InstallDir, logger: logger, acme: acmeclients.System(),
		runDescribe: func(ctx context.Context, path string) ([]byte, error) {
			return runByExec(ctx, path, plugincontract.OpDescribe, logger)
		},
		runDiscover: func(ctx context.Context, path string) ([]byte, error) {
			return runByExec(ctx, path, plugincontract.OpDiscover, logger)
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
	cat, err := m.catalog.Catalog(ctx)
	if err != nil {
		return Installed{}, msg.Err.T("plugin.install.catalog_failed", "reading the Marketplace catalog: {err}", "err", err)
	}
	entry, ok := findPlugin(cat, pluginID)
	if !ok {
		return Installed{}, ErrNotInCatalog
	}
	// Only first-party Plugins are installed: a third-party one would need a
	// signature this Agent cannot check yet, so it is refused rather than run
	// as root on the strength of a catalog entry alone.
	if entry.Party != catalog.PartyFirst {
		return Installed{}, msg.Err.T("plugin.install.not_first_party", "{plugin} is not a first-party Plugin, and this Agent installs only those", "plugin", pluginID)
	}
	artifact, ok := artifactFor(entry, goos, goarch)
	if !ok {
		return Installed{}, ErrNoArtifact
	}

	// A catalog entry with no digest would turn off the only check below, so it
	// is refused rather than trusted.
	if artifact.SHA256 == "" {
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
	if digest != artifact.SHA256 {
		return Installed{}, DigestMismatchError{PluginID: pluginID, Want: artifact.SHA256, Got: digest}
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
	desc, _, err := m.describeRaw(ctx, path, pluginID)
	return desc, err
}

// describeRaw is describe returning the answer as printed too, which the host
// inventory forwards: the decoded copy is checked, the bytes are sent, so a
// field a newer Plugin adds reaches the Server through this Agent.
func (m *Manager) describeRaw(ctx context.Context, path, pluginID string) (plugincontract.DescribeResponse, []byte, error) {
	var desc plugincontract.DescribeResponse
	dctx, cancel := context.WithTimeout(ctx, plugincontract.AnswerTimeout)
	defer cancel()
	raw, err := m.runDescribe(dctx, path)
	if err != nil {
		return desc, nil, err
	}
	if err := json.Unmarshal(raw, &desc); err != nil {
		return desc, nil, msg.Err.T("plugin.op.not_json", "the Plugin's `{op}` output is not JSON: {err}", "op", plugincontract.OpDescribe, "err", err)
	}
	// A Plugin built against another breaking version of the contract may
	// expect a request this Agent does not send, or answer one it cannot read,
	// so it is refused by name rather than run.
	if !plugincontract.Compatible(desc.ContractVersion) {
		return desc, nil, msg.Err.T("plugin.describe.contract", "the Plugin was built against contract version \"{got}\", which this Agent ({own}) does not run", "got", desc.ContractVersion, "own", plugincontract.ContractVersion)
	}
	if err := plugincontract.ValidateDescribe(desc); err != nil {
		return desc, nil, err
	}
	return desc, raw, nil
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

// Contracts maps each installed Plugin to the contract version it answers
// describe with, including one this Agent refuses, so `update` can tell which
// a newer Agent would refuse. A Plugin that does not answer is left out: it
// runs under no Agent now.
func (m *Manager) Contracts(ctx context.Context) (map[string]string, error) {
	installed, err := m.List()
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(installed))
	for _, p := range installed {
		// describeRaw decodes the answer before judging it, so the version is
		// there when only the contract check failed.
		if desc, _, _ := m.describeRaw(ctx, p.Path, p.ID); desc.ContractVersion != "" {
			out[p.ID] = desc.ContractVersion
		}
	}
	return out, nil
}

// Discover runs every installed Plugin's describe and then its discover, each
// under the timeout, and returns what the host inventory carries for each: the
// digest of the bytes on disk and the two answers merged, with the Agent's own
// warning added to every discovered Target on a path another ACME client
// manages (MarkManaged). A Plugin that exits non-zero, times out or answers
// something unusable is returned as present but unobserved, with a warning
// naming the failure, because otherwise it would look uninstalled. Only an
// unreadable directory is an error, since a report must not then claim the
// host has no Plugins.
func (m *Manager) Discover(ctx context.Context) ([]wire.PluginInventory, error) {
	obs, err := m.Observe(ctx)
	if err != nil {
		return nil, err
	}
	_, findings := m.Assess(obs)
	out := make([]wire.PluginInventory, len(obs))
	for i, o := range obs {
		out[i] = m.inventoryEntry(o, findings[i])
	}
	return out, nil
}

// Observation is one installed Plugin as it answered this run.
type Observation struct {
	Installed
	// Describe and Discover are its checked answers, exactly as it gave them:
	// without the Agent's warnings, which Assess computes beside them.
	// Meaningful only when Err is nil.
	Describe plugincontract.DescribeResponse
	Discover plugincontract.DiscoverResponse
	// FailedOp is the operation that failed when Err is set.
	FailedOp string
	Err      error

	describeRaw, discoverRaw []byte
}

// Observe runs every installed Plugin's describe and discover, each under the
// timeout and each Plugin at once, so the pass takes as long as the slowest
// Plugin rather than the sum of all of them and stays within the check-in
// interval however many are installed.
func (m *Manager) Observe(ctx context.Context) ([]Observation, error) {
	installed, err := m.List()
	if err != nil {
		return nil, err
	}
	out := make([]Observation, len(installed))
	var wg sync.WaitGroup
	for i, p := range installed {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out[i] = m.observe(ctx, p)
		}()
	}
	wg.Wait()
	return out, nil
}

// Assess is AssessOn this Manager's host.
func (m *Manager) Assess(obs []Observation) (*acmeclients.Rule, [][][]acmeclients.Finding) {
	return AssessOn(m.acme, obs)
}

// AssessOn applies the managed-path rule (acmeclients) to every discovered
// Target of every observed Plugin at once, reading each Target's path settings
// and its certificate's digest. The result is indexed like obs and each
// Plugin's discovered Targets. The host is read only when some Target has a
// path, so a host with nothing to check costs no scan; the Rule is then nil.
func AssessOn(host acmeclients.Host, obs []Observation) (*acmeclients.Rule, [][][]acmeclients.Finding) {
	var targets []acmeclients.Target
	var paths []string
	for _, o := range obs {
		if o.Err != nil {
			continue
		}
		for _, t := range o.Discover.DiscoveredTargets {
			at := acmeclients.Target{Paths: acmeclients.PathValues(o.Describe.Declarations, t.Settings)}
			if t.Certificate != nil {
				at.CertSHA256 = t.Certificate.SHA256
			}
			targets = append(targets, at)
			paths = append(paths, at.Paths...)
		}
	}
	out := make([][][]acmeclients.Finding, len(obs))
	for i, o := range obs {
		if o.Err == nil {
			out[i] = make([][]acmeclients.Finding, len(o.Discover.DiscoveredTargets))
		}
	}
	if len(paths) == 0 {
		return nil, out
	}
	rule := host.Scan(paths)
	assessed := rule.Assess(targets)
	k := 0
	for i, o := range obs {
		if o.Err != nil {
			continue
		}
		for j := range o.Discover.DiscoveredTargets {
			out[i][j] = assessed[k]
			k++
		}
	}
	return rule, out
}

// inventoryEntry is what the host inventory carries for one observed Plugin,
// with its findings as warnings on the discovered Targets they concern.
func (m *Manager) inventoryEntry(o Observation, findings [][]acmeclients.Finding) wire.PluginInventory {
	entry := wire.PluginInventory{ID: o.ID, SHA256: o.Digest, Warnings: []l10n.Text{}}
	op, err := o.FailedOp, o.Err
	var discover []byte
	if err == nil {
		discover, err = MarkManaged(o.Describe, o.discoverRaw, findings)
		op = plugincontract.OpDiscover
	}
	if err != nil {
		entry.Unobserved = true
		// Written by this Agent rather than by the Plugin, and read on the
		// Server by people of any language, so it carries every one.
		entry.Warnings = []l10n.Text{msg.Text("plugin.inventory.unobserved", "`{op}` produced nothing usable this run: {err}", "op", op, "err", err)}
		m.logger.Warn("plugin unobserved", "plugin", o.ID, "op", op, "err", err)
		return entry
	}
	entry.Describe, entry.Discover = o.describeRaw, discover
	return entry
}

// MarkManaged appends each finding's warning to the discovered Target it
// concerns, in the discover answer as the Plugin printed it, and checks the
// result as any answer is checked. Only the warnings of a Target with
// findings change: every other byte is the Plugin's, so a field a newer
// Plugin adds still reaches the Server through this Agent. A warning is what
// keeps the Server from suggesting the Target, so an answer that cannot carry
// one is refused rather than sent without it.
func MarkManaged(desc plugincontract.DescribeResponse, raw []byte, findings [][]acmeclients.Finding) ([]byte, error) {
	marked := false
	for _, fs := range findings {
		marked = marked || len(fs) > 0
	}
	if !marked {
		return raw, nil
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, err
	}
	var targets []map[string]json.RawMessage
	if err := json.Unmarshal(top["discoveredTargets"], &targets); err != nil {
		return nil, err
	}
	if len(targets) != len(findings) {
		return nil, fmt.Errorf("%d discovered Targets, %d assessed", len(targets), len(findings))
	}
	for i, fs := range findings {
		if len(fs) == 0 {
			continue
		}
		var warnings []l10n.Text
		if w, ok := targets[i]["warnings"]; ok {
			if err := json.Unmarshal(w, &warnings); err != nil {
				return nil, err
			}
		}
		for _, f := range fs {
			warnings = append(warnings, f.Warning())
		}
		b, err := json.Marshal(warnings)
		if err != nil {
			return nil, err
		}
		targets[i]["warnings"] = b
	}
	b, err := json.Marshal(targets)
	if err != nil {
		return nil, err
	}
	top["discoveredTargets"] = b
	out, err := json.Marshal(top)
	if err != nil {
		return nil, err
	}
	var disc plugincontract.DiscoverResponse
	if err := json.Unmarshal(out, &disc); err != nil {
		return nil, err
	}
	if err := plugincontract.ValidateDiscover(desc.Declarations, disc); err != nil {
		return nil, err
	}
	return out, nil
}

// observe runs one Plugin's describe and discover and checks decoded copies of
// both answers. The two run as separate processes, so the executable is
// hashed again afterwards: a binary replaced between them would otherwise
// report one build's declarations with another's findings.
func (m *Manager) observe(ctx context.Context, p Installed) Observation {
	o := Observation{Installed: p}
	fail := func(op string, err error) Observation {
		return Observation{Installed: p, FailedOp: op, Err: err}
	}
	desc, describe, err := m.describeRaw(ctx, p.Path, p.ID)
	if err != nil {
		return fail(plugincontract.OpDescribe, err)
	}
	dctx, cancel := context.WithTimeout(ctx, plugincontract.AnswerTimeout)
	discover, err := m.runDiscover(dctx, p.Path)
	cancel()
	var disc plugincontract.DiscoverResponse
	if err == nil {
		if jerr := json.Unmarshal(discover, &disc); jerr != nil {
			err = msg.Err.T("plugin.op.not_json", "the Plugin's `{op}` output is not JSON: {err}", "op", plugincontract.OpDiscover, "err", jerr)
		} else {
			err = plugincontract.ValidateDiscover(desc.Declarations, disc)
		}
	}
	if err != nil {
		return fail(plugincontract.OpDiscover, err)
	}
	if now, err := fileDigest(p.Path); err != nil || now != p.Digest {
		return fail(plugincontract.OpDiscover, msg.Err.T("plugin.inventory.changed", "the executable changed while it was being read"))
	}
	o.Version = desc.Version
	o.Describe, o.Discover = desc, disc
	o.describeRaw, o.discoverRaw = describe, discover
	return o
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
func runByExec(ctx context.Context, path, op string, logger *slog.Logger) ([]byte, error) {
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
			return nil, fmt.Errorf("%w: %s", err, diag)
		}
		return nil, err
	}
	if answer.over {
		return nil, msg.Err.T("plugin.op.too_large", "the `{op}` answer exceeds {bytes} bytes", "op", op, "bytes", plugintrace.MaxPluginOutput)
	}
	// Checked here so every caller holds JSON, which the inventory forwards
	// as it is.
	if !json.Valid(stdout) {
		return nil, msg.Err.T("plugin.op.not_json", "the Plugin's `{op}` output is not JSON: {err}", "op", op, "err", "invalid JSON")
	}
	return stdout, nil
}

func findPlugin(c catalog.Response, id string) (catalog.Plugin, bool) {
	for _, p := range c.Plugins {
		if p.ID == id {
			return p, true
		}
	}
	return catalog.Plugin{}, false
}

// HasArtifact reports whether the entry offers a build for this platform.
func HasArtifact(p catalog.Plugin, goos, goarch string) bool {
	_, ok := artifactFor(p, goos, goarch)
	return ok
}

func artifactFor(p catalog.Plugin, goos, goarch string) (catalog.Artifact, bool) {
	for _, a := range p.Artifacts {
		if a.OS == goos && a.Arch == goarch {
			return a, true
		}
	}
	return catalog.Artifact{}, false
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
	return Installed{ID: id, Digest: digest, Path: path, Version: desc.Version, Declarations: desc.Declarations}, true, nil
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
