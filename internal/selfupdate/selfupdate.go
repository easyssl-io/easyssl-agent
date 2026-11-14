// Package selfupdate replaces this Agent's own executable with the build the
// Server's catalog offers (catalog.Response.Agent): it decides whether there
// is one to take, fetches and checks it beside the running one, swaps it in
// keeping the previous build, and puts that back when asked.
//
// The command that drives it, `easyssl-agent update`, restarts the service
// between the swap and the check that the new build stays up.
package selfupdate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/easyssl-io/easyssl-agent/internal/msg"
	"github.com/easyssl-io/easyssl-agent/internal/version"
	"github.com/easyssl-io/easyssl-contract/catalog"
)

// maxArtifact bounds a download, as for a Plugin: the Agent is a static Go
// binary of a few megabytes.
const maxArtifact = 128 << 20

// Plan is what `update` would do with the Agent.
type Plan struct {
	Current, Offered string
	// Artifact is the build to take; zero when there is nothing to do.
	Artifact catalog.Artifact
	// Needed is false when this build is the one offered, or a newer one.
	Needed bool
}

var (
	// ErrNotOffered: the Server's catalog names no Agent build.
	ErrNotOffered = msg.Err.T("update.not_offered", "the Server's catalog offers no Agent build")
	// ErrNoBuild: it does, but not for this host's platform.
	ErrNoBuild = msg.Err.T("update.no_build", "the Server has no Agent build for this host's platform")
)

// Decide compares the running build with the catalog's. The digest decides:
// a build whose bytes are the ones offered is current whatever its version
// says, and two development builds of one release differ only there. A build
// offered at a lower version than the running one is not taken, so a Server
// holding an older Agent never downgrades a host.
func Decide(entry *catalog.Agent, goos, goarch, current, currentDigest string) (Plan, error) {
	if entry == nil {
		return Plan{}, ErrNotOffered
	}
	p := Plan{Current: current, Offered: entry.Version}
	var a catalog.Artifact
	for _, x := range entry.Artifacts {
		if x.OS == goos && x.Arch == goarch {
			a = x
		}
	}
	if a.URL == "" {
		return p, ErrNoBuild
	}
	// No digest would turn off the only check of what is downloaded.
	if a.SHA256 == "" {
		return p, msg.Err.T("update.no_digest", "the catalog publishes no digest for the Agent build, so it was not taken")
	}
	if a.SHA256 == currentDigest || version.Older(entry.Version, current) {
		return p, nil
	}
	p.Artifact, p.Needed = a, true
	return p, nil
}

// Downloader fetches an artifact by the URL the catalog names, from the Server
// the Agent is registered with.
type Downloader interface {
	Download(ctx context.Context, url string) (io.ReadCloser, error)
}

// Staged and Previous are the files an update keeps beside the binary: the
// build being installed, and the one it replaced, kept for a rollback.
// Uninstall removes them with the binary.
func Staged(binary string) string   { return binary + ".new" }
func Previous(binary string) string { return binary + ".prev" }

// Stage downloads the build beside binary, as Staged(binary), checks its
// digest and that it runs here and reports the version it was offered as, and
// returns its path. Nothing replaces the running build yet.
func Stage(ctx context.Context, d Downloader, p Plan, binary string) (string, error) {
	staged := Staged(binary)
	body, err := d.Download(ctx, p.Artifact.URL)
	if err != nil {
		return "", msg.Err.T("update.download_failed", "downloading the Agent: {err}", "err", err)
	}
	defer body.Close()
	_ = os.Remove(staged)
	f, err := os.OpenFile(staged, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, h), io.LimitReader(body, maxArtifact))
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(staged)
		return "", msg.Err.T("update.write_failed", "writing the Agent to disk: {err}", "err", err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != p.Artifact.SHA256 {
		_ = os.Remove(staged)
		return "", msg.Err.T("update.digest_mismatch", "the Agent downloaded as {got} but the catalog published {want}", "got", got, "want", p.Artifact.SHA256)
	}
	// Run once, so a build that cannot start on this host is refused before it
	// replaces one that can.
	vctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// #nosec G204 -- staged is Staged(binary), written above and checked
	// against the catalog's digest.
	out, err := exec.CommandContext(vctx, staged, "version").Output()
	if got := string(bytes.TrimSpace(out)); err != nil || (p.Offered != "" && got != p.Offered) {
		_ = os.Remove(staged)
		if err == nil {
			err = errors.New(got)
		}
		return "", msg.Err.T("update.does_not_run", "the downloaded Agent does not run on this host as {version}: {err}", "version", p.Offered, "err", err)
	}
	return staged, nil
}

// Swap keeps the running build as Previous(binary) and renames the staged
// one into its place, which the running process survives: it keeps the inode
// it was started from.
func Swap(binary, staged string) error {
	prev := Previous(binary)
	_ = os.Remove(prev)
	if err := os.Link(binary, prev); err != nil {
		return msg.Err.T("update.keep_previous_failed", "keeping the previous Agent as {path}: {err}", "path", prev, "err", err)
	}
	if err := os.Rename(staged, binary); err != nil {
		return err
	}
	return syncDir(filepath.Dir(binary))
}

// Restore puts the build Swap kept back in place.
func Restore(binary string) error {
	if err := os.Rename(Previous(binary), binary); err != nil {
		return err
	}
	return syncDir(filepath.Dir(binary))
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
