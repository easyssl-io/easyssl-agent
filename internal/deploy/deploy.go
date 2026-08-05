// Package deploy executes one Deployment on this host: it fetches the work the
// Server queued, hands the material and the resolved settings to the owning
// Plugin over stdio, and reports what came back.
//
// The private key never crosses the wire in either direction. It was generated
// here and lives in this host's keystore; the Server sends only the certificate
// and the chain, and this package reads the key locally by the certificate id.
// That is also why a Deployment can only ever run on the Client that holds the
// key.
package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/easyssl-io/easyssl-client/internal/commands"
	"github.com/easyssl-io/easyssl-client/internal/keystore"
	"github.com/easyssl-io/easyssl-client/internal/pluginmgr"
	"github.com/easyssl-io/easyssl-client/internal/serverapi"
	"github.com/easyssl-io/easyssl-contract/plugincontract"
	"github.com/easyssl-io/easyssl-contract/wire"
)

// runTimeout bounds one Plugin execution. A reload script may pull a container
// image or wait on a slow service, so this is generous; it sits far below the
// command TTL so a hung script is reported as a failed Deployment rather than
// swallowing the whole wait.
const runTimeout = 10 * time.Minute

// maxOutput bounds what is reported back. A runaway script can print without
// limit and the Server stores this text, so it is truncated here rather than
// there: head and tail are what a reader needs, and the marker says what was
// dropped instead of leaving a silently short transcript.
const maxOutput = 256 << 10

// hostLock serializes Plugin execution across this process (FR-011a). Two
// Deployments landing together would otherwise write and reload the same
// service at the same time, and the second could reload a half-written file.
// Queued Deployments simply wait here and stay pending.
var hostLock sync.Mutex

// API is the slice of the Server wrapper this handler uses, narrowed so a test
// can stand in for the Server.
type API interface {
	DeploymentWork(ctx context.Context, token, deploymentID string) (wire.DeploymentWork, error)
	ReportDeploymentResult(ctx context.Context, token, deploymentID string, res wire.DeploymentResult) error
}

var _ API = (*serverapi.Client)(nil)

// Plugins is the installed-Plugin lookup, narrowed the same way.
type Plugins interface {
	Find(id string) (pluginmgr.Installed, bool, error)
}

var _ Plugins = (*pluginmgr.Manager)(nil)

// loadKey is keystore.Load, indirected only so tests need no root and no real
// keystore. Load never generates: a certificate whose key this host does not
// hold cannot be installed here.
var loadKey = keystore.Load

// New returns the handler for wire.CommandDeploy.
func New(api API, plugins Plugins, token string, logger *slog.Logger) commands.Handler {
	return func(ctx context.Context, cmd wire.Command) error {
		work, err := api.DeploymentWork(ctx, token, cmd.RefID)
		if err != nil {
			var apiErr *serverapi.APIError
			if errors.As(err, &apiErr) && apiErr.Status == 404 {
				// Not this Client's, or gone. No retry changes that: a stale
				// instruction, discarded and acked.
				logger.Warn("deployment not found; discarding command", "deployment", cmd.RefID)
				return nil
			}
			return err // transport or Server trouble: leave pending, retry later
		}
		// Already finished, which is what a re-delivered command looks like.
		// Acked without running: the Server has its result and installing again
		// would be a second Deployment nobody asked for.
		if work.State != wire.DeploymentStatePending {
			logger.Info("deployment already finished; acking without running",
				"deployment", cmd.RefID, "state", work.State)
			return nil
		}

		res := run(ctx, plugins, work, logger)
		if err := api.ReportDeploymentResult(ctx, token, cmd.RefID, res); err != nil {
			var apiErr *serverapi.APIError
			if errors.As(err, &apiErr) && apiErr.Code == wire.CodeDeploymentFinished {
				// Something already reported this one, which is the shape of a
				// Client that died between acting and reporting. Done either way.
				logger.Info("deployment already reported; acking", "deployment", cmd.RefID)
				return nil
			}
			// The Plugin ran but the Server does not know. Left pending so the
			// report is retried; the fetch above will then find it terminal, or
			// the Plugin runs again, which for an install is the same work.
			return fmt.Errorf("reporting the deployment result: %w", err)
		}
		logger.Info("deployment finished", "deployment", cmd.RefID, "ok", res.OK)
		return nil
	}
}

// run performs one Deployment and always returns a result describing the
// attempt: every failure here is this Deployment failing rather than the Client
// failing, so it is reported rather than retried.
func run(ctx context.Context, plugins Plugins, work wire.DeploymentWork, logger *slog.Logger) wire.DeploymentResult {
	installed, found, err := plugins.Find(work.PluginID)
	switch {
	case err != nil:
		return failed("", fmt.Sprintf("could not read this host's plugin record: %v", err))
	case !found:
		// FR-005a: the Plugin left the host, or was never installed here. Name
		// it, because the fix is to install it and the Server cannot know that.
		return failed("", fmt.Sprintf(
			"the %s plugin is not installed on this host, so nothing could install this certificate.\n"+
				"Install it there and deploy again:\n    easyssl-client plugin install %s",
			work.PluginID, work.PluginID))
	}

	key, err := loadKey(work.CertificateID)
	if err != nil {
		if errors.Is(err, keystore.ErrNoKey) {
			return failed(installed.Version, fmt.Sprintf(
				"this host holds no private key for %s, so it cannot install it. "+
					"A certificate is installable only by the Client that generated its key.",
				work.CertificateID))
		}
		return failed(installed.Version, fmt.Sprintf("reading the private key: %v", err))
	}
	keyPEM, err := keystore.EncodePrivateKeyPEM(key)
	if err != nil {
		return failed(installed.Version, fmt.Sprintf("encoding the private key: %v", err))
	}

	// The run's own directory, created here and removed here whatever happens.
	// A Plugin that materializes files puts them in it, so a Plugin this Client
	// had to kill cannot leave key material behind.
	workDir, err := os.MkdirTemp("", "easyssl-deploy-")
	if err != nil {
		return failed(installed.Version, fmt.Sprintf("preparing the working directory: %v", err))
	}
	defer func() {
		if err := os.RemoveAll(workDir); err != nil {
			logger.Error("could not remove the deployment working directory",
				"dir", workDir, "err", err)
		}
	}()

	req := plugincontract.InstallRequest{
		ContractVersion: plugincontract.ContractVersion,
		CertificatePem:  work.CertificatePem,
		ChainPem:        work.ChainPem,
		PrivateKeyPem:   keyPEM,
		WorkDir:         workDir,
		Settings:        work.Settings,
	}

	// One Plugin at a time on this host (FR-011a).
	hostLock.Lock()
	defer hostLock.Unlock()

	out, err := runPlugin(ctx, installed.Path, req)
	if err != nil {
		return failed(installed.Version, err.Error())
	}
	return wire.DeploymentResult{
		OK:            out.OK,
		PluginVersion: installed.Version,
		Output:        truncate(out.Output),
	}
}

// runPlugin executes the Plugin's install operation: the operation name on
// argv, the request on stdin, the response on stdout.
func runPlugin(ctx context.Context, path string, req plugincontract.InstallRequest) (plugincontract.InstallResponse, error) {
	var out plugincontract.InstallResponse
	body, err := json.Marshal(req)
	if err != nil {
		return out, fmt.Errorf("encoding the install request: %w", err)
	}

	rctx, cancel := context.WithTimeout(ctx, runTimeout)
	defer cancel()

	// #nosec G204 -- path comes from this Client's own record of what it
	// installed, not from the Server or the request.
	cmd := exec.Command(path, plugincontract.OpInstall)
	cmd.Stdin = bytesReader(body)
	// Its own process group, so the kill below reaches whatever the reload
	// command started. A script that backgrounds a process would otherwise
	// outlive the timeout and hold nothing accountable.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdout, runErr := runBounded(rctx, cmd)
	if runErr != nil {
		return out, runErr
	}
	if err := json.Unmarshal(stdout, &out); err != nil {
		// A Plugin that answered with something unparseable failed, and what it
		// did say is the only evidence of why.
		return out, fmt.Errorf("the plugin's install output is not JSON: %w\noutput:\n%s", err, truncate(string(stdout)))
	}
	return out, nil
}

// runBounded runs cmd, killing its whole process group if the context expires,
// and returns stdout. Stderr is the Plugin's own diagnostics, kept only to
// explain a failure.
func runBounded(ctx context.Context, cmd *exec.Cmd) ([]byte, error) {
	var stdout, stderr limitedBuffer
	stdout.max, stderr.max = maxOutput, maxOutput
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("could not start the plugin: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case <-ctx.Done():
		// Negative pid signals the group, which is what reaches anything the
		// reload command started.
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		<-done
		return nil, fmt.Errorf("the plugin did not finish within %s and was killed.\noutput so far:\n%s",
			runTimeout, truncate(stdout.String()+stderr.String()))
	case err := <-done:
		if err != nil {
			return nil, fmt.Errorf("the plugin exited with an error: %w\n%s", err, truncate(stderr.String()))
		}
		return stdout.Bytes(), nil
	}
}

func failed(pluginVersion, output string) wire.DeploymentResult {
	return wire.DeploymentResult{OK: false, PluginVersion: pluginVersion, Output: truncate(output)}
}

// truncate bounds reported text, keeping the head and the tail around a marker
// naming what was dropped: the start says what the script set out to do and the
// end says how it ended, and the middle of a runaway loop says neither.
func truncate(s string) string {
	if len(s) <= maxOutput {
		return s
	}
	const marker = "\n… %d bytes omitted by the Client …\n"
	head := maxOutput / 2
	tail := maxOutput - head - len(marker) - 8
	return s[:head] + fmt.Sprintf(marker, len(s)-head-tail) + s[len(s)-tail:]
}

// limitedBuffer collects output up to a bound, so a Plugin printing without
// limit cannot exhaust this Client's memory while the Server would only have
// stored a truncated copy anyway.
type limitedBuffer struct {
	buf []byte
	max int
	// dropped counts what was discarded, so the truncation is reported rather
	// than silent.
	dropped int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	room := b.max - len(b.buf)
	if room <= 0 {
		b.dropped += len(p)
		return len(p), nil
	}
	if len(p) > room {
		b.buf = append(b.buf, p[:room]...)
		b.dropped += len(p) - room
		return len(p), nil
	}
	b.buf = append(b.buf, p...)
	return len(p), nil
}

func (b *limitedBuffer) Bytes() []byte { return b.buf }

func (b *limitedBuffer) String() string {
	if b.dropped == 0 {
		return string(b.buf)
	}
	return fmt.Sprintf("%s\n… %d further bytes discarded by the Client …\n", b.buf, b.dropped)
}

// bytesReader avoids importing bytes for one call.
func bytesReader(b []byte) *bytesReaderT { return &bytesReaderT{b: b} }

type bytesReaderT struct {
	b []byte
	i int
}

func (r *bytesReaderT) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}
