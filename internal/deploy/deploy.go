// Package deploy executes one Deployment on this host: it fetches the work the
// Server queued, hands the material and the resolved settings to the owning
// Plugin over stdio, and reports what came back.
//
// The private key never crosses the wire in either direction. It was generated
// here and stays in this host's keystore; the Server sends only the certificate
// and the chain, and this package reads the key locally. That is also why a
// Deployment can only run on the Agent that holds the key.
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

	"github.com/easyssl-io/easyssl-agent/internal/commands"
	"github.com/easyssl-io/easyssl-agent/internal/keystore"
	"github.com/easyssl-io/easyssl-agent/internal/msg"
	"github.com/easyssl-io/easyssl-agent/internal/pluginmgr"
	"github.com/easyssl-io/easyssl-agent/internal/plugintrace"
	"github.com/easyssl-io/easyssl-agent/internal/serverapi"
	"github.com/easyssl-io/easyssl-contract/l10n"
	"github.com/easyssl-io/easyssl-contract/plugincontract"
	"github.com/easyssl-io/easyssl-contract/wire"
)

// runTimeout bounds one Plugin execution. It is generous because a reload
// script may pull a container image or wait on a slow service, and far below
// the command TTL so a hung script is reported as a failed Deployment rather
// than swallowing the whole wait.
const runTimeout = 10 * time.Minute

// maxOutput bounds what is reported back. A runaway script can print without
// limit and the Server stores this text, so it is truncated here, keeping head
// and tail around a marker that says what was dropped. It equals the bound the
// Agent collects a Plugin's output at: collecting more than the Server would
// keep buys nothing.
const maxOutput = plugintrace.MaxPluginOutput

// hostLock serializes Plugin execution across this process. Two Deployments
// landing together could otherwise write and reload the same service at once,
// and the second could reload a half-written file. Queued Deployments wait here
// and stay pending.
var hostLock sync.Mutex

// API is the slice of the Server wrapper this handler uses, so a test can stand
// in for the Server.
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
// hold under the name the Server gave cannot be installed here.
var loadKey = keystore.Load

// New returns the handler for wire.CommandDeploy.
func New(api API, plugins Plugins, token string, logger *slog.Logger) commands.Handler {
	return func(ctx context.Context, cmd wire.Command) error {
		work, err := api.DeploymentWork(ctx, token, cmd.RefID)
		if err != nil {
			var apiErr *serverapi.APIError
			if errors.As(err, &apiErr) && apiErr.Code == wire.CodeDeploymentNotFound {
				// Not this Agent's, or gone. No retry changes that: a stale
				// instruction, discarded and acked. Any other 404 is retried.
				logger.Warn("deployment not found; discarding command", "deployment", cmd.RefID)
				return nil
			}
			return err // transport or Server trouble: leave pending, retry later
		}
		// Already finished, which is what a re-delivered command looks like. Acked
		// without running: installing again would be a second Deployment nobody asked
		// for.
		if work.State != wire.DeploymentStatePending {
			logger.Info("deployment already finished; acking without running",
				"deployment", cmd.RefID, "state", work.State)
			return nil
		}

		res := run(ctx, plugins, work, logger)
		if err := api.ReportDeploymentResult(ctx, token, cmd.RefID, res); err != nil {
			var apiErr *serverapi.APIError
			if errors.As(err, &apiErr) && apiErr.Code == wire.CodeDeploymentFinished {
				// Something already reported this one, which is the shape of an
				// Agent that died between acting and reporting. Done either way.
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

// run performs one Deployment and always returns a result: every failure here
// is the Deployment failing, not the Agent, so it is reported rather than
// retried.
//
// Each sentence the Agent reports is a message in every language (msg.Text),
// because it is read in the web console by people who do not share the host's
// language. An operating system's error inside one stays as produced.
func run(ctx context.Context, plugins Plugins, work wire.DeploymentWork, logger *slog.Logger) wire.DeploymentResult {
	installed, found, err := plugins.Find(work.PluginID)
	switch {
	case err != nil:
		return failed("", msg.Text("deploy.plugin_record_unreadable",
			"could not read this host's Plugin record: {err}", "err", err))
	case !found:
		// The Plugin left the host, or was never installed here. Name it, because
		// the fix is to install it and the Server cannot know that.
		return failed("", msg.Text("deploy.plugin_not_installed",
			"the {plugin} Plugin is not installed on this host, so nothing could install this Certificate.\n"+
				"Install it there and deploy again:\n    easyssl-agent plugin install {plugin}",
			"plugin", work.PluginID))
	}

	// That the record says the Plugin is installed does not mean the artifact is
	// still there and executable. Checked before the key is read, so the message
	// names the Plugin and the fix rather than the operating system's words about
	// a failed exec.
	if err := runnable(installed.Path); err != nil {
		return failed(installed.Version, msg.Text("deploy.plugin_not_runnable",
			"the {plugin} Plugin is recorded on this host but cannot be run ({err}), "+
				"so nothing could install this Certificate.\n"+
				"Install it there again and deploy again:\n    easyssl-agent plugin install {plugin}",
			"plugin", work.PluginID, "err", err))
	}

	// The key is the one the Server named, never one this host picks: the
	// link between a certificate and its key is the Server's record, and a
	// host holds only keys named by their own fingerprint.
	if work.KeyFingerprint == "" {
		return failed(installed.Version, msg.Text("deploy.no_key_named",
			"the Server named no private key for {certificate}, so nothing could install it. "+
				"The Server is older than this Agent.", "certificate", work.CertificateID))
	}
	key, err := loadKey(work.KeyFingerprint)
	if err != nil {
		if errors.Is(err, keystore.ErrNoKey) {
			return failed(installed.Version, msg.Text("deploy.no_key",
				"this host holds no private key {fingerprint} for {certificate}, so it cannot install it. "+
					"A Certificate is installable only by an Agent holding its key.",
				"fingerprint", work.KeyFingerprint, "certificate", work.CertificateID))
		}
		return failed(installed.Version, msg.Text("deploy.key_unreadable",
			"reading the private key: {err}", "err", err))
	}
	keyPEM, err := keystore.EncodePrivateKeyPEM(key)
	if err != nil {
		return failed(installed.Version, msg.Text("deploy.key_not_encoded",
			"encoding the private key: {err}", "err", err))
	}

	// The run's own directory, created here and removed here whatever happens.
	// A Plugin that materializes files puts them in it, so a Plugin this Agent
	// had to kill cannot leave key material behind.
	workDir, err := os.MkdirTemp("", "easyssl-deploy-")
	if err != nil {
		return failed(installed.Version, msg.Text("deploy.workdir",
			"preparing the working directory: {err}", "err", err))
	}
	defer func() {
		if err := os.RemoveAll(workDir); err != nil {
			logger.Error("could not remove the deployment working directory",
				"dir", workDir, "err", err)
		}
	}()

	req := plugincontract.DeployRequest{
		ContractVersion: plugincontract.ContractVersion,
		CertificatePem:  work.CertificatePem,
		ChainPem:        work.ChainPem,
		PrivateKeyPem:   keyPEM,
		WorkDir:         workDir,
		Settings:        work.Settings,
	}

	hostLock.Lock()
	defer hostLock.Unlock()

	run, err := runPlugin(ctx, installed.Path, req, logger,
		"deployment", work.ID, "certificate", work.CertificateID,
		"plugin", installed.ID, "plugin_version", installed.Version)
	result := wire.DeploymentResult{
		OK:            succeeded(err, run),
		PluginVersion: installed.Version,
		PluginRun:     run,
	}
	if err != nil {
		// The Agent's sentence and the process's facts are never merged: what the
		// Plugin printed is on `run`, so this says only what the Agent concluded. It
		// goes through report like every other message, because the error quotes the
		// operating system's own words about the run.
		result.AgentMessage = report(msg.TextOf(err))
	}
	return result
}

// succeeded is the whole of how this Agent decides a Deployment worked: the
// Plugin's process ended, and it ended with status 0.
//
// It is one function so that no struct literal can omit the field and silently
// take Go's zero. The error is checked as well as the status because a path
// that fails with a zero status (a check after the run, a decode) must not
// count as success, and because a run that never started has no status of the
// Plugin's own: the -1 standing in for one must not be read as though the
// Plugin chose it.
func succeeded(err error, run *wire.PluginRun) bool {
	return err == nil && run != nil && run.ExitStatus == 0
}

// runPlugin executes the Plugin's deploy operation: the operation name on argv,
// the request on stdin, the response on stdout.
//
// The whole exchange goes to plugintrace, which does nothing unless the
// operator turned it on. Nothing else shows it: the Server gets only the
// Plugin's own account of itself, so an argument the Agent got wrong, or a
// Plugin failing before it printed anything, leaves no evidence anywhere else.
func runPlugin(ctx context.Context, path string, req plugincontract.DeployRequest, logger *slog.Logger, attrs ...any) (*wire.PluginRun, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, msg.Err.T("deploy.request_not_encoded", "encoding the deploy request: {err}", "err", err)
	}

	rctx, cancel := context.WithTimeout(ctx, runTimeout)
	defer cancel()

	// #nosec G204 -- path comes from this Agent's own record of what it
	// installed, not from the Server or the request.
	cmd := exec.Command(path, plugincontract.OpDeploy)
	cmd.Stdin = bytesReader(body)
	// Its own process group, so the kill below reaches whatever the reload
	// command started. A script that backgrounds a process would otherwise
	// outlive the timeout and hold nothing accountable.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	started := time.Now()
	captured, code, runErr := runBounded(rctx, cmd)
	elapsed := time.Since(started)
	plugintrace.Record(logger, plugintrace.Exchange{
		Op: plugincontract.OpDeploy, Path: path, Args: []string{plugincontract.OpDeploy},
		Stdin:    body,
		Stdout:   []byte(captured.Text(plugintrace.StreamStdout)),
		Stderr:   []byte(captured.Text(plugintrace.StreamStderr)),
		ExitCode: code, Duration: elapsed, Err: runErr, Attrs: attrs,
	})

	// Reported whatever happened, including a run that was killed. Nothing here
	// interprets what the Plugin wrote: the exit status is the answer, and the two
	// streams are what it said while arriving at it.
	run := &wire.PluginRun{
		ExitStatus: code, DurationMs: elapsed.Milliseconds(),
		Output:      chunks(captured),
		StdoutBytes: captured.Produced(plugintrace.StreamStdout),
		StderrBytes: captured.Produced(plugintrace.StreamStderr),
	}
	return run, runErr
}

// chunks converts the capture to the wire's shape, redacting as it goes. A
// Plugin that echoes its request or dumps its environment on failure is how a
// private key reaches its own output, and this is the last point before that
// output leaves the host.
func chunks(c *plugintrace.Capture) []wire.OutputChunk {
	recorded := c.Chunks()
	if len(recorded) == 0 {
		return nil
	}
	out := make([]wire.OutputChunk, 0, len(recorded))
	// One redactor per stream, carried across that stream's chunks: a key the
	// Plugin prints on stdout is split into several chunks whenever a stderr
	// line lands in the middle of it, and the continuation has no begin marker.
	redactors := map[string]*plugintrace.KeyRedactor{}
	for _, ch := range recorded {
		r := redactors[ch.Stream]
		if r == nil {
			r = &plugintrace.KeyRedactor{}
			redactors[ch.Stream] = r
		}
		out = append(out, wire.OutputChunk{Stream: ch.Stream, Text: truncate(r.Redact(ch.Text))})
	}
	return out
}

// runBounded runs cmd, killing its whole process group if the context expires.
// It returns everything the run produced (stdout, stderr and the exit code)
// whether or not it succeeded, because the caller records the exchange either
// way and a failed run is the one worth reading.
func runBounded(ctx context.Context, cmd *exec.Cmd) (captured *plugintrace.Capture, exitCode int, err error) {
	captured = &plugintrace.Capture{Max: maxOutput}
	stdout, stderr := captured.Writer(plugintrace.StreamStdout), captured.Writer(plugintrace.StreamStderr)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	defer func() {
		// A command killed mid-line still wrote something worth reading.
		stdout.Flush()
		stderr.Flush()
	}()

	if startErr := cmd.Start(); startErr != nil {
		return captured, -1, msg.Err.T("deploy.plugin_not_started", "could not start the Plugin: {err}", "err", startErr)
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
		return captured, -1, msg.Err.T("deploy.plugin_killed",
			"the Plugin did not finish within {timeout} and was killed", "timeout", runTimeout)
	case waitErr := <-done:
		code := cmd.ProcessState.ExitCode()
		if waitErr != nil {
			// A Plugin that exits with a status has said why in its output, which
			// the reader sees beside this sentence; Go's "exit status 1" alone
			// read as though nothing had explained it. A process ended by a
			// signal has no status and may have said nothing.
			if code >= 0 {
				return captured, code, msg.Err.T("deploy.plugin_exited",
					"the Plugin exited with status {status}; its output says why", "status", code)
			}
			return captured, code, msg.Err.T("deploy.plugin_ended", "the Plugin ended without an exit status: {err}", "err", waitErr)
		}
		return captured, code, nil
	}
}

// runnable reports whether the recorded artifact is still a file this Agent
// could execute. The record and the file disagree when someone removes it by
// hand or an upgrade leaves it unexecutable.
//
// Its error is quoted inside the Agent's sentence about the Plugin: its own two
// findings are messages, and the operating system's error is left as produced.
func runnable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return msg.Err.T("deploy.artifact.is_directory", "it is a directory")
	}
	if info.Mode().Perm()&0o100 == 0 {
		return msg.Err.T("deploy.artifact.not_executable", "it is not executable (mode {mode})",
			"mode", fmt.Sprintf("%o", info.Mode().Perm()))
	}
	return nil
}

// failed builds a result for an attempt in which no Plugin ran: it was not
// installed, its artifact could not be executed, or this host holds no key. The
// absent PluginRun is the fact that nothing ran.
//
// It still goes through report, because one of these messages quotes a path and
// a redaction that applies only to some of them is one somebody forgets.
func failed(pluginVersion string, message l10n.Text) wire.DeploymentResult {
	return wire.DeploymentResult{OK: false, PluginVersion: pluginVersion, AgentMessage: report(message)}
}

// report prepares the Agent's message for the Server, one language at a time.
// In each, the key is removed first and the result bounded afterwards, because
// truncating first can cut a key's end marker off and leave the head of one
// unredactable. Every language goes through it because each quotes the same
// paths and errors, and one left out would carry what the others had removed.
func report(message l10n.Text) l10n.Text {
	out := make(l10n.Text, len(message))
	for lang, s := range message {
		out[lang] = truncate(plugintrace.RedactPrivateKeys(s))
	}
	return out
}

// truncate bounds reported text, keeping the head and the tail around a marker
// naming what was dropped: the start says what the script set out to do and the
// end says how it ended, and the middle of a runaway loop says neither.
func truncate(s string) string {
	if len(s) <= maxOutput {
		return s
	}
	const marker = "\n… %d bytes omitted by the Agent …\n"
	head := maxOutput / 2
	tail := maxOutput - head - len(marker) - 8
	return s[:head] + fmt.Sprintf(marker, len(s)-head-tail) + s[len(s)-tail:]
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
