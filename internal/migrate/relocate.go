package migrate

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/easyssl-io/easyssl-agent/internal/msg"
	"github.com/easyssl-io/easyssl-agent/internal/plugintrace"
	"github.com/easyssl-io/easyssl-contract/plugincontract"
)

// relocateTimeout bounds one `relocate`, which tests and reloads a web server
// as a Deployment does, under the same bound.
const relocateTimeout = 10 * time.Minute

// runRelocate runs a Plugin's `relocate`: the operation on argv, the request
// on stdin, and an answer in the exit status and what it printed, as deploy
// is run. Its own process group, killed whole on the timeout, so a reload it
// started does not outlive it. stderr is the Plugin's diagnostics, shown only
// when it failed, since then they may be all there is to go on.
func runRelocate(ctx context.Context, path string, req plugincontract.RelocateRequest, logger *slog.Logger) (string, int, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return "", -1, err
	}
	rctx, cancel := context.WithTimeout(ctx, relocateTimeout)
	defer cancel()
	// #nosec G204 -- path comes from this Agent's own Plugin directory, and the
	// operation is the contract's constant.
	cmd := exec.CommandContext(rctx, path, plugincontract.OpRelocate)
	cmd.Stdin = strings.NewReader(string(body))
	// The Plugin speaks the language EASYSSL_LANG names, and `sudo` drops the
	// variable, so the language this run speaks is passed on explicitly.
	cmd.Env = append(os.Environ(), "EASYSSL_LANG="+msg.Language())
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 5 * time.Second
	captured := &plugintrace.Capture{Max: plugintrace.MaxPluginOutput}
	stdout, stderr := captured.Writer(plugintrace.StreamStdout), captured.Writer(plugintrace.StreamStderr)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	started := time.Now()
	runErr := cmd.Run()
	stdout.Flush()
	stderr.Flush()
	code := -1
	if cmd.ProcessState != nil {
		code = cmd.ProcessState.ExitCode()
	}
	plugintrace.Record(logger, plugintrace.Exchange{
		Op: plugincontract.OpRelocate, Path: path, Args: []string{plugincontract.OpRelocate},
		Stdin:  body,
		Stdout: []byte(captured.Text(plugintrace.StreamStdout)), Stderr: []byte(captured.Text(plugintrace.StreamStderr)),
		ExitCode: code, Duration: time.Since(started), Err: runErr,
	})
	out := captured.Text(plugintrace.StreamStdout)
	if errors.Is(runErr, exec.ErrWaitDelay) {
		runErr = nil
	}
	if runErr == nil {
		return out, code, nil
	}
	if diag := strings.TrimSpace(captured.Text(plugintrace.StreamStderr)); diag != "" {
		out = strings.TrimRight(out, "\n") + "\n" + diag
	}
	if rctx.Err() != nil {
		return out, code, msg.Err.T("migrate.relocate.killed", "it did not finish within {timeout} and was killed", "timeout", relocateTimeout)
	}
	if code >= 0 {
		return out, code, msg.Err.T("migrate.relocate.exited", "its output says why")
	}
	return out, code, runErr
}
