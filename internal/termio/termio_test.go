package termio

import (
	"bufio"
	"context"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestReadLine(t *testing.T) {
	line, err := ReadLine(bufio.NewReader(strings.NewReader("1\nrest\n")))
	if err != nil || line != "1\n" {
		t.Fatalf("ReadLine = %q, %v", line, err)
	}
}

// helperEnv makes the test binary, run again as a child, block in ReadLine
// the way a prompt does, with SIGINT caught as main catches it.
const helperEnv = "TERMIO_READLINE_HELPER"

func TestMain(m *testing.M) {
	if os.Getenv(helperEnv) == "1" {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		_ = ctx
		os.Stdout.WriteString("ready\n")
		_, _ = ReadLine(bufio.NewReader(os.Stdin))
		os.Exit(0) // only if Ctrl+C were swallowed and a line arrived
	}
	os.Exit(m.Run())
}

// Ctrl+C at a prompt ends the process by SIGINT even though the program
// catches SIGINT to cancel its work, which is what swallowed it before.
func TestCtrlCAtAPromptEndsTheProcess(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), helperEnv+"=1")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if line, _ := bufio.NewReader(out).ReadString('\n'); line != "ready\n" {
		t.Fatalf("helper said %q", line)
	}
	time.Sleep(200 * time.Millisecond) // into the read
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatalf("the helper exited with %v, not killed by SIGINT", err)
		}
		if ws, ok := exit.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGINT {
			t.Fatalf("the helper ended with %v, not by SIGINT", exit)
		}
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("Ctrl+C at the prompt was swallowed: the helper is still waiting for a line")
	}
}
