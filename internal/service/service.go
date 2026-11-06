// Package service installs and manages the Agent's one long-running service
// under whichever init system the host runs: systemd, OpenRC, runit, sysvinit
// or BusyBox init. Re-running the installer refreshes the one service and
// restarts it onto the updated binary rather than adding a second. Root-only.
//
// The init system is detected, never asked for: the one running as PID 1 is the
// one that will start the Agent at the next boot, and an operator naming
// another would install a service nothing runs. A host running none of the five
// is refused with the command to run under whatever supervises it.
//
// Every backend has two separate steps, because the installer waits for the
// operator to authorize this host before it wants a second process polling the
// Server: Install writes and enables the service without running it, and Start
// runs it, restarting it when it already runs so a first install and a
// reinstall converge on the same state.
//
// Only systemd restarts the Agent under a policy and collects its output in a
// journal. OpenRC's supervise-daemon, runit and BusyBox's respawn restart it
// too; sysvinit does not, which its status hint says. Outside systemd the
// output goes to a log file named in the hints.
package service

import (
	"fmt"
	"github.com/easyssl-io/easyssl-contract/wire"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/easyssl-io/easyssl-agent/internal/msg"
)

// BinaryPath is where the installer places the Agent binary, which uninstall
// removes last.
const BinaryPath = wire.AgentBinaryPath

const (
	name    = "easyssl-agent"
	logPath = "/var/log/easyssl-agent.log"
)

var ErrNotRoot = msg.Err.T("service.not_root", "must run as root to manage the Agent's service")

// ErrUnsupportedInit is returned on a host whose init system is none of the
// five. The Agent still runs there, under whatever the operator uses.
var ErrUnsupportedInit = msg.Err.T("service.unsupported_init", "this host's init system is not systemd, OpenRC, runit, sysvinit or BusyBox init, so the Agent cannot install its service; run `{binary} run` under the supervisor this host uses", "binary", BinaryPath)

type file struct {
	path    string
	content string
	mode    os.FileMode
}

// backend is one init system: what it writes, and the commands that enable,
// start, stop and query what it wrote. Every command is run with run, so a
// test sees each one instead of executing it.
type backend struct {
	// Init names the init system, for messages.
	Init string
	// Name is the service's name under it, as the operator would type it.
	Name string
	// StatusHint and LogHint are the commands an operator uses to see it.
	StatusHint string
	LogHint    string

	files     []file
	install   func(b *backend) error
	start     func(b *backend) error
	uninstall func(b *backend) error
	state     func(b *backend) string
	// marker is the file whose presence means the service is installed, or
	// installed decides it where no file of its own exists.
	marker    string
	installed func() bool
}

// Hooks for tests: the filesystem root every path is under, the command
// runner, the running processes, and the effective user id.
var (
	root = "/"
	run  = func(name string, args ...string) error {
		cmd := exec.Command(name, args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	output = func(name string, args ...string) (string, error) {
		out, err := exec.Command(name, args...).Output()
		return strings.TrimSpace(string(out)), err
	}
	euid = os.Geteuid
)

func path(p string) string { return filepath.Join(root, p) }

func exists(p string) bool {
	_, err := os.Lstat(path(p))
	return err == nil
}

func onPath(cmd string) bool {
	for _, dir := range []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
		if exists(filepath.Join(dir, cmd)) {
			return true
		}
	}
	return false
}

// pid1 names the program running as PID 1: its executable's base name, or its
// command name when the executable cannot be read.
func pid1() string {
	if exe, err := os.Readlink(path("/proc/1/exe")); err == nil {
		return filepath.Base(exe)
	}
	if comm, err := os.ReadFile(path("/proc/1/comm")); err == nil {
		return strings.TrimSpace(string(comm))
	}
	return ""
}

// Detect returns the backend for the init system this host runs, checking from
// the most specific marker to the least: each of the first three leaves a
// directory under /run that nothing else creates, BusyBox is recognized by PID
// 1's executable, and sysvinit is what an `init` PID 1 with /etc/init.d is once
// the others are ruled out.
func Detect() (*backend, error) {
	switch {
	case exists("/run/systemd/system"):
		return systemd(), nil
	case exists("/run/openrc"):
		return openrc(), nil
	case exists("/run/runit") || pid1() == "runit" || pid1() == "runit-init":
		return runit()
	case pid1() == "busybox":
		return busybox(), nil
	case pid1() == "init" && exists("/etc/init.d") && onPath("start-stop-daemon"):
		return sysvinit()
	}
	return nil, ErrUnsupportedInit
}

func requireRoot() error {
	if euid() != 0 {
		return ErrNotRoot
	}
	return nil
}

// Install writes the service's files and enables it at boot without running
// it. Idempotent.
func Install() error {
	if err := requireRoot(); err != nil {
		return err
	}
	b, err := Detect()
	if err != nil {
		return err
	}
	for _, f := range b.files {
		if err := os.MkdirAll(filepath.Dir(path(f.path)), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path(f.path), []byte(f.content), f.mode); err != nil {
			return msg.Err.T("service.write_failed", "writing {path}: {err}", "path", f.path, "err", err)
		}
		// WriteFile keeps an existing file's mode; a run script must be
		// executable whatever an earlier version left.
		if err := os.Chmod(path(f.path), f.mode); err != nil {
			return err
		}
	}
	if b.install != nil {
		return b.install(b)
	}
	return nil
}

// Start runs the service on the installed binary, restarting it if it runs.
func Start() error {
	if err := requireRoot(); err != nil {
		return err
	}
	b, err := Detect()
	if err != nil {
		return err
	}
	return b.start(b)
}

// Uninstall stops and disables the service and removes its files. A missing
// or already stopped service is not an error, so uninstall works on a
// partially installed host.
func Uninstall() error {
	if err := requireRoot(); err != nil {
		return err
	}
	b, err := Detect()
	if err != nil {
		return err
	}
	if b.uninstall != nil {
		if err := b.uninstall(b); err != nil {
			return err
		}
	}
	for _, f := range b.files {
		if err := os.Remove(path(f.path)); err != nil && !os.IsNotExist(err) {
			return msg.Err.T("service.remove_failed", "removing {path}: {err}", "path", f.path, "err", err)
		}
	}
	return nil
}

func Installed() bool {
	b, err := Detect()
	if err != nil {
		return false
	}
	if b.installed != nil {
		return b.installed()
	}
	return exists(b.marker)
}

// State reports the service's state: active, inactive, failed and so on as
// the init system words it, or "unknown" when it cannot be asked.
func State() string {
	b, err := Detect()
	if err != nil {
		return "unknown"
	}
	if s := b.state(b); s != "" {
		return s
	}
	return "unknown"
}

// Describe returns the service's name and the two hints for the host's init
// system, for the installer's messages and `easyssl-agent status`. On an
// unsupported init system it gives the systemd wording, since the refusal
// itself says what to do.
func Describe() (serviceName, statusHint, logHint string) {
	b, err := Detect()
	if err != nil {
		b = systemd()
	}
	return b.Name, b.StatusHint, b.LogHint
}
