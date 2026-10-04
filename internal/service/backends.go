package service

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/easyssl-io/easyssl-agent/internal/msg"
)

// systemd: one unit, Type=notify so the Agent can set the line `systemctl
// status` prints under it (see sdnotify).
//
// The unit orders itself after network.target and not network-online.target.
// Reaching the second means running a wait-online helper, and on a host whose
// interface that helper does not recognize as configured, which includes a
// static address with no network manager and every container whose address
// the runtime set up, it blocks for its full two-minute timeout after every
// boot. A network that is not ready yet costs this poll loop one failed
// attempt and RestartSec instead.
func systemd() *backend {
	const unit = name + ".service"
	unitPath := "/etc/systemd/system/" + unit
	return &backend{
		Init:       "systemd",
		Name:       unit,
		StatusHint: "systemctl status " + unit,
		LogHint:    "journalctl -u " + unit,
		marker:     unitPath,
		files: []file{{unitPath, `[Unit]
Description=easySSL Agent
After=network.target

[Service]
Type=notify
NotifyAccess=main
ExecStart=` + BinaryPath + ` run
Restart=on-failure
RestartSec=10
# A private /tmp, so the directory a Deployment creates for the Plugin to write
# the private key into is not shared with anything else on the host. That
# directory is already 0700 root-owned under a random name and is removed on
# every path, so this closes the class rather than a known hole. Deliberately alone: NoNewPrivileges and
# ProtectSystem would also reach a Plugin's reload command, which may call sudo
# or systemctl, so they need their own decision.
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
`, 0o644}},
		install: func(*backend) error {
			if err := run("systemctl", "daemon-reload"); err != nil {
				return err
			}
			return run("systemctl", "enable", unit)
		},
		start: func(*backend) error { return run("systemctl", "restart", unit) },
		uninstall: func(*backend) error {
			_ = run("systemctl", "disable", "--now", unit) // best effort: may be absent
			return nil
		},
		state: func(*backend) string {
			// `systemctl is-active` exits non-zero for every state but
			// active, so the printed word is the answer.
			s, _ := output("systemctl", "is-active", unit)
			return s
		},
	}
}

// OpenRC: an openrc-run script under supervise-daemon, which restarts the
// Agent when it exits. `use net` rather than `need net`: a host, or a
// container, with no net service would otherwise never start it.
func openrc() *backend {
	script := "/etc/init.d/" + name
	return &backend{
		Init:       "OpenRC",
		Name:       name,
		StatusHint: "rc-service " + name + " status",
		LogHint:    "tail " + logPath,
		marker:     script,
		files: []file{{script, `#!/sbin/openrc-run
description="easySSL Agent"
command=` + BinaryPath + `
command_args=run
supervisor=supervise-daemon
respawn_delay=10
output_log=` + logPath + `
error_log=` + logPath + `

depend() {
	use net
}
`, 0o755}},
		install: func(*backend) error { return run("rc-update", "add", name, "default") },
		start:   func(*backend) error { return run("rc-service", name, "restart") },
		uninstall: func(*backend) error {
			_ = run("rc-service", name, "stop") // best effort: may not be running
			_ = run("rc-update", "del", name, "default")
			return nil
		},
		state: func(*backend) string {
			// "status: started", "status: stopped", "status: crashed".
			s, _ := output("rc-service", name, "status")
			switch {
			case strings.Contains(s, "started"):
				return "active"
			case strings.Contains(s, "crashed"):
				return "failed"
			case s != "":
				return "inactive"
			}
			return ""
		},
	}
}

// runit: a service directory with svlogd for its output, linked into the
// directory runsvdir watches. A `down` file keeps runsv from starting it the
// moment it is linked, which is Install's promise; Start removes it.
func runit() (*backend, error) {
	svDir := "/etc/sv/" + name
	var watched string
	for _, d := range []string{"/var/service", "/etc/service", "/service", "/etc/runit/runsvdir/default"} {
		if exists(d) {
			watched = d
			break
		}
	}
	if watched == "" {
		return nil, msg.Err.T("service.runit.no_service_dir", "runit is running but none of /var/service, /etc/service, /service or /etc/runit/runsvdir/default exists, so there is nowhere to link the service: {err}", "err", ErrUnsupportedInit)
	}
	link := filepath.Join(watched, name)
	logDir := "/var/log/" + name
	sv := func(args ...string) error {
		// runsv creates supervise/ within a few seconds of the link; until
		// then sv cannot reach it.
		var err error
		for range 20 {
			if err = run("sv", args...); err == nil {
				return nil
			}
			time.Sleep(500 * time.Millisecond)
		}
		return err
	}
	return &backend{
		Init:       "runit",
		Name:       name,
		StatusHint: "sv status " + name,
		LogHint:    "tail " + logDir + "/current",
		marker:     svDir + "/run",
		files: []file{
			{svDir + "/run", "#!/bin/sh\nexec " + BinaryPath + " run 2>&1\n", 0o755},
			{svDir + "/log/run", "#!/bin/sh\nexec svlogd -tt " + logDir + "\n", 0o755},
			{svDir + "/down", "", 0o644},
		},
		install: func(*backend) error {
			if err := os.MkdirAll(path(logDir), 0o750); err != nil {
				return err
			}
			if exists(link) {
				return nil
			}
			return os.Symlink(svDir, path(link))
		},
		start: func(*backend) error {
			if err := os.Remove(path(svDir + "/down")); err != nil && !os.IsNotExist(err) {
				return err
			}
			return sv("restart", name)
		},
		uninstall: func(*backend) error {
			_ = run("sv", "down", name) // best effort: may not be running
			if err := os.Remove(path(link)); err != nil && !os.IsNotExist(err) {
				return err
			}
			// runsvdir notices the removed link within five seconds and stops
			// this service's runsv, which until then keeps writing supervise/
			// into the directory; removing it earlier left it recreated.
			waitGone("runsv", name, 10*time.Second)
			// The whole directory: runsv adds supervise/ (and log/supervise/)
			// beside the files Install wrote, and a directory left behind with
			// only those in it reads as a service that is still installed.
			return os.RemoveAll(path(svDir))
		},
		state: func(*backend) string {
			// "run: easyssl-agent: (pid 12) 30s", "down: …", "fail: …".
			s, _ := output("sv", "status", name)
			switch {
			case strings.HasPrefix(s, "run:"):
				return "active"
			case strings.HasPrefix(s, "down:"):
				return "inactive"
			case strings.HasPrefix(s, "fail:"):
				return "failed"
			}
			return ""
		},
	}, nil
}

// sysvinit: an LSB init script backgrounding the Agent with
// start-stop-daemon, enabled with whichever of update-rc.d, chkconfig and
// insserv the host has. sysvinit does not restart a service that exits, and
// the status hint says so.
func sysvinit() (*backend, error) {
	script := "/etc/init.d/" + name
	var enable, disable []string
	switch {
	case onPath("update-rc.d"):
		enable, disable = []string{"update-rc.d", name, "defaults"}, []string{"update-rc.d", "-f", name, "remove"}
	case onPath("chkconfig"):
		enable, disable = []string{"chkconfig", "--add", name}, []string{"chkconfig", "--del", name}
	case onPath("insserv"):
		enable, disable = []string{"insserv", name}, []string{"insserv", "-r", name}
	default:
		return nil, msg.Err.T("service.sysvinit.no_enabler", "sysvinit is running but none of update-rc.d, chkconfig or insserv exists to enable the service at boot: {err}", "err", ErrUnsupportedInit)
	}
	pidFile := "/run/" + name + ".pid"
	return &backend{
		Init:       "sysvinit",
		Name:       name,
		StatusHint: script + " status (sysvinit does not restart the Agent if it exits)",
		LogHint:    "tail " + logPath,
		marker:     script,
		files: []file{{script, `#!/bin/sh
### BEGIN INIT INFO
# Provides:          ` + name + `
# Required-Start:    $network $remote_fs
# Required-Stop:     $network $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: easySSL Agent
### END INIT INFO
PIDFILE=` + pidFile + `
case "$1" in
start)
	start-stop-daemon --start --quiet --oknodo --background --make-pidfile --pidfile "$PIDFILE" \
		--exec /bin/sh -- -c 'exec ` + BinaryPath + ` run >>` + logPath + ` 2>&1'
	;;
stop)
	start-stop-daemon --stop --quiet --oknodo --retry TERM/10/KILL/5 --pidfile "$PIDFILE"
	rm -f "$PIDFILE"
	;;
restart)
	"$0" stop
	"$0" start
	;;
status)
	if start-stop-daemon --status --pidfile "$PIDFILE"; then echo running; else echo stopped; exit 3; fi
	;;
*)
	echo "Usage: $0 {start|stop|restart|status}" >&2
	exit 2
	;;
esac
`, 0o755}},
		install: func(*backend) error { return run(enable[0], enable[1:]...) },
		start:   func(*backend) error { return run(script, "restart") },
		uninstall: func(*backend) error {
			_ = run(script, "stop") // best effort: may not be running
			_ = run(disable[0], disable[1:]...)
			return nil
		},
		state: func(*backend) string {
			s, _ := output(script, "status")
			switch s {
			case "running":
				return "active"
			case "stopped":
				return "inactive"
			}
			return ""
		},
	}, nil
}

// BusyBox init: a respawn line in /etc/inittab, which init rereads on SIGHUP.
// There is no service file, so Install only makes sure the log's directory
// exists; Start adds the line, and when the Agent already runs, stops it so
// init respawns it on the new binary. BusyBox runs a line containing shell
// characters through `sh -c`, which is what the redirection relies on.
func busybox() *backend {
	const inittab = "/etc/inittab"
	line := "::respawn:" + BinaryPath + " run >>" + logPath + " 2>&1"
	hup := func() error { return syscall.Kill(1, syscall.SIGHUP) }
	return &backend{
		Init:       "BusyBox init",
		Name:       name,
		StatusHint: "grep " + name + " " + inittab + " and ps",
		LogHint:    "tail " + logPath,
		installed: func() bool {
			present, _ := inittabHas(inittab, line)
			return present
		},
		install: func(*backend) error {
			return os.MkdirAll(filepath.Dir(path(logPath)), 0o755)
		},
		start: func(*backend) error {
			present, err := inittabHas(inittab, line)
			if err != nil {
				return err
			}
			if present {
				return stopRunning()
			}
			if err := inittabEdit(inittab, func(lines []string) []string { return append(lines, line) }); err != nil {
				return err
			}
			return hupInit(hup)
		},
		uninstall: func(*backend) error {
			if err := inittabEdit(inittab, func(lines []string) []string {
				kept := lines[:0]
				for _, l := range lines {
					if !strings.Contains(l, BinaryPath+" run") {
						kept = append(kept, l)
					}
				}
				return kept
			}); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			// Reread first, so init no longer respawns what is stopped next.
			if err := hupInit(hup); err != nil {
				return err
			}
			return stopRunning()
		},
		state: func(*backend) string {
			if len(runningAgents()) > 0 {
				return "active"
			}
			return "inactive"
		},
	}
}

// hupInit asks init to reread its inittab, unless this is a test's root.
func hupInit(hup func() error) error {
	if root != "/" {
		return nil
	}
	return hup()
}

func inittabHas(inittab, line string) (bool, error) {
	body, err := os.ReadFile(path(inittab))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	for l := range strings.SplitSeq(string(body), "\n") {
		if strings.TrimSpace(l) == line {
			return true, nil
		}
	}
	return false, nil
}

func inittabEdit(inittab string, edit func([]string) []string) error {
	body, err := os.ReadFile(path(inittab))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	lines := strings.Split(strings.TrimRight(string(body), "\n"), "\n")
	if len(body) == 0 {
		lines = nil
	}
	out := strings.Join(edit(lines), "\n") + "\n"
	return os.WriteFile(path(inittab), []byte(out), 0o644)
}

// runningAgents lists the pids of `easyssl-agent run` processes, never this
// one: the installer is the same binary under another subcommand.
func runningAgents() []int { return processes(name, "run") }

// processes lists the pids, other than this one, whose command line is prog
// (by base name) followed by arg.
func processes(prog, arg string) []int {
	entries, _ := os.ReadDir(path("/proc"))
	var pids []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		cmdline, err := os.ReadFile(path(filepath.Join("/proc", e.Name(), "cmdline")))
		if err != nil {
			continue
		}
		args := bytes.Split(bytes.TrimRight(cmdline, "\x00"), []byte{0})
		if len(args) >= 2 && filepath.Base(string(args[0])) == prog && string(args[1]) == arg {
			pids = append(pids, pid)
		}
	}
	return pids
}

// waitGone waits up to limit for no process to run as `prog arg`.
func waitGone(prog, arg string, limit time.Duration) {
	if root != "/" {
		return
	}
	for deadline := time.Now().Add(limit); time.Now().Before(deadline); time.Sleep(250 * time.Millisecond) {
		if len(processes(prog, arg)) == 0 {
			return
		}
	}
}

// stopRunning ends every running Agent; under BusyBox init the respawn line
// then starts it again on the installed binary.
func stopRunning() error {
	if root != "/" {
		return nil
	}
	for _, pid := range runningAgents() {
		if err := syscall.Kill(pid, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
			return err
		}
	}
	return nil
}
