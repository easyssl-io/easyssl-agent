package service

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// host builds a fake root holding the given paths (a trailing "/" makes a
// directory) and PID 1's executable, and records every command instead of
// running it. status answers the backend's state query.
func host(t *testing.T, pid1Exe string, status string, paths ...string) *[]string {
	t.Helper()
	dir := t.TempDir()
	for _, p := range paths {
		full := filepath.Join(dir, p)
		if strings.HasSuffix(p, "/") {
			if err := os.MkdirAll(full, 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, nil, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if pid1Exe != "" {
		if err := os.MkdirAll(filepath.Join(dir, "proc/1"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(pid1Exe, filepath.Join(dir, "proc/1/exe")); err != nil {
			t.Fatal(err)
		}
	}
	var ran []string
	oldRoot, oldRun, oldOutput, oldEuid := root, run, output, euid
	root = dir
	run = func(name string, args ...string) error {
		ran = append(ran, strings.Join(append([]string{name}, args...), " "))
		return nil
	}
	output = func(name string, args ...string) (string, error) { return status, nil }
	euid = func() int { return 0 }
	t.Cleanup(func() { root, run, output, euid = oldRoot, oldRun, oldOutput, oldEuid })
	return &ran
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(path(p))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestDetect(t *testing.T) {
	for _, c := range []struct {
		name  string
		pid1  string
		paths []string
		want  string
	}{
		{"systemd", "/usr/lib/systemd/systemd", []string{"run/systemd/system/"}, "systemd"},
		{"OpenRC", "/sbin/init", []string{"run/openrc/"}, "OpenRC"},
		{"runit", "/usr/bin/runit", []string{"var/service/"}, "runit"},
		{"BusyBox", "/bin/busybox", []string{"etc/init.d/"}, "BusyBox init"},
		{"sysvinit", "/sbin/init", []string{"etc/init.d/", "sbin/start-stop-daemon", "usr/sbin/update-rc.d"}, "sysvinit"},
	} {
		t.Run(c.name, func(t *testing.T) {
			host(t, c.pid1, "", c.paths...)
			b, err := Detect()
			if err != nil || b.Init != c.want {
				t.Fatalf("Detect = %v, %v; want %s", b, err, c.want)
			}
		})
	}
	t.Run("unsupported", func(t *testing.T) {
		host(t, "/sbin/tini", "")
		if _, err := Detect(); err != ErrUnsupportedInit {
			t.Fatalf("Detect = %v, want ErrUnsupportedInit", err)
		}
	})
	t.Run("sysvinit with no way to enable a service", func(t *testing.T) {
		host(t, "/sbin/init", "", "etc/init.d/", "sbin/start-stop-daemon")
		if _, err := Detect(); err == nil {
			t.Fatal("Detect accepted sysvinit with none of update-rc.d, chkconfig or insserv")
		}
	})
}

func TestSystemdLifecycle(t *testing.T) {
	ran := host(t, "/usr/lib/systemd/systemd", "active", "run/systemd/system/")
	if err := Install(); err != nil {
		t.Fatal(err)
	}
	unit := read(t, "/etc/systemd/system/easyssl-agent.service")
	if !strings.Contains(unit, "ExecStart=/usr/local/bin/easyssl-agent run") || !strings.Contains(unit, "Type=notify") {
		t.Fatalf("unit = %s", unit)
	}
	if err := Start(); err != nil {
		t.Fatal(err)
	}
	if !Installed() || State() != "active" {
		t.Fatalf("Installed %v, State %q", Installed(), State())
	}
	if err := Uninstall(); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"systemctl daemon-reload", "systemctl enable easyssl-agent.service",
		"systemctl restart easyssl-agent.service",
		"systemctl disable --now easyssl-agent.service",
	}
	if !reflect.DeepEqual(*ran, want) {
		t.Fatalf("ran %q, want %q", *ran, want)
	}
	if Installed() {
		t.Fatal("the unit survived Uninstall")
	}
}

func TestOpenRCLifecycle(t *testing.T) {
	ran := host(t, "/sbin/init", "status: started", "run/openrc/")
	if err := Install(); err != nil {
		t.Fatal(err)
	}
	script := read(t, "/etc/init.d/easyssl-agent")
	for _, want := range []string{"#!/sbin/openrc-run", "command=/usr/local/bin/easyssl-agent", "supervisor=supervise-daemon", "use net"} {
		if !strings.Contains(script, want) {
			t.Fatalf("script misses %q:\n%s", want, script)
		}
	}
	if fi, _ := os.Stat(path("/etc/init.d/easyssl-agent")); fi.Mode().Perm() != 0o755 {
		t.Fatalf("script mode %v, want 0755", fi.Mode().Perm())
	}
	_ = Start()
	if State() != "active" {
		t.Fatalf("State = %q, want active from %q", State(), "status: started")
	}
	_ = Uninstall()
	want := []string{"rc-update add easyssl-agent default", "rc-service easyssl-agent restart", "rc-service easyssl-agent stop", "rc-update del easyssl-agent default"}
	if !reflect.DeepEqual(*ran, want) {
		t.Fatalf("ran %q, want %q", *ran, want)
	}
}

func TestRunitLifecycle(t *testing.T) {
	ran := host(t, "/usr/bin/runit", "run: easyssl-agent: (pid 12) 3s", "var/service/")
	if err := Install(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(read(t, "/etc/sv/easyssl-agent/run"), "exec /usr/local/bin/easyssl-agent run") {
		t.Fatal("run script does not exec the Agent")
	}
	if !exists("/etc/sv/easyssl-agent/down") {
		t.Fatal("Install left no down file, so runsv would start the Agent before authorization")
	}
	if target, _ := os.Readlink(path("/var/service/easyssl-agent")); target != "/etc/sv/easyssl-agent" {
		t.Fatalf("service link -> %q", target)
	}
	if err := Start(); err != nil {
		t.Fatal(err)
	}
	if exists("/etc/sv/easyssl-agent/down") {
		t.Fatal("Start left the down file, so the Agent would not start at boot")
	}
	if State() != "active" {
		t.Fatalf("State = %q", State())
	}
	_ = Uninstall()
	if exists("/var/service/easyssl-agent") || exists("/etc/sv/easyssl-agent/run") {
		t.Fatal("Uninstall left the service behind")
	}
	want := []string{"sv restart easyssl-agent", "sv down easyssl-agent"}
	if !reflect.DeepEqual(*ran, want) {
		t.Fatalf("ran %q, want %q", *ran, want)
	}
}

func TestSysvinitLifecycle(t *testing.T) {
	ran := host(t, "/sbin/init", "running", "etc/init.d/", "sbin/start-stop-daemon", "usr/sbin/update-rc.d")
	if err := Install(); err != nil {
		t.Fatal(err)
	}
	script := read(t, "/etc/init.d/easyssl-agent")
	for _, want := range []string{"### BEGIN INIT INFO", "start-stop-daemon --start", "--background --make-pidfile", "exec /usr/local/bin/easyssl-agent run >>/var/log/easyssl-agent.log"} {
		if !strings.Contains(script, want) {
			t.Fatalf("script misses %q:\n%s", want, script)
		}
	}
	_ = Start()
	if State() != "active" {
		t.Fatalf("State = %q", State())
	}
	_ = Uninstall()
	want := []string{"update-rc.d easyssl-agent defaults", "/etc/init.d/easyssl-agent restart", "/etc/init.d/easyssl-agent stop", "update-rc.d -f easyssl-agent remove"}
	if !reflect.DeepEqual(*ran, want) {
		t.Fatalf("ran %q, want %q", *ran, want)
	}
	if _, hint, _ := Describe(); !strings.Contains(hint, "does not restart") {
		t.Fatalf("status hint %q does not say sysvinit leaves an exited Agent down", hint)
	}
}

func TestBusyBoxLifecycle(t *testing.T) {
	host(t, "/bin/busybox", "", "etc/inittab")
	if err := os.WriteFile(path("/etc/inittab"), []byte("::sysinit:/etc/init.d/rcS\n::respawn:-/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Install(); err != nil {
		t.Fatal(err)
	}
	if Installed() {
		t.Fatal("Installed before Start added the respawn line")
	}
	for range 2 { // a reinstall must not add a second line
		if err := Start(); err != nil {
			t.Fatal(err)
		}
	}
	tab := read(t, "/etc/inittab")
	if strings.Count(tab, "/usr/local/bin/easyssl-agent run") != 1 || !strings.HasPrefix(tab, "::sysinit:/etc/init.d/rcS\n::respawn:-/bin/sh\n") {
		t.Fatalf("inittab after two starts:\n%s", tab)
	}
	if !Installed() {
		t.Fatal("not Installed after Start")
	}
	if err := Uninstall(); err != nil {
		t.Fatal(err)
	}
	if got := read(t, "/etc/inittab"); got != "::sysinit:/etc/init.d/rcS\n::respawn:-/bin/sh\n" {
		t.Fatalf("inittab after Uninstall:\n%s", got)
	}
}

func TestRefusesWithoutRoot(t *testing.T) {
	host(t, "/usr/lib/systemd/systemd", "", "run/systemd/system/")
	euid = func() int { return 1000 }
	for _, f := range []func() error{Install, Start, Uninstall} {
		if err := f(); err != ErrNotRoot {
			t.Fatalf("got %v, want ErrNotRoot", err)
		}
	}
}
