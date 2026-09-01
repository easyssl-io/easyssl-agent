// Package sysd installs and manages the Agent's single systemd unit. A host
// runs one Agent as easyssl-agent.service, so re-running the installer
// refreshes this one unit and restarts it onto the updated binary rather than
// adding a second unit. Root-only for now.
//
// The unit orders itself after network.target and not network-online.target.
// The two are not the same promise: network.target says the stack is up, while
// network-online.target says a link is configured and reachable, and reaching
// it means running a wait-online helper that blocks until it is satisfied or
// times out. On a host whose interface that helper does not recognize as
// configured, which includes a static address with no network manager and every
// container whose address the runtime set up itself, it blocks for its full
// two-minute timeout and the Agent is silent for that long after every boot.
//
// The stronger dependency buys nothing here. This is a poll loop that retries,
// under Restart=on-failure, so a network that is not ready yet costs one failed
// attempt and RestartSec, and a network that never comes back is not something
// waiting longer at boot would fix.
package sysd

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Type=notify, so the Agent can set the line `systemctl status` prints under
// the unit: a host removed from the web console keeps its service running and says
// so there, rather than exiting and leaving a dead unit with no reason. See
// sdnotify. The Agent sends READY=1 at startup; without it systemd would wait
// out the start timeout and kill the service.
const (
	unitName    = "easyssl-agent.service"
	unitPath    = "/etc/systemd/system/" + unitName
	binaryPath  = "/usr/local/bin/easyssl-agent"
	unitContent = `[Unit]
Description=easySSL Agent
After=network.target

[Service]
Type=notify
NotifyAccess=main
ExecStart=` + binaryPath + ` run
Restart=on-failure
RestartSec=10
# A private /tmp, so the directory a Deployment writes the private key into is
# not shared with anything else on the host. The key is already 0700 root-owned
# under a random name and is removed on every path, so this closes the class
# rather than a known hole. Deliberately alone: NoNewPrivileges and
# ProtectSystem would also reach a Plugin's reload command, which may call sudo
# or systemctl, so they need their own decision.
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
`
)

// ErrNotRoot is returned when systemd operations are attempted without root.
var ErrNotRoot = fmt.Errorf("must run as root to manage systemd units (this slice is root-only)")

// Install (re)writes the unit (idempotent), enables it at boot, and restarts it
// so the service runs the currently installed binary. Restart starts the service
// when it is stopped and bounces it onto a new binary when it is already running,
// which makes both first install and reinstall converge on the same state. It
// requires root.
func Install() error {
	if os.Geteuid() != 0 {
		return ErrNotRoot
	}
	if err := os.WriteFile(unitPath, []byte(unitContent), 0o644); err != nil {
		return fmt.Errorf("write unit: %w", err)
	}
	if err := run("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := run("systemctl", "enable", unitName); err != nil {
		return err
	}
	return run("systemctl", "restart", unitName)
}

// Uninstall stops and disables the service and removes its unit file. It is
// idempotent: a missing or already-stopped unit is not an error, so uninstall
// works on a partially installed host. It requires root.
func Uninstall() error {
	if os.Geteuid() != 0 {
		return ErrNotRoot
	}
	// Best-effort: the unit may already be stopped, disabled, or absent.
	_ = run("systemctl", "disable", "--now", unitName)
	if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove unit: %w", err)
	}
	return run("systemctl", "daemon-reload")
}

// State reports systemd's view of the unit: active, inactive, failed, and so
// on, or "unknown" when systemctl cannot be consulted at all. `systemctl
// is-active` exits non-zero for every state except active, so the printed word
// is the answer and the exit status is not.
func State() string {
	out, err := exec.Command("systemctl", "is-active", unitName).Output()
	if s := strings.TrimSpace(string(out)); s != "" {
		return s
	}
	if err != nil {
		return "unknown"
	}
	return "unknown"
}

// BinaryPath is where the installer places the Agent binary, which uninstall
// removes last. UnitPath is the systemd unit it installs.
func BinaryPath() string { return binaryPath }
func UnitPath() string   { return unitPath }

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s %v: %w: %s", name, args, err, out)
	}
	return nil
}
