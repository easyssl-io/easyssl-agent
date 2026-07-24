// Package sysd installs and manages the Client's single systemd unit. A host
// runs one Client as easyssl-client.service (FR-002), so re-running the
// installer refreshes this one unit and restarts it onto the updated binary
// rather than adding a second unit. Root-only in this slice (FR-001d).
package sysd

import (
	"fmt"
	"os"
	"os/exec"
)

const (
	unitPath    = "/etc/systemd/system/easyssl-client.service"
	binaryPath  = "/usr/local/bin/easyssl-client"
	unitContent = `[Unit]
Description=easySSL Client
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=` + binaryPath + ` run
Restart=on-failure
RestartSec=10

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
	if err := run("systemctl", "enable", "easyssl-client.service"); err != nil {
		return err
	}
	return run("systemctl", "restart", "easyssl-client.service")
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s %v: %w: %s", name, args, err, out)
	}
	return nil
}
