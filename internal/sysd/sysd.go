// Package sysd installs and manages the Client's systemd units. Each Client
// instance runs as easyssl-client@<instance-id>.service from one shared template
// unit, so multiple Clients coexist on a host without colliding (FR-001b).
// Root-only in this slice (FR-001d).
package sysd

import (
	"fmt"
	"os"
	"os/exec"
)

const (
	unitPath    = "/etc/systemd/system/easyssl-client@.service"
	binaryPath  = "/usr/local/bin/easyssl-client"
	unitContent = `[Unit]
Description=easySSL Client (%i)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=` + binaryPath + ` run --instance %i
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
`
)

// ErrNotRoot is returned when systemd operations are attempted without root.
var ErrNotRoot = fmt.Errorf("must run as root to manage systemd units (this slice is root-only)")

// InstallAndStart writes the template unit (idempotent) and enables + starts the
// instance's unit. It requires root.
func InstallAndStart(instanceID string) error {
	if os.Geteuid() != 0 {
		return ErrNotRoot
	}
	if err := os.WriteFile(unitPath, []byte(unitContent), 0o644); err != nil {
		return fmt.Errorf("write unit: %w", err)
	}
	if err := run("systemctl", "daemon-reload"); err != nil {
		return err
	}
	instance := "easyssl-client@" + instanceID
	return run("systemctl", "enable", "--now", instance)
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s %v: %w: %s", name, args, err, out)
	}
	return nil
}
