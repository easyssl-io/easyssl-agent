// Package identity manages the Agent's on-disk identity and state. A host runs
// a single Agent: its configuration is the one file under ConfigDir, and
// everything else it keeps (its bearer token, its keystore and its Plugins) is
// state under StateDir.
package identity

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/easyssl-io/easyssl-agent/internal/atomicfile"
	"github.com/easyssl-io/easyssl-agent/internal/msg"
)

// ConfigDir holds config.json and nothing else: what an administrator might
// read or edit, as /etc is for. StateDir holds what the Agent itself creates
// and keeps, the token and every private key among it, as /var/lib is for.
// Fixed before the first release because moving the keys later would mean an
// update migrating the only copy of each.
const (
	ConfigDir = "/etc/easyssl"
	StateDir  = "/var/lib/easyssl"
)

// Config is what the host keeps of its registration, beside the token: which
// Server to talk to, and which Organization it joined, the latter only so an
// offline `status` or `uninstall` can say where this host belongs. No Agent ID
// and no name: the Server is the only namer of Agents, both are answered by any
// authenticated call, and a reactivation token carries the identity a host
// resumes.
type Config struct {
	ServerURL string `json:"serverUrl"`
	// OrganizationName and OrganizationID are the display name and public id
	// of the Organization this host joined, learned at registration and
	// refreshed on every check-in. Optional so an older config still loads.
	OrganizationName string `json:"organizationName,omitempty"`
	OrganizationID   string `json:"organizationId,omitempty"`
	// Language is the base code of the language this host's commands speak, chosen
	// in the installer's language step or with `easyssl-agent language`. Only the
	// host holds it: the Server is never told. When absent it reads as the
	// operating system locale's language, else English (msg.Resolve).
	Language string `json:"language,omitempty"`
}

// Organization names the Organization for a message, in whatever detail the
// config holds.
func (c Config) Organization() string {
	switch {
	case c.OrganizationName != "" && c.OrganizationID != "":
		return c.OrganizationName + " (" + c.OrganizationID + ")"
	case c.OrganizationName != "":
		return c.OrganizationName
	case c.OrganizationID != "":
		return c.OrganizationID
	default:
		return msg.T("config.organization.unnamed", "its Organization")
	}
}

func ConfigPath() string { return filepath.Join(ConfigDir, "config.json") }
func TokenPath() string  { return filepath.Join(StateDir, "agent.token") }

// CheckedInPath holds the version of the build whose service last had a
// check-in accepted after it started, written then and dated by its mtime.
// `update` reads it to know the build it just started works, without waiting
// out its whole watch.
func CheckedInPath() string { return filepath.Join(StateDir, "checked-in") }

// UpdateLockPath is the lock `update` and `plugin update` hold while they
// change the installed builds (selfupdate.Lock).
func UpdateLockPath() string { return filepath.Join(StateDir, "update.lock") }

// MarkCheckedIn records that this build's service had a check-in accepted.
func MarkCheckedIn(version string) error { return markCheckedIn(CheckedInPath(), version) }

// CheckedInSince reports whether build version had a check-in accepted at or
// after since.
func CheckedInSince(version string, since time.Time) bool {
	return checkedInSince(CheckedInPath(), version, since)
}

func markCheckedIn(path, version string) error {
	return atomicfile.Write(path, []byte(version+"\n"), 0o600, 0o700)
}

func checkedInSince(path, version string, since time.Time) bool {
	info, err := os.Stat(path)
	// To the second, since some filesystems keep no finer mtime.
	if err != nil || info.ModTime().Before(since.Truncate(time.Second)) {
		return false
	}
	data, err := os.ReadFile(path)
	return err == nil && strings.TrimSpace(string(data)) == version
}

// SaveConfig writes the config (0600) under a 0700 ConfigDir.
func SaveConfig(cfg Config) error {
	if err := os.MkdirAll(ConfigDir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(ConfigPath(), append(data, '\n'), 0o600, 0o700)
}

func LoadConfig() (Config, error) {
	var cfg Config
	data, err := os.ReadFile(ConfigPath())
	if err != nil {
		return cfg, err
	}
	return cfg, json.Unmarshal(data, &cfg)
}

// SaveToken writes the bearer token (0600) under a 0700 StateDir; the
// plaintext lives only here.
func SaveToken(token string) error {
	if err := os.MkdirAll(StateDir, 0o700); err != nil {
		return err
	}
	return atomicfile.Write(TokenPath(), []byte(token), 0o600, 0o700)
}

// RemoveAll deletes this Agent's config and token. An already-absent file is
// not an error.
//
// It deliberately does not remove StateDir, because the keystore lives under
// it and is the Agent's only copy of every private key it generated.
// Uninstalling is too ordinary a command to destroy that, so the keys are left
// behind and the caller says so.
func RemoveAll() error {
	for _, path := range []string{ConfigPath(), TokenPath(), CheckedInPath(), UpdateLockPath()} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func LoadToken() (string, error) {
	data, err := os.ReadFile(TokenPath())
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}
