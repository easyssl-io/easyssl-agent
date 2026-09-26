// Package identity manages the Agent's on-disk identity and state. A host runs
// a single Agent, identified by its public Agent ID (`agnt-` + 14 base32
// characters): the Server mints it at registration, this package persists it,
// and every reinstall presents it, so re-running the installer updates the
// existing Agent instead of registering a second one. It is the same
// identifier the web console shows; nothing here mints anything. The config and
// bearer token live directly under BaseDir.
package identity

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// BaseDir holds the single Agent's config and token on this host.
const BaseDir = "/etc/easyssl"

// Config is the Agent's persisted registration state.
// Config is what the host keeps of its registration, beside the token: which
// Server to talk to, and which Organization it joined, the latter only so an
// offline `status` or `uninstall` can say where this host belongs. No Agent
// ID and no name: the Server is the only namer of Agents, both are answered
// by any authenticated call, and a reactivation token carries the identity
// a host resumes.
type Config struct {
	ServerURL string `json:"serverUrl"`
	// OrganizationName and OrganizationID are the display name and public id
	// of the Organization this host joined, learned at registration and
	// refreshed on every check-in. Optional so an older config still loads.
	OrganizationName string `json:"organizationName,omitempty"`
	OrganizationID   string `json:"organizationId,omitempty"`
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
		return "its Organization"
	}
}

// ConfigPath and TokenPath locate the two state files.
func ConfigPath() string { return filepath.Join(BaseDir, "config.json") }
func TokenPath() string  { return filepath.Join(BaseDir, "agent.token") }

// SaveConfig writes the config (0600) under a 0700 BaseDir.
func SaveConfig(cfg Config) error {
	if err := os.MkdirAll(BaseDir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(ConfigPath(), append(data, '\n'), 0o600)
}

// LoadConfig reads the host's config.
func LoadConfig() (Config, error) {
	var cfg Config
	data, err := os.ReadFile(ConfigPath())
	if err != nil {
		return cfg, err
	}
	return cfg, json.Unmarshal(data, &cfg)
}

// SaveToken writes the bearer token (0600); the plaintext lives only here.
func SaveToken(token string) error {
	if err := os.MkdirAll(BaseDir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(TokenPath(), []byte(token), 0o600)
}

// RemoveAll deletes this Agent's identity: its config and its token. It is
// idempotent, so an already-absent file is not an error.
//
// It deliberately does not remove BaseDir itself, because the keystore lives
// under it and is the Agent's only copy of every private key it generated.
// Uninstalling is too ordinary a command to destroy that, so the keys are left
// behind and the caller says so. This function used to remove the whole
// directory, which was correct only while nothing but the config and the token
// lived there.
func RemoveAll() error {
	for _, path := range []string{ConfigPath(), TokenPath()} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// LoadToken reads the host's bearer token.
func LoadToken() (string, error) {
	data, err := os.ReadFile(TokenPath())
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}
