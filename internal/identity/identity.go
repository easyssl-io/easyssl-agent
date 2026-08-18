// Package identity manages the Agent's on-disk identity and state. A host runs
// a single Agent, identified by its public Agent ID (`agnt-` + 14 base32
// characters): the Server mints it at registration, this package persists it,
// and every reinstall presents it, so re-running the installer updates the
// existing Agent instead of registering a second one. It is the same
// identifier the console shows; nothing here mints anything. The config and
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

// serviceName is the host's single systemd unit (not templated: one per host).
const serviceName = "easyssl-agent.service"

// Config is the Agent's persisted registration state.
type Config struct {
	AgentID     string `json:"agentId"`
	DisplayName string `json:"displayName"`
	ServerURL   string `json:"serverUrl"`
}

// ConfigPath and TokenPath locate the two state files.
func ConfigPath() string { return filepath.Join(BaseDir, "config.json") }
func TokenPath() string  { return filepath.Join(BaseDir, "agent.token") }

// ServiceName is the host's systemd unit name.
func ServiceName() string { return serviceName }

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
// under it and holds the only copy of every private key this host generated.
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
