// Package identity manages the Client's on-disk identity and state. A host runs
// a single Client: its 16-hex instance ID is generated once, persisted in the
// config, and reused across reinstalls, so re-running the installer updates the
// existing Client instead of registering a second one. The config and bearer
// token live directly under BaseDir.
package identity

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// BaseDir holds the single Client's config and token on this host.
const BaseDir = "/etc/easyssl"

// serviceName is the host's single systemd unit (not templated: one per host).
const serviceName = "easyssl-client.service"

// Config is the Client's persisted registration state.
type Config struct {
	InstanceID  string `json:"instanceId"`
	DisplayName string `json:"displayName"`
	ServerURL   string `json:"serverUrl"`
}

// NewInstanceID returns a fresh instance ID: 64 CSPRNG bits as 16 lowercase hex
// characters. Generated locally, persisted once, and reused thereafter; the
// Server enforces its global uniqueness.
func NewInstanceID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// ConfigPath and TokenPath locate the two state files.
func ConfigPath() string { return filepath.Join(BaseDir, "config.json") }
func TokenPath() string  { return filepath.Join(BaseDir, "client.token") }

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

// RemoveAll deletes the Client's whole state directory (config and token). It
// is idempotent: an already-absent directory is not an error.
func RemoveAll() error { return os.RemoveAll(BaseDir) }

// LoadToken reads the host's bearer token.
func LoadToken() (string, error) {
	data, err := os.ReadFile(TokenPath())
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}
