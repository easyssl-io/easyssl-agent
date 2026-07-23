// Package identity manages the Client's per-instance identity and on-disk state:
// the 16-hex instance ID (generated locally at install, embedded in the systemd
// unit name), and the per-instance directory holding the config and the bearer
// token. Multiple Clients coexist on one host under distinct instance dirs.
package identity

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// BaseDir is the root under which each Client instance keeps its state.
const BaseDir = "/etc/easyssl"

// Config is the Client's persisted registration state.
type Config struct {
	InstanceID  string `json:"instanceId"`
	DisplayName string `json:"displayName"`
	ServerURL   string `json:"serverUrl"`
}

// NewInstanceID returns a fresh instance ID: 64 CSPRNG bits as 16 lowercase hex
// characters. Generated locally because the ID names the systemd unit installed
// before the first check-in; the Server enforces its global uniqueness.
func NewInstanceID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// Dir is the per-instance directory (BaseDir/<instanceID>).
func Dir(instanceID string) string { return filepath.Join(BaseDir, instanceID) }

// ConfigPath and TokenPath locate the two per-instance files.
func ConfigPath(instanceID string) string { return filepath.Join(Dir(instanceID), "config.json") }
func TokenPath(instanceID string) string   { return filepath.Join(Dir(instanceID), "client.token") }

// ServiceName is the systemd unit name for an instance.
func ServiceName(instanceID string) string { return "easyssl-client@" + instanceID + ".service" }

// SaveConfig writes the config (0600) under a 0700 instance directory.
func SaveConfig(cfg Config) error {
	if err := os.MkdirAll(Dir(cfg.InstanceID), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(ConfigPath(cfg.InstanceID), append(data, '\n'), 0o600)
}

// LoadConfig reads the config for an instance.
func LoadConfig(instanceID string) (Config, error) {
	var cfg Config
	data, err := os.ReadFile(ConfigPath(instanceID))
	if err != nil {
		return cfg, err
	}
	return cfg, json.Unmarshal(data, &cfg)
}

// SaveToken writes the bearer token (0600); the plaintext lives only here.
func SaveToken(instanceID, token string) error {
	if err := os.MkdirAll(Dir(instanceID), 0o700); err != nil {
		return err
	}
	return os.WriteFile(TokenPath(instanceID), []byte(token), 0o600)
}

// LoadToken reads the bearer token for an instance.
func LoadToken(instanceID string) (string, error) {
	data, err := os.ReadFile(TokenPath(instanceID))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}
