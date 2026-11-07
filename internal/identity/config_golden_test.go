package identity

import (
	"testing"

	"github.com/easyssl-io/easyssl-contract/contracttest"
)

// config.json is read again by every later Agent on the same host, so each
// form it was written in stays loadable: "config" as SaveConfig writes it now,
// and "config-minimal" as an Agent wrote it before it learned an Organization
// or a language.
func TestConfigFiles(t *testing.T) {
	contracttest.Messages(t, "testdata", map[string]any{
		"config": Config{
			ServerURL: "https://console.easyssl.io", OrganizationName: "Northwind", OrganizationID: "org-northwindaaaaaa", Language: "es",
		},
		"config-minimal": Config{ServerURL: "https://console.easyssl.io"},
	})
}
