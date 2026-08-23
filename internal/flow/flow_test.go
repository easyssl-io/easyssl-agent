package flow

import (
	"strings"
	"testing"
)

func TestMarketplaceURL(t *testing.T) {
	t.Run("uses the Server response", func(t *testing.T) {
		const fromServer = "https://console.example/plugins/marketplace"
		if got := marketplaceURL("https://server.example", fromServer); got != fromServer {
			t.Fatalf("marketplaceURL = %q, want %q", got, fromServer)
		}
	})

	t.Run("falls back for an older Server", func(t *testing.T) {
		const want = "https://server.example/plugins/marketplace"
		if got := marketplaceURL("https://server.example/", ""); got != want {
			t.Fatalf("marketplaceURL = %q, want %q", got, want)
		}
	})
}

func TestAuthorizationInstructionsPutMarketplaceBeforeWait(t *testing.T) {
	got := authorizationInstructions("https://server.example/plugins/marketplace")
	marketplace := strings.Index(got, "Visit the Plugin marketplace")
	wait := strings.Index(got, "Waiting for authorization")
	if marketplace < 0 || wait < 0 || marketplace >= wait {
		t.Fatalf("instructions are out of order: %q", got)
	}
}
