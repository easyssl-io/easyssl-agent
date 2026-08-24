package flow

import (
	"bufio"
	"bytes"
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

// FR-001c: the installer offers the hostname's first label, not the whole
// hostname. Every host exercised during development had a single-label
// hostname, where trimming and not trimming agree, which is why this went
// unnoticed; the domain-qualified case is the one that matters.
func TestProposedNameIsTheHostnamesFirstLabel(t *testing.T) {
	for _, c := range []struct{ hostname, want string }{
		{"web-01.nw.internal", "web-01"},
		{"web-01", "web-01"},
		{"db-prod-01.eu-west-1.compute.internal", "db-prod-01"},
		{"", ""},
	} {
		if got := proposedName(c.hostname); got != c.want {
			t.Errorf("proposedName(%q) = %q, want %q", c.hostname, got, c.want)
		}
	}
}

func fakeTerminal(answer string) (*terminal, *bytes.Buffer) {
	var out bytes.Buffer
	return &terminal{in: bufio.NewReader(strings.NewReader(answer + "\n")), out: &out, close: func() {}}, &out
}

func TestConfirmName(t *testing.T) {
	t.Run("a name given on the command line wins over any proposal", func(t *testing.T) {
		got, err := confirmName(nil, "chosen", "web-01", "web-01.nw.internal")
		if err != nil || got != "chosen" {
			t.Fatalf("confirmName = %q, %v; want \"chosen\", nil", got, err)
		}
	})

	t.Run("unattended takes the proposal", func(t *testing.T) {
		got, err := confirmName(nil, "", "web-01", "web-01.nw.internal")
		if err != nil || got != "web-01" {
			t.Fatalf("confirmName = %q, %v; want \"web-01\", nil", got, err)
		}
	})

	// FR-001c: with no hostname there is nothing to propose. Unattended there is
	// also nobody to ask, so it fails here rather than registering an empty name
	// the Server would refuse later.
	t.Run("unattended with no hostname is an error, not an empty name", func(t *testing.T) {
		if _, err := confirmName(nil, "", "", ""); err == nil {
			t.Fatal("confirmName with no proposal and no terminal = nil error, want one")
		}
	})

	t.Run("the prompt shows the whole hostname beside the proposal", func(t *testing.T) {
		term, out := fakeTerminal("")
		got, err := confirmName(term, "", "web-01", "web-01.nw.internal")
		if err != nil || got != "web-01" {
			t.Fatalf("confirmName = %q, %v; want \"web-01\", nil", got, err)
		}
		if !strings.Contains(out.String(), "web-01.nw.internal") {
			t.Errorf("prompt = %q, want it to name the whole hostname", out.String())
		}
	})

	t.Run("nothing was trimmed, so nothing is shown beside it", func(t *testing.T) {
		term, out := fakeTerminal("")
		if _, err := confirmName(term, "", "web-01", "web-01"); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out.String(), "host ") {
			t.Errorf("prompt = %q, want no host aside for a single-label hostname", out.String())
		}
	})

	t.Run("an answer at the prompt replaces the proposal", func(t *testing.T) {
		term, _ := fakeTerminal("edge-a")
		got, err := confirmName(term, "", "web-01", "web-01.nw.internal")
		if err != nil || got != "edge-a" {
			t.Fatalf("confirmName = %q, %v; want \"edge-a\", nil", got, err)
		}
	})

	t.Run("no hostname and an empty answer is an error", func(t *testing.T) {
		term, _ := fakeTerminal("")
		if _, err := confirmName(term, "", "", ""); err == nil {
			t.Fatal("confirmName with no proposal and an empty answer = nil error, want one")
		}
	})
}
