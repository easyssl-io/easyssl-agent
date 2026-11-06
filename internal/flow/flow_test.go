package flow

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/easyssl-io/easyssl-agent/internal/msg"
	"github.com/easyssl-io/easyssl-agent/internal/pluginmgr"
	"github.com/easyssl-io/easyssl-contract/l10n"
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

// The installer offers the hostname's first label, not the whole hostname. On a
// single-label hostname trimming and not trimming agree, so the
// domain-qualified case is the one that matters.
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

	// With no hostname there is nothing to propose. Unattended there is also
	// nobody to ask, so it fails here rather than registering an empty name
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

func TestLanguageStep(t *testing.T) {
	t.Setenv(msg.EnvVar, "")
	t.Setenv("LC_ALL", "C")

	t.Run("each language under its own name, the default marked, Enter accepts it", func(t *testing.T) {
		term, out := fakeTerminal("")
		if got := askLanguage(term, "es"); got != "es" {
			t.Fatalf("askLanguage = %q, want es", got)
		}
		want := "Language / Idioma\n    1  English (en)\n  * 2  Español (es)\n[2]: "
		if out.String() != want {
			t.Fatalf("language step printed %q, want %q", out.String(), want)
		}
	})

	for answer, want := range map[string]string{"1": "en", "2": "es", "es": "es", "EN": "en", "es-PE": "es", "español": "es"} {
		t.Run("the answer "+answer, func(t *testing.T) {
			term, _ := fakeTerminal(answer)
			if got := askLanguage(term, "en"); got != want {
				t.Fatalf("askLanguage = %q, want %q", got, want)
			}
		})
	}

	t.Run("an answer that names no language is asked again", func(t *testing.T) {
		term, out := fakeTerminal("fr\n3\n2")
		if got := askLanguage(term, "en"); got != "es" {
			t.Fatalf("askLanguage = %q, want es", got)
		}
		if n := strings.Count(out.String(), "[1]: "); n != 3 {
			t.Fatalf("asked %d times, want 3", n)
		}
	})

	t.Run("a terminal that ends takes the default instead of asking forever", func(t *testing.T) {
		term := &terminal{in: bufio.NewReader(strings.NewReader("fr\n")), out: &bytes.Buffer{}, close: func() {}}
		if got := askLanguage(term, "es"); got != "es" {
			t.Fatalf("askLanguage = %q, want es", got)
		}
	})

	t.Run("--lang decides without asking", func(t *testing.T) {
		term, out := fakeTerminal("1")
		got, err := settleLanguage(term, "es", "en")
		if err != nil || got != "es" || out.Len() != 0 {
			t.Fatalf("settleLanguage = %q, %v, printed %q; want es, nil, nothing", got, err, out.String())
		}
	})

	t.Run("an unsupported --lang is refused", func(t *testing.T) {
		if _, err := settleLanguage(nil, "fr", ""); err == nil {
			t.Fatal("settleLanguage with --lang fr = nil error, want one")
		}
	})

	t.Run("without a terminal the default is taken", func(t *testing.T) {
		t.Setenv(msg.EnvVar, "es")
		got, err := settleLanguage(nil, "", "en")
		if err != nil || got != "es" {
			t.Fatalf("settleLanguage = %q, %v; want es, nil", got, err)
		}
	})

	t.Run("the saved language is the default the step offers", func(t *testing.T) {
		term, out := fakeTerminal("")
		got, err := settleLanguage(term, "", "es")
		if err != nil || got != "es" || !strings.Contains(out.String(), "* 2") {
			t.Fatalf("settleLanguage = %q, %v, printed %q", got, err, out.String())
		}
	})
}

// A prompt is answered with the language's own affirmative, and the hint it
// shows is that language's.
func TestConfirmUninstallInSpanish(t *testing.T) {
	msg.SetLanguage("es")
	t.Cleanup(func() { msg.SetLanguage(l10n.English) })
	for answer, want := range map[string]bool{"s": true, "Sí": true, "y": true, "": false, "n": false} {
		term, out := fakeTerminal(answer)
		if got := confirmUninstall(term, true, "Acme (org-abc)"); got != want {
			t.Errorf("confirmUninstall(%q) = %v, want %v", answer, got, want)
		}
		if !strings.Contains(out.String(), "[s/N]") || !strings.Contains(out.String(), "Acme (org-abc)") {
			t.Errorf("prompt = %q, want the Spanish hint and the Organization", out.String())
		}
	}
}

// A host that ends a registration with no Plugin is told how to get one,
// unless the installer is about to install some or the host already has one.
func TestNoPluginHint(t *testing.T) {
	none := func() ([]pluginmgr.Installed, error) { return nil, nil }
	one := func() ([]pluginmgr.Installed, error) { return []pluginmgr.Installed{{ID: "nginx"}}, nil }
	failed := func() ([]pluginmgr.Installed, error) { return nil, errors.New("permission denied") }
	env := func(v string) func(string) string {
		return func(k string) string {
			if k == installerPluginsEnv {
				return v
			}
			return ""
		}
	}
	for _, c := range []struct {
		name string
		list func() ([]pluginmgr.Installed, error)
		env  string
		want bool
	}{
		{"none installed, none coming", none, "", true},
		{"none installed, the installer brings some", none, "nginx", false},
		{"one installed", one, "", false},
		{"listing failed", failed, "", false},
	} {
		got := noPluginHint(c.list, env(c.env))
		if (got != "") != c.want {
			t.Errorf("%s: hint = %q", c.name, got)
		}
		if c.want && !strings.Contains(got, "sudo easyssl-agent plugin install <name>") {
			t.Errorf("%s: the hint names no install command: %q", c.name, got)
		}
	}
}

// The install script restores the Agent build it replaced only when register
// changed nothing on the host, so an error after the first write must not read
// as unchanged, and one before it must, without hiding what it wraps.
func TestMarkUnchanged(t *testing.T) {
	cause := errors.New("refused")
	if markUnchanged(nil, false) != nil {
		t.Error("a nil error became one")
	}
	if err := markUnchanged(cause, true); Unchanged(err) {
		t.Error("an error after the host changed reads as unchanged")
	}
	err := markUnchanged(cause, false)
	if !Unchanged(err) {
		t.Error("an error before any write does not read as unchanged")
	}
	if !errors.Is(err, cause) || err.Error() != cause.Error() {
		t.Errorf("the wrapped error is %q, not the cause", err)
	}
}

func TestRegisterRefusedBeforeWritingIsUnchanged(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the refusal tested is the one for a user other than root")
	}
	err := Register(context.Background(), Options{ServerURL: "https://easyssl.example"})
	if err == nil || !Unchanged(err) {
		t.Fatalf("Register as a non-root user = %v, want an unchanged error", err)
	}
}
