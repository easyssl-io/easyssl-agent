package plugintrace_test

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/easyssl-io/easyssl-agent/internal/plugintrace"
)

// A Plugin is arbitrary code and is handed the private key on its stdin, so one
// that echoes its request, prints the file it was given, or dumps its
// environment on failure puts the key in its output. Reporting that verbatim
// would store a usable key in the Server's database and show it in the web
// console, and the debug log below passes the request itself through here,
// where the key is the payload rather than an accident. These cover the shapes
// that text actually arrives in.

const secretBody = "MIIBSECRETKEYBYTESmustNeverBeReported"

func TestRedactPrivateKeys(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{{
		name: "a PEM block with real newlines, as a plugin printing the key file produces",
		in:   "wrote it\n-----BEGIN PRIVATE KEY-----\n" + secretBody + "\n-----END PRIVATE KEY-----\ndone\n",
	}, {
		// The case the finding names: the request echoed back, where the whole
		// key is one line and its newlines are two-character escapes.
		name: "a key echoed inside JSON, newlines escaped",
		in:   `{"privateKeyPem":"-----BEGIN PRIVATE KEY-----\n` + secretBody + `\n-----END PRIVATE KEY-----\n"}`,
	}, {
		name: "the RSA/EC spelling of the markers",
		in:   "-----BEGIN EC PRIVATE KEY-----\n" + secretBody + "\n-----END EC PRIVATE KEY-----",
	}, {
		// Output is bounded while it is collected, so a key at the very end can
		// lose its closing marker. Half a key is still key material.
		name: "a key whose end marker was cut off",
		in:   "lots of output\n-----BEGIN PRIVATE KEY-----\n" + secretBody,
	}, {
		name: "more than one key in the same text",
		in: "-----BEGIN PRIVATE KEY-----\n" + secretBody + "\n-----END PRIVATE KEY-----\n" +
			"and again\n-----BEGIN PRIVATE KEY-----\n" + secretBody + "2\n-----END PRIVATE KEY-----\n",
	}}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := plugintrace.RedactPrivateKeys(c.in)
			if strings.Contains(got, secretBody) {
				t.Fatalf("the key survived redaction:\n%s", got)
			}
			if !strings.Contains(got, "redacted by the easySSL Agent") {
				t.Fatalf("nothing says the text was redacted:\n%s", got)
			}
			// The markers stay, so a reader can see a key was there rather than
			// mistaking the gap for a plugin that said nothing.
			if !strings.Contains(got, "BEGIN") {
				t.Fatalf("the redaction removed the marker too:\n%s", got)
			}
		})
	}
}

// Everything around a key is kept: the output is the record of what happened,
// and redaction must not cost the reader the rest of it.
func TestRedactionKeepsSurroundingOutput(t *testing.T) {
	in := "installing to /etc/nginx\n-----BEGIN PRIVATE KEY-----\n" + secretBody +
		"\n-----END PRIVATE KEY-----\nreloaded nginx: ok\n"
	got := plugintrace.RedactPrivateKeys(in)
	for _, want := range []string{"installing to /etc/nginx", "reloaded nginx: ok"} {
		if !strings.Contains(got, want) {
			t.Fatalf("redaction dropped %q:\n%s", want, got)
		}
	}
}

// Certificates are public and must survive: redacting them would remove the
// evidence that the right certificate was installed.
func TestRedactionLeavesCertificatesAlone(t *testing.T) {
	in := "-----BEGIN CERTIFICATE-----\nPUBLICCERTBYTES\n-----END CERTIFICATE-----\n"
	if got := plugintrace.RedactPrivateKeys(in); got != in {
		t.Fatalf("a certificate was altered:\n%s", got)
	}
}

// A typo in a unit file must not stop an Agent from running, so an
// unrecognized level is info rather than an error.
func TestLevel(t *testing.T) {
	for in, want := range map[string]slog.Level{
		"debug": slog.LevelDebug, "DEBUG": slog.LevelDebug, " debug ": slog.LevelDebug,
		"warn": slog.LevelWarn, "warning": slog.LevelWarn, "error": slog.LevelError,
		"info": slog.LevelInfo, "": slog.LevelInfo, "verbose": slog.LevelInfo,
	} {
		if got := plugintrace.Level(in); got != want {
			t.Errorf("Level(%q) = %v, want %v", in, got, want)
		}
	}
}

func debugLogger() (*slog.Logger, *strings.Builder) {
	var b strings.Builder
	return slog.New(slog.NewTextHandler(&b, &slog.HandlerOptions{Level: slog.LevelDebug})), &b
}

// The whole point of the debug level being separate from the trace file: an
// install request carries the private key, and this one is safe to leave on.
func TestRecordRedactsTheKeyItLogs(t *testing.T) {
	logger, out := debugLogger()
	stdin := []byte(`{"certificatePem":"-----BEGIN CERTIFICATE-----\nPUBLIC\n-----END CERTIFICATE-----","privateKeyPem":"-----BEGIN PRIVATE KEY-----\n` + secretBody + `\n-----END PRIVATE KEY-----","settings":{"reload":"nginx -s reload"}}`)
	plugintrace.Record(logger, plugintrace.Exchange{
		Op: "install", Path: "/var/lib/easyssl/plugins/generic-cli", Stdin: stdin,
		Stdout: []byte(`{"ok":true,"output":"reloaded"}`), Stderr: []byte("some diagnostic"),
	})
	got := out.String()
	if strings.Contains(got, secretBody) {
		t.Fatalf("the private key reached the log:\n%s", got)
	}
	// Everything else is the reason for logging at all, so it must survive.
	for _, want := range []string{"nginx -s reload", "PUBLIC", "reloaded", "some diagnostic", "install"} {
		if !strings.Contains(got, want) {
			t.Fatalf("the log lost %q:\n%s", want, got)
		}
	}
}

// Silent unless asked. An Agent nobody is debugging must not narrate every
// Deployment into the journal.
func TestRecordSaysNothingBelowDebug(t *testing.T) {
	var b strings.Builder
	logger := slog.New(slog.NewTextHandler(&b, &slog.HandlerOptions{Level: slog.LevelInfo}))
	plugintrace.Record(logger, plugintrace.Exchange{Op: "install", Path: "/p", Stdin: []byte("{}")})
	if b.String() != "" {
		t.Fatalf("an info-level Agent logged an exchange:\n%s", b.String())
	}
}

// The second switch, and the reason it is a file rather than the journal: this
// is the verbatim key. The test asserts exactly that, because a trace that
// redacted would have no reason to exist.
func TestTraceWritesTheLiteralBytesToItsOwnFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trace.log")
	t.Setenv(plugintrace.TraceEnv, path)
	logger, _ := debugLogger()
	plugintrace.Record(logger, plugintrace.Exchange{
		Op: "install", Path: "/p",
		Stdin:  []byte("-----BEGIN PRIVATE KEY-----\n" + secretBody + "\n-----END PRIVATE KEY-----"),
		Stdout: []byte(`{"ok":true}`),
	})
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no trace file: %v", err)
	}
	if !strings.Contains(string(raw), secretBody) {
		t.Fatal("the trace redacted the key, which is the one thing it exists to keep")
	}
	if !strings.Contains(string(raw), "WARNING") {
		t.Fatal("the trace file does not warn what is in it")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("trace file mode %o, want 600: it holds private keys", perm)
	}
}

// The reason KeyPlaceholder carries no newline. Nearly everything redacted here
// is a JSON document with the key inside a string value, and a real newline
// there makes the whole document unparseable — which costs a debugging session
// `jq` in exchange for a prettier rendering of the one part that is gone.
func TestRedactedJSONIsStillJSON(t *testing.T) {
	req := map[string]string{
		"certificatePem": "-----BEGIN CERTIFICATE-----\nPUBLIC\n-----END CERTIFICATE-----\n",
		"privateKeyPem":  "-----BEGIN PRIVATE KEY-----\n" + secretBody + "\n-----END PRIVATE KEY-----\n",
		"workDir":        "/tmp/easyssl-deploy-1",
	}
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	redacted := plugintrace.RedactPrivateKeys(string(raw))
	if strings.Contains(redacted, secretBody) {
		t.Fatalf("the key survived:\n%s", redacted)
	}
	var back map[string]string
	if err := json.Unmarshal([]byte(redacted), &back); err != nil {
		t.Fatalf("redaction broke the JSON, so nothing can parse the log line: %v\n%s", err, redacted)
	}
	if !strings.Contains(back["certificatePem"], "PUBLIC") {
		t.Fatal("the certificate did not survive the round trip")
	}
	if !strings.Contains(back["privateKeyPem"], "redacted by the easySSL Agent") {
		t.Fatalf("the placeholder is not where the key was: %q", back["privateKeyPem"])
	}
}

// The format switch exists so a debug session is one `jq` call instead of a
// parser for Go's quoting, so what matters is that the line parses.
func TestHandlerJSONFormatIsParseable(t *testing.T) {
	var b strings.Builder
	slog.New(plugintrace.Handler(&b, "debug", "json")).Debug("plugin exchange", "op", "install")
	var line map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(b.String())), &line); err != nil {
		t.Fatalf("the json format did not produce JSON: %v\n%s", err, b.String())
	}
	if line["op"] != "install" || line["msg"] != "plugin exchange" {
		t.Fatalf("the line lost its fields: %v", line)
	}
}

// Text stays the default: someone reading `journalctl` with no pipeline should
// not have to.
func TestHandlerDefaultsToText(t *testing.T) {
	for _, format := range []string{"", "text", "yaml"} {
		var b strings.Builder
		slog.New(plugintrace.Handler(&b, "debug", format)).Debug("hello", "op", "install")
		if strings.HasPrefix(strings.TrimSpace(b.String()), "{") {
			t.Fatalf("format %q produced JSON: %s", format, b.String())
		}
		if !strings.Contains(b.String(), "op=install") {
			t.Fatalf("format %q is not the text handler: %s", format, b.String())
		}
	}
}
