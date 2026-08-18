package deploy

import (
	"strings"
	"testing"
)

// A Plugin is arbitrary code and is handed the private key on its stdin, so one
// that echoes its request, prints the file it was given, or dumps its
// environment on failure puts the key in its output. Reporting that verbatim
// would store a usable key in the Server's database and show it in the console.
// These cover the shapes that output actually arrives in.

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
			got := redactPrivateKeys(c.in)
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
	got := redactPrivateKeys(in)
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
	if got := redactPrivateKeys(in); got != in {
		t.Fatalf("a certificate was altered:\n%s", got)
	}
}

// Redaction runs before the bound, not after: truncating first can cut a key's
// end marker away and leave a head that the block pattern no longer matches.
func TestReportRedactsBeforeTruncating(t *testing.T) {
	// A key at the end of an output long enough to be truncated.
	filler := strings.Repeat("x", maxOutput)
	in := filler + "\n-----BEGIN PRIVATE KEY-----\n" + secretBody + "\n-----END PRIVATE KEY-----\n"
	got := report(in)
	if strings.Contains(got, secretBody) {
		t.Fatal("a key at the end of a truncated output was reported")
	}
	if len(got) > maxOutput {
		t.Fatalf("report returned %d bytes, over the %d bound", len(got), maxOutput)
	}
}
