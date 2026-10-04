package deploy

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/easyssl-io/easyssl-agent/internal/keystore"
	"github.com/easyssl-io/easyssl-agent/internal/pluginmgr"
	"github.com/easyssl-io/easyssl-contract/l10n"
	"github.com/easyssl-io/easyssl-contract/wire"
)

// What redaction itself must do is covered in the package that owns it
// (internal/plugintrace). What is covered here is deploy's own funnel: that it
// redacts before bounding, since only this package knows about the bound.

const secretBody = "MIIBSECRETKEYBYTESmustNeverBeReported"

// Redaction runs before the bound, not after: truncating first can cut a key's
// end marker away and leave a head that the block pattern no longer matches.
func TestReportRedactsBeforeTruncating(t *testing.T) {
	// A key at the end of an output long enough to be truncated.
	filler := strings.Repeat("x", maxOutput)
	in := filler + "\n-----BEGIN PRIVATE KEY-----\n" + secretBody + "\n-----END PRIVATE KEY-----\n"
	got := report(l10n.Text{"en": in, "es": in})
	if len(got) != 2 {
		t.Fatalf("report returned %d languages, want both", len(got))
	}
	// Each language on its own: one left out of the funnel would carry the
	// key the other had removed.
	for lang, text := range got {
		if strings.Contains(text, secretBody) {
			t.Fatalf("%s: a key at the end of a truncated output was reported", lang)
		}
		if len(text) > maxOutput {
			t.Fatalf("%s: report returned %d bytes, over the %d bound", lang, len(text), maxOutput)
		}
	}
}

// A failure the Agent words itself reaches the Server in every language,
// whatever language this host speaks, and what the operating system said
// inside it stays as produced.
func TestFailuresAreReportedInEveryLanguage(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "generic-cli")
	_, statErr := os.Stat(missing)

	res := run(context.Background(), plugins{installed: pluginmgr.Installed{ID: "generic-cli", Path: missing}}, wire.DeploymentWork{PluginID: "generic-cli"}, nil)
	if res.OK || res.PluginRun != nil {
		t.Fatalf("a Plugin that is not on disk ran: %+v", res)
	}
	if err := res.AgentMessage.Validate(); err != nil {
		t.Fatal(err)
	}
	en, es := res.AgentMessage["en"], res.AgentMessage["es"]
	if en == "" || es == "" || en == es {
		t.Fatalf("AgentMessage = %v, want English and Spanish", res.AgentMessage)
	}
	for lang, text := range res.AgentMessage {
		if !strings.Contains(text, statErr.Error()) || !strings.Contains(text, "easyssl-agent plugin install generic-cli") {
			t.Fatalf("%s reads %q, without the operating system's error or the command as produced", lang, text)
		}
	}

	// The Agent's own finding inside the sentence reads in each language too.
	res = run(context.Background(), plugins{installed: pluginmgr.Installed{ID: "generic-cli", Path: t.TempDir()}}, wire.DeploymentWork{PluginID: "generic-cli"}, nil)
	if !strings.Contains(res.AgentMessage["en"], "it is a directory") || !strings.Contains(res.AgentMessage["es"], "es un directorio") {
		t.Fatalf("AgentMessage = %v, want the finding in each language", res.AgentMessage)
	}
}

// A Plugin's failed run is the Agent's sentence in every language around the
// process's own error, left as produced.
func TestAFailedRunIsReportedInEveryLanguage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "generic-cli")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 3\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	loadKey = func(string) (crypto.Signer, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }
	t.Cleanup(func() { loadKey = keystore.Load })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	res := run(context.Background(), plugins{installed: pluginmgr.Installed{ID: "generic-cli", Path: path}},
		wire.DeploymentWork{PluginID: "generic-cli", KeyFingerprint: "00"}, logger)
	if res.OK || res.PluginRun == nil || res.PluginRun.ExitStatus != 3 {
		t.Fatalf("result = %+v, want a run that exited 3", res)
	}
	want := l10n.Text{
		"en": "the Plugin exited with an error: exit status 3",
		"es": "el Plugin terminó con un error: exit status 3",
	}
	if !reflect.DeepEqual(res.AgentMessage, want) {
		t.Fatalf("AgentMessage = %v, want %v", res.AgentMessage, want)
	}
}

type plugins struct{ installed pluginmgr.Installed }

func (p plugins) Find(string) (pluginmgr.Installed, bool, error) { return p.installed, true, nil }

// What decides a Deployment worked. There is one rule and it is this one; the
// field used to be set in two struct literals, one computing it and one leaving
// it out, and the omitted one reported Go's `false` while looking deliberate.
func TestSucceededIsTheExitStatusAndNothingElse(t *testing.T) {
	clean := &wire.PluginRun{ExitStatus: 0}
	for name, tc := range map[string]struct {
		err  error
		run  *wire.PluginRun
		want bool
	}{
		"ran and exited 0": {nil, clean, true},
		"ran and exited 1": {errors.New("exit status 1"), &wire.PluginRun{ExitStatus: 1}, false},
		// The Agent's marker for a run it killed. Not a status the Plugin chose,
		// and it must not be read as one.
		"killed at the bound": {errors.New("did not finish"), &wire.PluginRun{ExitStatus: -1}, false},
		// The case the two literals could have parted on: something concluded
		// the attempt failed while the process itself ended cleanly.
		"an error despite a 0 status": {errors.New("something else went wrong"), clean, false},
		// No process at all: the Plugin was missing or unrunnable.
		"no run": {errors.New("not installed"), nil, false},
		// The other way the two literals could have parted, and the reason the
		// status is checked rather than inferred from the error. It cannot
		// arise today, `cmd.Wait` erroring exactly when the status is non-zero,
		// which is what makes it worth pinning: a path that stopped returning
		// an error for a failed run would otherwise report the Deployment as
		// having worked.
		"a non-zero status with no error": {nil, &wire.PluginRun{ExitStatus: 2}, false},
	} {
		if got := succeeded(tc.err, tc.run); got != tc.want {
			t.Errorf("%s: succeeded = %v, want %v", name, got, tc.want)
		}
	}
}
