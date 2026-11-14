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
	"time"

	"github.com/easyssl-io/easyssl-agent/internal/acmeclients"
	"github.com/easyssl-io/easyssl-agent/internal/keystore"
	"github.com/easyssl-io/easyssl-agent/internal/pluginmgr"
	"github.com/easyssl-io/easyssl-agent/internal/serverapi"
	"github.com/easyssl-io/easyssl-contract/l10n"
	"github.com/easyssl-io/easyssl-contract/plugincontract"
	"github.com/easyssl-io/easyssl-contract/wire"
)

// Redaction itself is covered in internal/plugintrace. Covered here is deploy's
// own funnel: that it redacts before bounding, since only this package knows
// about the bound.

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
		wire.DeploymentWork{PluginID: "generic-cli", KeySPKISHA256: "00"}, logger)
	if res.OK || res.PluginRun == nil || res.PluginRun.ExitStatus != 3 {
		t.Fatalf("result = %+v, want a run that exited 3", res)
	}
	want := l10n.Text{
		"en": "the Plugin exited with status 3; its output says why",
		"es": "el Plugin terminó con el estado 3; su salida dice por qué",
	}
	if !reflect.DeepEqual(res.AgentMessage, want) {
		t.Fatalf("AgentMessage = %v, want %v", res.AgentMessage, want)
	}
}

// A Plugin ended by a signal has no status, so the Agent does not claim its
// output explains it, and quotes the process's own error instead.
func TestARunEndedBySignalQuotesTheError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "generic-cli")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nkill -TERM $$\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	loadKey = func(string) (crypto.Signer, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }
	t.Cleanup(func() { loadKey = keystore.Load })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	res := run(context.Background(), plugins{installed: pluginmgr.Installed{ID: "generic-cli", Path: path}},
		wire.DeploymentWork{PluginID: "generic-cli", KeySPKISHA256: "00"}, logger)
	if res.OK || res.PluginRun == nil || res.PluginRun.ExitStatus != -1 {
		t.Fatalf("result = %+v, want a run with no status", res)
	}
	want := l10n.Text{
		"en": "the Plugin ended without an exit status: signal: terminated",
		"es": "el Plugin terminó sin un estado de salida: signal: terminated",
	}
	if !reflect.DeepEqual(res.AgentMessage, want) {
		t.Fatalf("AgentMessage = %v, want %v", res.AgentMessage, want)
	}
}

type plugins struct{ installed pluginmgr.Installed }

func (p plugins) Find(string) (pluginmgr.Installed, bool, error) { return p.installed, true, nil }

// The one rule that decides a Deployment worked.
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
		// Something concluded the attempt failed while the process itself ended
		// cleanly.
		"an error despite a 0 status": {errors.New("something else went wrong"), clean, false},
		// No process at all: the Plugin was missing or unrunnable.
		"no run": {errors.New("not installed"), nil, false},
		// The reason the status is checked rather than inferred from the error. It
		// cannot arise today, `cmd.Wait` erroring exactly when the status is
		// non-zero, which is what makes it worth pinning: a path that stopped
		// returning an error for a failed run would otherwise report the Deployment
		// as having worked.
		"a non-zero status with no error": {nil, &wire.PluginRun{ExitStatus: 2}, false},
	} {
		if got := succeeded(tc.err, tc.run); got != tc.want {
			t.Errorf("%s: succeeded = %v, want %v", name, got, tc.want)
		}
	}
}

type workAPI struct{ err error }

func (a workAPI) DeploymentWork(context.Context, string, string) (wire.DeploymentWork, error) {
	return wire.DeploymentWork{}, a.err
}

func (workAPI) ReportDeploymentResult(context.Context, string, string, wire.DeploymentResult) error {
	return nil
}

// Only the contract's code says a Deployment is gone; a bare 404, such as a
// proxy's, leaves the command for a retry.
func TestOnlyDeploymentNotFoundDiscardsTheCommand(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cmd := wire.Command{ID: "cmd-1", Type: wire.CommandDeploy, RefID: "dep-1"}
	gone := New(workAPI{&serverapi.APIError{Status: 404, Code: wire.CodeDeploymentNotFound}}, plugins{}, "tok", logger)
	if err := gone(context.Background(), cmd); err != nil {
		t.Fatalf("deployment_not_found: handler = %v, want nil (discarded)", err)
	}
	bare := New(workAPI{&serverapi.APIError{Status: 404}}, plugins{}, "tok", logger)
	if err := bare(context.Background(), cmd); err == nil {
		t.Fatal("bare 404: handler = nil, want error (retry later)")
	}
}

// A process the install command leaves in the background keeps the Plugin's
// output open. The Deployment still ends when the Plugin exits, with its own
// exit status, rather than when that process does.
func TestABackgroundProcessDoesNotHoldTheDeployment(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	orig := pipeWaitDelay
	pipeWaitDelay = 200 * time.Millisecond
	t.Cleanup(func() { pipeWaitDelay = orig })
	plugin := filepath.Join(t.TempDir(), "plugin")
	if err := os.WriteFile(plugin, []byte("#!/bin/sh\nsleep 30 &\necho installed\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	run, err := runPlugin(context.Background(), plugin, plugincontract.DeployRequest{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil || run.ExitStatus != 0 {
		t.Fatalf("run = %+v, err %v; want exit 0 and no error", run, err)
	}
	if elapsed := time.Since(started); elapsed > 10*time.Second {
		t.Fatalf("took %s, so the background process held the Deployment", elapsed)
	}
}

type unusablePlugin struct{}

func (unusablePlugin) Find(string) (pluginmgr.Installed, bool, error) {
	return pluginmgr.Installed{}, true, errors.New("generic-cli did not answer `describe` usably")
}

// A Plugin that is on the host but fails describe is named, with the command
// that replaces it, since reinstalling is the fix and the Server cannot know it.
func TestAnUnusablePluginNamesTheReinstall(t *testing.T) {
	res := run(context.Background(), unusablePlugin{}, wire.DeploymentWork{PluginID: "generic-cli"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if res.OK {
		t.Fatal("a Deployment with an unusable Plugin succeeded")
	}
	got := res.AgentMessage["en"]
	for _, want := range []string{"cannot be used", "did not answer `describe` usably", "easyssl-agent plugin install generic-cli"} {
		if !strings.Contains(got, want) {
			t.Errorf("message %q lacks %q", got, want)
		}
	}
}

// A Deployment to a file another ACME client manages fails before its Plugin
// runs, and says so in every language; one beside it runs.
func TestAManagedPathIsRefusedBeforeThePluginRuns(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "ran")
	path := filepath.Join(dir, "nginx")
	if err := os.WriteFile(path, []byte("#!/bin/sh\ntouch "+marker+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc/letsencrypt/live/example.com"), 0o755); err != nil {
		t.Fatal(err)
	}
	acmeHost = func() acmeclients.Host { return acmeclients.Host{Root: root} }
	t.Cleanup(func() { acmeHost = acmeclients.System })
	loadKey = func(string) (crypto.Signer, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }
	t.Cleanup(func() { loadKey = keystore.Load })

	installed := pluginmgr.Installed{ID: "nginx", Path: path, Version: "0.2.0", Declarations: []plugincontract.SettingDeclaration{
		{Key: "ssl_certificate", Type: plugincontract.SettingTypePath},
		{Key: "reload", Type: plugincontract.SettingTypeCommand},
	}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	work := wire.DeploymentWork{PluginID: "nginx", KeySPKISHA256: "00", Settings: map[string]string{
		"ssl_certificate": "/etc/letsencrypt/live/example.com/fullchain.pem", "reload": "/etc/letsencrypt/x",
	}}
	res := run(context.Background(), plugins{installed: installed}, work, logger)
	if res.OK || res.PluginRun != nil || res.PluginVersion != "0.2.0" {
		t.Fatalf("result = %+v, want a refusal with no run", res)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the Plugin ran")
	}
	en := res.AgentMessage["en"]
	if !strings.HasPrefix(en, "easySSL does not write to `/etc/letsencrypt/live/example.com/fullchain.pem`, so the nginx Plugin was not run. Certbot manages `/etc/letsencrypt`") {
		t.Fatalf("AgentMessage = %q", en)
	}
	if es := res.AgentMessage["es"]; !strings.Contains(es, "Certbot gestiona `/etc/letsencrypt`") {
		t.Fatalf("Spanish AgentMessage = %q", es)
	}

	// Only path settings count: the same directory in a command is not a file
	// easySSL writes.
	work.Settings["ssl_certificate"] = "/etc/ssl/example.pem"
	res = run(context.Background(), plugins{installed: installed}, work, logger)
	if !res.OK {
		t.Fatalf("result = %+v, want the Plugin to run", res)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("the Plugin did not run")
	}
}
