package deploy

import (
	"errors"
	"strings"
	"testing"

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
	got := report(in)
	if strings.Contains(got, secretBody) {
		t.Fatal("a key at the end of a truncated output was reported")
	}
	if len(got) > maxOutput {
		t.Fatalf("report returned %d bytes, over the %d bound", len(got), maxOutput)
	}
}

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
