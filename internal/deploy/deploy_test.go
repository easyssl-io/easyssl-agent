package deploy

import (
	"strings"
	"testing"
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
