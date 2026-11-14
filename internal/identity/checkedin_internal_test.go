package identity

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// `update` trusts the record only from the build it started, written after it
// started: an older build's record, or one written before, says nothing.
func TestCheckedInSinceNeedsTheVersionAndATimeAfter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "checked-in")
	if checkedInSince(path, "0.2.2", time.Now().Add(-time.Hour)) {
		t.Fatal("no record counted as a check-in")
	}
	if err := markCheckedIn(path, "0.2.2"); err != nil {
		t.Fatal(err)
	}
	if !checkedInSince(path, "0.2.2", time.Now().Add(-time.Minute)) {
		t.Error("the started build's record after it started was not counted")
	}
	if checkedInSince(path, "0.2.1", time.Now().Add(-time.Minute)) {
		t.Error("another build's record was counted")
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	if checkedInSince(path, "0.2.2", time.Now().Add(-time.Minute)) {
		t.Error("a record from before the restart was counted")
	}
}
