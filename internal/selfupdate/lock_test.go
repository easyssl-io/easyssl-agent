package selfupdate

import (
	"path/filepath"
	"strings"
	"testing"
)

// A second update is refused while one holds the lock, and taken once it
// is released.
func TestLockRefusesASecondUpdateUntilTheFirstEnds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "update.lock")
	unlock, err := Lock(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Lock(path); err == nil || !strings.Contains(err.Error(), "running on this host") {
		t.Fatalf("second lock = %v, want a refusal", err)
	}
	unlock()
	again, err := Lock(path)
	if err != nil {
		t.Fatalf("after release: %v", err)
	}
	again()
}
