package flow

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/easyssl-io/easyssl-agent/internal/selfupdate"
)

// Uninstall deletes the binary and the builds an update keeps beside it, and
// says which there were; with none there, nothing.
func TestRemoveBinariesTakesTheBuildsAnUpdateKeeps(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "easyssl-agent")
	for _, path := range []string{binary, selfupdate.Previous(binary), selfupdate.Staged(binary)} {
		if err := os.WriteFile(path, []byte("an Agent build"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	removed, err := removeBinaries(binary)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{binary, selfupdate.Previous(binary), selfupdate.Staged(binary)}; !reflect.DeepEqual(removed, want) {
		t.Fatalf("removed = %v, want %v", removed, want)
	}
	entries, _ := os.ReadDir(filepath.Dir(binary))
	if len(entries) != 0 {
		t.Fatalf("left behind: %v", entries)
	}
	if removed, err := removeBinaries(binary); err != nil || len(removed) != 0 {
		t.Fatalf("second run = %v, %v, want nothing", removed, err)
	}
}
