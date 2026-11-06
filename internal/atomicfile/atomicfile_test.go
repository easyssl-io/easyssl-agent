package atomicfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteReplacesWholeAndLeavesNoTemporaryFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a", "b")
	path := filepath.Join(dir, "config.json")
	for _, content := range []string{"first", "second"} {
		if err := Write(path, []byte(content), 0o600, 0o700); err != nil {
			t.Fatal(err)
		}
		if got, _ := os.ReadFile(path); string(got) != content {
			t.Fatalf("read %q, want %q", got, content)
		}
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, want 0600", info.Mode().Perm())
	}
	if info, _ := os.Stat(dir); info.Mode().Perm() != 0o700 {
		t.Fatalf("directory mode %v, want 0700", info.Mode().Perm())
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("%d entries, want only the file", len(entries))
	}
}
