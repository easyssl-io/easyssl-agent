// Package atomicfile writes a file so that a reader sees either the old content
// or the complete new one, never part of it, and so that the write survives a
// power loss. The Agent's keys, configuration and token are each its only
// copy, and a crash in the middle of an ordinary write would leave one the
// Agent can no longer read.
package atomicfile

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
)

// Write puts data at path. The temporary file is created in the destination
// directory at its final mode, because adjusting the mode afterwards would
// leave a window in which the file is readable by others, and with O_EXCL under
// a random name, so it cannot collide with anything already there. The rename
// makes the write atomic, and the two syncs make it durable. Missing
// directories are created with dirMode.
func Write(path string, data []byte, mode, dirMode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := mkdirAllSynced(dir, dirMode); err != nil {
		return err
	}
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return err
	}
	tmp := filepath.Join(dir, ".tmp-"+hex.EncodeToString(suffix))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	defer os.Remove(tmp) // a no-op once the rename below has succeeded

	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDir(dir)
}

func mkdirAllSynced(dir string, mode os.FileMode) error {
	if _, err := os.Stat(dir); err == nil {
		return nil
	}
	parent := filepath.Dir(dir)
	if parent != dir {
		if err := mkdirAllSynced(parent, mode); err != nil {
			return err
		}
	}
	if err := os.Mkdir(dir, mode); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return syncDir(parent)
}

// syncDir flushes a directory entry, so the renamed file is still there after a
// power loss rather than only its contents having been written.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
