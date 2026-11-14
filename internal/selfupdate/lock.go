package selfupdate

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"github.com/easyssl-io/easyssl-agent/internal/msg"
)

// LockHeldEnv is set in the environment of the `plugin update` an `update`
// runs through the new build, which holds the lock already for it: the child
// takes none, rather than refusing the update it is part of.
const LockHeldEnv = "EASYSSL_UPDATE_LOCK_HELD"

// Lock takes the host's update lock at path, refusing at once while another
// `update` or `plugin update` holds it, and returns the function that
// releases it. Held from reading the installed build until the last rollback,
// it keeps two updates from both planning against the same build and then
// overwriting each other's Previous and Staged files, which can lose the only
// working build. The kernel releases it if the process dies.
func Lock(path string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	// #nosec G304 -- a fixed path under the Agent's state directory.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, msg.Err.T("update.locked", "another `easyssl-agent update` or `plugin update` is running on this host; run this again once it ends")
		}
		return nil, err
	}
	return func() { _ = f.Close() }, nil
}
