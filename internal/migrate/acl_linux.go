package migrate

import "syscall"

// hasACL reports whether name carries a POSIX access ACL. A filesystem
// without extended attributes has none.
func hasACL(name string) bool {
	n, err := syscall.Getxattr(name, "system.posix_acl_access", nil)
	return err == nil && n > 0
}
