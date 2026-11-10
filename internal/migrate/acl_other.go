//go:build !linux

package migrate

// hasACL is false where POSIX ACLs are not read: the Agent runs on Linux, and
// this lets the package build and be tested elsewhere.
func hasACL(string) bool { return false }
