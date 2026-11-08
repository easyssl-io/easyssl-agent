// Package buildinfo holds this Agent build's own version, which every request
// to the Server carries in User-Agent and the installer prints.
package buildinfo

// Version is set with `-ldflags -X` by the build scripts: the release tag's
// version on a tagged commit, a `+dev` version naming the commit otherwise.
// A build made without them, `go build` or a test, reports 0.0.0, which is
// never a release. A variable rather than a constant, since `-X` can set only
// a variable.
var Version = "0.0.0"
