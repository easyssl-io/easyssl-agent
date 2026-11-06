// Package buildinfo holds this Agent build's own version, which every request
// to the Server carries in User-Agent and the installer prints.
package buildinfo

// Version is set from the Agent's release tag, `vX.Y.Z`, with `-ldflags -X`
// when a release is built. Every other build reports the version the Agent
// keeps until its first release. A variable rather than a constant, since `-X`
// can set only a variable.
var Version = "0.0.1"
