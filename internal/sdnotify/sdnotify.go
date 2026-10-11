// Package sdnotify speaks the small part of systemd's notification protocol
// this Agent needs: READY=1 at startup and a STATUS= line systemd prints under
// the unit in `systemctl status`.
//
// Implemented here rather than taken as a dependency because it is one datagram
// to a socket whose path systemd puts in the environment, and because the Agent
// must remain readable by whoever is trusting it with root. Every call is a
// no-op when NOTIFY_SOCKET is unset: the Agent run by hand, under a different
// init, or in a container without systemd.
package sdnotify

import (
	"net"
	"os"
	"strings"
)

// notify sends one message. Errors are deliberately swallowed: the Agent's work
// does not depend on systemd hearing it, and a failure here must never take the
// process down.
func notify(state string) {
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" {
		return
	}
	// An abstract socket, which systemd uses by default, is written with a
	// leading NUL rather than the '@' the environment variable carries.
	if strings.HasPrefix(socket, "@") {
		socket = "\x00" + socket[1:]
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		return
	}
	defer conn.Close()
	_, _ = conn.Write([]byte(state))
}

// Ready tells systemd the service has finished starting. Required under
// Type=notify: without it systemd waits for the whole start timeout and then
// kills the service.
func Ready() { notify("READY=1") }

// Status sets the line `systemctl status` prints under the unit. One short
// sentence in the present tense, saying what the service is doing now.
func Status(text string) { notify("STATUS=" + text) }
