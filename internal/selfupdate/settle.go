package selfupdate

import (
	"context"
	"time"
)

// Settle watches a service just restarted on a new build, looking every
// interval until limit: done as soon as the build has had a check-in accepted,
// failed at the first look that finds the service not active, and, when
// neither happens, done at the limit, since a Server that cannot be reached
// says nothing about the build. A build that exits on start is restarted by
// the init system and shows as not active at one of the looks.
func Settle(ctx context.Context, state func() string, checkedIn func() bool, interval, limit time.Duration) bool {
	deadline := time.Now().Add(limit)
	for {
		if state() != "active" {
			return false
		}
		if checkedIn() {
			return true
		}
		if !time.Now().Before(deadline) {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(interval):
		}
	}
}
