package selfupdate

import (
	"context"
	"testing"
	"time"
)

// The watch ends at the first accepted check-in, fails at the first look that
// finds the service down, and otherwise lasts to the limit and passes.
func TestSettle(t *testing.T) {
	looks := 0
	checkedInAt := func(n int) func() bool { return func() bool { looks++; return looks >= n } }
	active := func() string { return "active" }

	start := time.Now()
	if !Settle(context.Background(), active, checkedInAt(2), 10*time.Millisecond, time.Minute) || time.Since(start) > 5*time.Second {
		t.Fatal("a check-in on the second look did not end the watch early")
	}

	n := 0
	crashes := func() string {
		n++
		if n >= 3 {
			return "activating"
		}
		return "active"
	}
	if Settle(context.Background(), crashes, func() bool { return false }, 10*time.Millisecond, time.Minute) {
		t.Error("a service found down passed")
	}

	if !Settle(context.Background(), active, func() bool { return false }, 10*time.Millisecond, 50*time.Millisecond) {
		t.Error("a service up to the limit with no check-in did not pass")
	}
}
