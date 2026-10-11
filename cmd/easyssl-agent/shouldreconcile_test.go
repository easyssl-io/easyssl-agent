package main

import (
	"testing"

	"github.com/easyssl-io/easyssl-contract/wire"
)

// Skipping the reconcile fetch is safe only when the Server said there is
// nothing. The case that matters most is a Server that reports no count at all:
// the Agent must still fetch.
func TestShouldReconcile(t *testing.T) {
	n := func(i int) *int { return &i }

	for _, tc := range []struct {
		name string
		resp wire.CheckinResponse
		want bool
	}{
		{"nothing outstanding: skip", wire.CheckinResponse{PendingCommands: n(0)}, false},
		{"one outstanding: fetch", wire.CheckinResponse{PendingCommands: n(1)}, true},
		{"a backlog: fetch", wire.CheckinResponse{PendingCommands: n(7)}, true},
		{"a Server that does not report the count: fetch", wire.CheckinResponse{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldReconcile(tc.resp); got != tc.want {
				t.Fatalf("shouldReconcile(%v) = %v, want %v", tc.resp.PendingCommands, got, tc.want)
			}
		})
	}
}
