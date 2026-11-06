package main

import (
	"testing"

	"github.com/easyssl-io/easyssl-contract/wire"
)

// Skipping the reconcile fetch is safe only when the Server said there is
// nothing.
func TestShouldReconcile(t *testing.T) {
	for _, tc := range []struct {
		name string
		resp wire.CheckinResponse
		want bool
	}{
		{"nothing outstanding: skip", wire.CheckinResponse{PendingCommands: 0}, false},
		{"one outstanding: fetch", wire.CheckinResponse{PendingCommands: 1}, true},
		{"a backlog: fetch", wire.CheckinResponse{PendingCommands: 7}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldReconcile(tc.resp); got != tc.want {
				t.Fatalf("shouldReconcile(%v) = %v, want %v", tc.resp.PendingCommands, got, tc.want)
			}
		})
	}
}
