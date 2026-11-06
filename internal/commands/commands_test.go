package commands

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"

	"github.com/easyssl-io/easyssl-contract/wire"
)

type fakeServer struct {
	cmds []wire.Command
	acks map[string]string
}

func (f *fakeServer) PendingCommands(context.Context, string) ([]wire.Command, error) {
	return f.cmds, nil
}

func (f *fakeServer) AckCommand(_ context.Context, _, id, status string) error {
	f.acks[id] = status
	return nil
}

// What a handler returns decides what the Server hears: done, unsupported, or
// nothing at all, so the command comes back on the next fetch.
func TestHandlerOutcomeDecidesTheAck(t *testing.T) {
	cases := map[string]struct {
		cmdType string
		err     error
		want    string // "" means not acked
	}{
		"finished":             {wire.CommandDeploy, nil, wire.CommandStatusAcked},
		"may clear":            {wire.CommandDeploy, errors.New("server answered 500"), ""},
		"cannot do":            {wire.CommandRequestCSR, fmt.Errorf("key type %q: %w", "ml-dsa-44", ErrUnsupported), wire.CommandStatusUnsupported},
		"unknown command type": {"rotate_key", nil, wire.CommandStatusUnsupported},
	}
	for name, c := range cases {
		srv := &fakeServer{cmds: []wire.Command{{ID: "cmd-1", Type: c.cmdType}}, acks: map[string]string{}}
		handlers := map[string]Handler{
			wire.CommandDeploy:     func(context.Context, wire.Command) error { return c.err },
			wire.CommandRequestCSR: func(context.Context, wire.Command) error { return c.err },
		}
		NewRunner(srv, "tok", slog.New(slog.NewTextHandler(io.Discard, nil)), handlers).Reconcile(context.Background())
		if got := srv.acks["cmd-1"]; got != c.want {
			t.Errorf("%s: acked %q, want %q", name, got, c.want)
		}
	}
}

// A handler interrupted by shutdown leaves its command for the next start.
func TestShutdownLeavesTheCommandOutstanding(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	srv := &fakeServer{cmds: []wire.Command{{ID: "cmd-1", Type: wire.CommandDeploy}}, acks: map[string]string{}}
	handlers := map[string]Handler{wire.CommandDeploy: func(context.Context, wire.Command) error {
		cancel()
		return context.Canceled
	}}
	NewRunner(srv, "tok", slog.New(slog.NewTextHandler(io.Discard, nil)), handlers).Reconcile(ctx)
	if got, ok := srv.acks["cmd-1"]; ok {
		t.Fatalf("acked %q during shutdown, want no ack", got)
	}
}
