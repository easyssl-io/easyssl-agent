// Package commands runs the work the Server asks this Agent to do. The Agent
// asks for it whenever the Server nudges it over the event stream, and on a
// timer regardless. The timer guarantees the work happens and the nudge only
// makes it prompt, which is why nothing retries a delivery or tracks whether a
// nudge arrived.
package commands

import (
	"context"
	"errors"
	"log/slog"
	"sync"

	"github.com/easyssl-io/easyssl-contract/wire"
)

// Handler performs one kind of command. Work that ran and failed is reported on
// the resource the command refers to and returns nil, which acks the command.
// An error means something stopped it from finishing that may clear, so the
// command is left for the next fetch; ErrUnsupported means the work asks for
// something this Agent cannot do, which no retry changes.
type Handler func(ctx context.Context, cmd wire.Command) error

// ErrUnsupported is what a Handler returns, possibly wrapped, for work this
// Agent cannot do, such as a key type it does not know. The command is acked
// unsupported, which ends the referenced work on the Server naming this Agent.
var ErrUnsupported = errors.New("the command asks for something this Agent cannot do")

// Fetcher is the subset of the Server API this needs, so a test can drive the
// loop without a Server.
type Fetcher interface {
	PendingCommands(ctx context.Context, token string) ([]wire.Command, error)
	AckCommand(ctx context.Context, token, commandID, status string) error
}

// Runner reconciles this Agent against the commands the Server is waiting on.
type Runner struct {
	api      Fetcher
	token    string
	logger   *slog.Logger
	handlers map[string]Handler

	mu      sync.Mutex
	running map[string]bool // command ids in flight, so a nudge racing the timer acts once
}

func NewRunner(api Fetcher, token string, logger *slog.Logger, handlers map[string]Handler) *Runner {
	return &Runner{api: api, token: token, logger: logger, handlers: handlers, running: map[string]bool{}}
}

// Reconcile fetches everything outstanding and works through it. The event
// stream and the poll both call it, often at the same moment; commands already
// in flight are skipped rather than started twice.
func (r *Runner) Reconcile(ctx context.Context) {
	cmds, err := r.api.PendingCommands(ctx, r.token)
	if err != nil {
		if ctx.Err() == nil {
			r.logger.Warn("fetching pending commands failed", "err", err)
		}
		return
	}
	for _, cmd := range cmds {
		if ctx.Err() != nil {
			return
		}
		r.runOne(ctx, cmd)
	}
}

// runOne executes a single command and reports the outcome. The handler records
// its result on the referenced resource and only then is the command acked. An
// Agent that dies in between leaves the command outstanding, so it runs again
// on the next fetch against work already recorded, which is why a handler has
// to tolerate running twice.
func (r *Runner) runOne(ctx context.Context, cmd wire.Command) {
	if !r.claim(cmd.ID) {
		return
	}
	defer r.release(cmd.ID)

	handler, ok := r.handlers[cmd.Type]
	if !ok {
		// Older than the Server. Say so rather than acking, which would report work
		// that never happened, or staying silent, which would leave the Server
		// waiting. Other commands are unaffected and the stream stays open.
		r.logger.Warn("unsupported command type", "command", cmd.ID, "type", cmd.Type)
		r.ack(ctx, cmd, wire.CommandStatusUnsupported)
		return
	}

	err := handler(ctx, cmd)
	switch {
	case err == nil:
		r.ack(ctx, cmd, wire.CommandStatusAcked)
	case errors.Is(err, ErrUnsupported):
		r.logger.Error("command asks for something this Agent cannot do", "command", cmd.ID, "type", cmd.Type, "err", err)
		r.ack(ctx, cmd, wire.CommandStatusUnsupported)
	case ctx.Err() != nil:
		// Shutting down: left outstanding, it will be handed back.
	default:
		// Left outstanding, so the next fetch runs it again. A reason that never
		// clears ends with the command's expiry, which fails the referenced work
		// naming this Agent; acking here would end it with nothing recorded.
		r.logger.Warn("command not finished; it will be retried", "command", cmd.ID, "type", cmd.Type, "err", err)
	}
}

func (r *Runner) ack(ctx context.Context, cmd wire.Command, status string) {
	if err := r.api.AckCommand(ctx, r.token, cmd.ID, status); err != nil {
		// Nothing to do about it: the command stays outstanding and comes back
		// on the next fetch, which is exactly the recovery path.
		if ctx.Err() == nil {
			r.logger.Warn("acking command failed", "command", cmd.ID, "status", status, "err", err)
		}
		return
	}
	r.logger.Info("command finished", "command", cmd.ID, "type", cmd.Type, "status", status)
}

func (r *Runner) claim(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.running[id] {
		return false
	}
	r.running[id] = true
	return true
}

func (r *Runner) release(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.running, id)
}
