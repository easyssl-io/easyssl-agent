package flow

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/easyssl-io/easyssl-agent/internal/serverapi"
	"github.com/easyssl-io/easyssl-contract/wire"
)

// waitBudget bounds every wait below. It exists so a regression fails rather
// than hangs: this loop retries anything that is not a rejected token, so an
// installer that went back to checking in would be answered 418 by the fake
// below and would then retry until the Go test binary's own panic timeout.
// Three seconds is ample for two one-second polls against a loopback server.
const waitBudget = 3 * time.Second

// registrationFake answers the registration read with one state per request,
// repeating the last, and records every path it was asked for. The recorded
// paths are what these tests are really about: this wait must not check in,
// because a check-in refreshes the Agent's last-seen and the systemd service
// is the process that is meant to record.
type registrationFake struct {
	mu     sync.Mutex
	paths  []string
	states []string
}

func (f *registrationFake) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		n := len(f.paths)
		f.paths = append(f.paths, r.URL.Path)
		f.mu.Unlock()

		if r.URL.Path != wire.RouteRegistration {
			// A route this wait should never reach. Answering it plausibly
			// would hide the mistake, so it is refused and the assertions on
			// the recorded paths report it.
			http.Error(w, `{"code":"unexpected_route"}`, http.StatusTeapot)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch state := f.states[min(n, len(f.states)-1)]; state {
		case wire.CodeUnknownToken:
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"code":"unknown_token","message":"unknown token"}`))
		default:
			_, _ = w.Write([]byte(`{"status":"` + state +
				`","displayName":"web01","organizationName":"Acme","organizationId":"org-abc"}`))
		}
	})
}

func (f *registrationFake) recorded() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.paths...)
}

// start returns a client for a fake answering the given states, and the fake.
func start(t *testing.T, states ...string) (*serverapi.Client, *registrationFake) {
	t.Helper()
	fake := &registrationFake{states: states}
	srv := httptest.NewServer(fake.handler())
	t.Cleanup(srv.Close)
	return serverapi.New(srv.URL), fake
}

func TestWaitForAuthorizationReadsTheRegistrationAndNeverChecksIn(t *testing.T) {
	t.Run("returns the Organization once the Agent is active", func(t *testing.T) {
		api, fake := start(t, wire.StatusActive)
		ctx, cancel := context.WithTimeout(context.Background(), waitBudget)
		defer cancel()

		name, id, err := waitForAuthorization(ctx, api, "esat_x", 1)
		if err != nil {
			t.Fatalf("waitForAuthorization: %v (asked for %v)", err, fake.recorded())
		}
		if name != "Acme" || id != "org-abc" {
			t.Fatalf("got Organization %q/%q, want Acme/org-abc", name, id)
		}
		if got := fake.recorded(); len(got) != 1 || got[0] != wire.RouteRegistration {
			t.Fatalf("asked for %v, want exactly one %s", got, wire.RouteRegistration)
		}
	})

	t.Run("keeps asking while pending, and never checks in", func(t *testing.T) {
		api, fake := start(t, wire.StatusPending, wire.StatusActive)
		ctx, cancel := context.WithTimeout(context.Background(), waitBudget)
		defer cancel()

		if _, _, err := waitForAuthorization(ctx, api, "esat_x", 1); err != nil {
			t.Fatalf("waitForAuthorization: %v (asked for %v)", err, fake.recorded())
		}
		got := fake.recorded()
		for _, p := range got {
			if p != wire.RouteRegistration {
				t.Fatalf("the wait asked for %s; it must only read %s: %v",
					p, wire.RouteRegistration, got)
			}
		}
		if len(got) != 2 {
			t.Fatalf("asked %d times, want 2 (one pending, one active): %v", len(got), got)
		}
	})

	t.Run("a rejected token ends the wait rather than retrying to the deadline", func(t *testing.T) {
		api, _ := start(t, wire.CodeUnknownToken)
		ctx, cancel := context.WithTimeout(context.Background(), waitBudget)
		defer cancel()

		_, _, err := waitForAuthorization(ctx, api, "esat_x", 1)
		if err == nil {
			t.Fatal("want an error for a rejected token, got nil")
		}
		if ctx.Err() != nil {
			t.Fatalf("the wait ran to the deadline instead of ending on the rejection: %v", err)
		}
	})
}
