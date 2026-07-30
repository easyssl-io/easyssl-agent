// Command easyssl-client is the easySSL Client binary. Subcommands:
//
//	register --server <url> [--key <key>] [--name <name>]   interactive registration
//	run                                                     the systemd service loop (periodic check-in)
//	status [--json]                                         print local state + what the Server says
//	uninstall [--yes]                                       unregister and remove the Client
//
// A host runs one Client, so the commands need no instance selector. The CLI
// writes human output to stdout, JSON where asked, and errors to stderr;
// connections are only ever made from Client to Server, never the reverse.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"math/rand/v2"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/easyssl-io/easyssl-client/internal/commands"
	"github.com/easyssl-io/easyssl-client/internal/flow"
	"github.com/easyssl-io/easyssl-client/internal/identity"
	"github.com/easyssl-io/easyssl-client/internal/serverapi"
	"github.com/easyssl-io/easyssl-client/internal/sysd"
	"github.com/easyssl-io/easyssl-contract/wire"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var err error
	switch os.Args[1] {
	case "register":
		err = cmdRegister(ctx, os.Args[2:])
	case "run":
		err = cmdRun(ctx, os.Args[2:])
	case "status":
		err = cmdStatus(os.Args[2:])
	case "uninstall":
		err = cmdUninstall(ctx, os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "easyssl-client: unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "easyssl-client: "+err.Error())
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: easyssl-client <register|run|status|uninstall> [flags]")
}

func cmdRegister(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("register", flag.ExitOnError)
	server := fs.String("server", "", "easySSL Server base URL (required)")
	key := fs.String("key", os.Getenv("REGISTRATION_KEY"), "organization registration key (defaults to $REGISTRATION_KEY)")
	name := fs.String("name", os.Getenv("CLIENT_NAME"), "Client name (defaults to $CLIENT_NAME, else the hostname; prompted when interactive)")
	_ = fs.Parse(args)
	if *server == "" {
		return errors.New("register: --server is required")
	}
	return flow.Register(ctx, flow.Options{ServerURL: *server, RegistrationKey: *key, Name: *name})
}

func cmdUninstall(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	_ = fs.Parse(args)
	return flow.Uninstall(ctx, *yes)
}

func cmdRun(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	_ = fs.Parse(args)
	cfg, err := identity.LoadConfig()
	if err != nil {
		return stateError("run", err)
	}
	token, err := identity.LoadToken()
	if err != nil {
		return stateError("run", err)
	}

	api := serverapi.New(cfg.ServerURL)
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	// No handlers registered yet: certificate signing requests and deployments
	// arrive with the features that need them. Until then an incoming command
	// is reported unsupported, which is the same thing a Client older than its
	// Server does, and exercises that path for free.
	runner := commands.NewRunner(api, token, logger, map[string]commands.Handler{})

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var streaming sync.Once

	poll := 60
	for {
		resp, err := api.Checkin(ctx, token, wire.CheckinRequest{ClientVersion: flow.Version})
		if err == nil {
			poll = resp.NextPollSeconds
			if resp.Status == wire.StatusActive {
				// Only now: every push-channel route refuses a Client that is
				// still awaiting authorization, exactly as the check-in does,
				// so subscribing earlier would just loop on 401s.
				streaming.Do(func() { go streamCommands(ctx, api, token, runner, logger) })
				runner.Reconcile(ctx)
			}
		} else if isUnknownToken(err) {
			// Rejected or revoked: stop cleanly so systemd does not restart-loop.
			fmt.Fprintln(os.Stderr, "run: token rejected or revoked; re-registration required")
			return nil
		}
		// A transient error (Server unreachable) falls through and retries.
		if poll <= 0 {
			poll = 60
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(time.Duration(poll) * time.Second):
		}
	}
}

// streamCommands keeps the event stream open for as long as the service runs,
// reconciling on connect and on every command the Server pushes.
//
// A dropped stream is ordinary, not a failure: networks and proxies close idle
// connections, and the check-in loop keeps delivering commands the whole time.
// So this reconnects quietly and never ends the service. The one thing it will
// not retry is a rejected credential, which no amount of waiting repairs.
func streamCommands(ctx context.Context, api *serverapi.Client, token string, runner *commands.Runner, logger *slog.Logger) {
	const (
		minBackoff = 2 * time.Second
		maxBackoff = 5 * time.Minute
	)
	backoff := minBackoff
	for {
		// Reconcile on every (re)connect, before trusting anything to arrive on
		// the stream: whatever was published while disconnected is waiting.
		runner.Reconcile(ctx)

		err := api.SubscribeCommands(ctx, token, func(commandID string) {
			// The id is a nudge, not the work. Reconcile reads authoritative
			// state, which also picks up anything this Client missed.
			runner.Reconcile(ctx)
		})
		if ctx.Err() != nil {
			return
		}
		if isUnknownToken(err) {
			logger.Warn("command stream refused; token rejected or revoked")
			return
		}
		if err != nil {
			logger.Debug("command stream ended", "err", err, "retry_in", backoff)
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(jitter(backoff)):
		}
		if backoff *= 2; backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// jitter spreads reconnects so a fleet that lost its Server does not return in
// lockstep the moment it comes back.
func jitter(d time.Duration) time.Duration {
	return d/2 + time.Duration(rand.Int64N(int64(d/2)+1))
}

// stateError explains why the Client's on-disk state could not be read. The two
// common causes have obvious fixes, but the raw "permission denied" on
// config.json sends people hunting for a filesystem problem instead: the state
// is deliberately root-only (0600 under a 0700 directory) so an unprivileged
// process cannot read the bearer token.
func stateError(cmd string, err error) error {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("no easySSL Client is registered on this host (%s does not exist); register one with \"sudo easyssl-client register --server <url>\"", identity.ConfigPath())
	case errors.Is(err, fs.ErrPermission):
		return fmt.Errorf("cannot read %s: the Client's config and token are root-only; re-run as root with \"sudo easyssl-client %s\"", identity.BaseDir, cmd)
	}
	return fmt.Errorf("%s: %w", cmd, err)
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	_ = fs.Parse(args)

	cfg, err := identity.LoadConfig()
	if err != nil {
		return stateError("status", err)
	}
	token, tokenErr := identity.LoadToken()

	// Whether the Client is still registered is not a local fact: the Server
	// owns it and can drop a Client without telling the host, so a stored token
	// proves only that one was issued once. Ask the Server. This is a read
	// (GET), not a check-in, so running status never refreshes last-seen and
	// therefore cannot make a stopped Client look alive in the console.
	stateCode, stateDetail := serverState(cfg, token, tokenErr)

	if *asJSON {
		out := map[string]any{
			"instanceId":   cfg.InstanceID,
			"displayName":  cfg.DisplayName,
			"serverUrl":    cfg.ServerURL,
			"serviceName":  identity.ServiceName(),
			"serviceState": sysd.State(),
			"tokenPresent": tokenErr == nil,
			// Short code for machines; the printed line spells it out.
			"serverState": stateCode,
		}
		return json.NewEncoder(os.Stdout).Encode(out)
	}

	fmt.Printf("instance   %s\n", cfg.InstanceID)
	fmt.Printf("name       %s\n", cfg.DisplayName)
	fmt.Printf("server     %s\n", cfg.ServerURL)
	fmt.Printf("service    %s (%s)\n", identity.ServiceName(), sysd.State())
	if tokenErr == nil {
		fmt.Printf("token      stored in %s\n", identity.TokenPath())
	} else {
		fmt.Printf("token      missing, so this Client cannot authenticate\n")
	}
	fmt.Printf("state      %s\n", stateDetail)
	return nil
}

// serverState asks the Server what this Client actually is right now, which a
// host cannot tell from its own files: it has no way to know it was removed
// from the console. Read-only, so status stays free of side effects.
//
// It returns a short stable code for machines and a sentence for people. The
// wire calls an authorized Client "active", which printed next to a stopped
// systemd unit reads as if the Client were running, when it only means the
// operator admitted it; the console says "Authorized" and so does this.
func serverState(cfg identity.Config, token string, tokenErr error) (code, detail string) {
	if tokenErr != nil {
		return "not-registered", "not registered (no local token)"
	}
	// Short: status must stay snappy on a host that cannot reach the Server.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := serverapi.New(cfg.ServerURL).RegistrationStatus(ctx, token)
	switch {
	case err == nil && resp.Status == wire.StatusActive:
		return "authorized", "authorized"
	case err == nil && resp.Status == wire.StatusPending:
		return "pending", "pending authorization"
	case err == nil:
		return resp.Status, resp.Status
	case isUnknownToken(err):
		return "not-registered", "not registered (the Server rejected this token; it was removed or revoked there)"
	default:
		return "unknown", fmt.Sprintf("unknown (could not reach %s: %v)", cfg.ServerURL, err)
	}
}

// isUnknownToken reports whether err is the Server's unknown-token response.
func isUnknownToken(err error) bool {
	apiErr, ok := errors.AsType[*serverapi.APIError](err)
	return ok && apiErr.Code == wire.CodeUnknownToken
}
