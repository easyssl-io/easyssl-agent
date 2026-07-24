// Package flow drives the interactive line-based registration session (S4 US1).
// A host runs one Client (FR-002): the first run generates and persists the
// instance ID, registers, stores the token, installs the systemd unit, and waits
// for the operator to authorize from the console. A later run on an
// already-registered host is idempotent: it refreshes the service onto the
// updated binary and reports state instead of registering a second Client. It is
// plain stdin/stdout, no full-screen TUI in this slice.
package flow

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/easyssl-io/easyssl-contract/wire"
	"github.com/easyssl-io/easyssl-client/internal/hostinfo"
	"github.com/easyssl-io/easyssl-client/internal/identity"
	"github.com/easyssl-io/easyssl-client/internal/serverapi"
	"github.com/easyssl-io/easyssl-client/internal/sysd"
)

// Version is the Client agent version reported to the Server.
const Version = "0.0.1"

// maxInstanceIDAttempts bounds instance-ID regeneration on the (astronomically
// unlikely) collision path before giving up.
const maxInstanceIDAttempts = 5

// Options configures a registration session.
type Options struct {
	ServerURL       string // required
	RegistrationKey string // from --key or REGISTRATION_KEY; prompted if empty and interactive
}

// Register runs the registration session. If this host already has a Client
// identity it takes the idempotent reinstall path; otherwise it registers a new
// Client. A context cancellation (Ctrl-C) during the wait is not an error: the
// installed systemd service keeps polling, so authorization can complete later.
func Register(ctx context.Context, opts Options) error {
	fmt.Printf("easySSL client installer · v%s\n", Version)
	fmt.Println("Registering this host to an easySSL organization...")
	fmt.Println()

	if cfg, err := identity.LoadConfig(); err == nil && cfg.InstanceID != "" {
		return reinstall(ctx, opts, cfg)
	}
	return freshRegister(ctx, opts)
}

// freshRegister registers a host that has no Client yet.
func freshRegister(ctx context.Context, opts Options) error {
	key, err := resolveKey(opts.RegistrationKey)
	if err != nil {
		return err
	}
	host, _ := os.Hostname()
	name := confirmName(host)
	fmt.Printf("✓ client name  %s\n", name)

	api := serverapi.New(opts.ServerURL)
	resp, instanceID, err := register(ctx, api, key, name, opts.ServerURL)
	if err != nil {
		return err
	}

	cfg := identity.Config{InstanceID: instanceID, DisplayName: name, ServerURL: opts.ServerURL}
	if err := identity.SaveConfig(cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	if err := identity.SaveToken(resp.ClientToken); err != nil {
		return fmt.Errorf("save token: %w", err)
	}
	fmt.Printf("✓ client token stored in %s\n", identity.TokenPath())

	if err := sysd.Install(); err != nil {
		return fmt.Errorf("installing systemd unit: %w", err)
	}
	fmt.Printf("✓ systemd service installed: %s\n", identity.ServiceName())

	return awaitAuthorization(ctx, api, name, resp.ClientToken, resp.NextPollSeconds)
}

// reinstall handles a host that is already registered. It reconciles the token
// (re-registering under the same instance ID if it was removed from the console),
// then refreshes and restarts the service onto the freshly installed binary, and
// reports state. Reconciling the token BEFORE the restart is essential: restarting
// first would run the service with the stale token, and a revoked token makes the
// service exit (systemd does not auto-restart a clean exit) before the new token
// is written, leaving nothing running even after the operator authorizes.
func reinstall(ctx context.Context, opts Options, cfg identity.Config) error {
	fmt.Printf("This host is already registered as %q (instance %s).\n", cfg.DisplayName, cfg.InstanceID)

	api := serverapi.New(cfg.ServerURL)
	token, status, poll, err := reconcileToken(ctx, api, opts, cfg)
	if err != nil {
		return err
	}

	// (Re)start the service now that a valid token is on disk, so it runs the
	// freshly installed binary and keeps polling regardless of whether the
	// operator waits below.
	if err := sysd.Install(); err != nil {
		return fmt.Errorf("updating systemd unit: %w", err)
	}
	fmt.Printf("✓ %s updated and restarted\n", identity.ServiceName())

	switch status {
	case wire.StatusActive:
		fmt.Printf("\n✓ %s is authorized and ACTIVE.\n", cfg.DisplayName)
		return nil
	case "":
		fmt.Println("\nCould not confirm status with the Server; the service will keep polling, so authorize any time.")
		return nil
	default: // pending
		return awaitAuthorization(ctx, api, cfg.DisplayName, token, poll)
	}
}

// reconcileToken returns a token the service can run with, plus the Client's
// current status and poll cadence. It checks in with the stored token; if that
// token is missing or was removed from the console it re-registers under the same
// instance ID. status is "" (poll unused) when the Server could not be reached.
func reconcileToken(ctx context.Context, api *serverapi.Client, opts Options, cfg identity.Config) (token, status string, poll int, err error) {
	if token, err = identity.LoadToken(); err == nil {
		resp, cerr := api.Checkin(ctx, token, wire.CheckinRequest{AgentVersion: Version})
		switch {
		case cerr == nil:
			return token, resp.Status, resp.NextPollSeconds, nil
		case isUnknownToken(cerr):
			fmt.Println("The previous registration was removed from the console; re-registering this host.")
			// fall through to re-register
		default:
			return token, "", 0, nil // transient error: keep the token, status unknown
		}
	}
	return reregister(ctx, api, opts, cfg)
}

// reregister re-registers keeping the host's persisted instance ID and name, and
// returns the new token with a pending status.
func reregister(ctx context.Context, api *serverapi.Client, opts Options, cfg identity.Config) (string, string, int, error) {
	key, err := resolveKey(opts.RegistrationKey)
	if err != nil {
		return "", "", 0, err
	}
	resp, err := api.Register(ctx, wire.RegistrationRequest{
		RegistrationKey: key,
		InstanceID:      cfg.InstanceID,
		ProposedName:    cfg.DisplayName,
		AgentVersion:    Version,
		ProtocolVersion: wire.ProtocolVersion,
		Diagnostics:     hostinfo.Collect(),
	})
	if err != nil {
		if apiErr, ok := errors.AsType[*serverapi.APIError](err); ok {
			switch apiErr.Code {
			case wire.CodeInstanceIDTaken:
				return "", "", 0, errors.New("registration failed: this host is already registered; remove it from the console, then reinstall")
			case wire.CodeInvalidRegistrationKey:
				return "", "", 0, errors.New("registration failed: the registration key was not accepted")
			}
		}
		return "", "", 0, fmt.Errorf("registration failed: %w", err)
	}
	if err := identity.SaveToken(resp.ClientToken); err != nil {
		return "", "", 0, fmt.Errorf("save token: %w", err)
	}
	fmt.Printf("✓ re-registered, new client token stored in %s\n", identity.TokenPath())
	return resp.ClientToken, wire.StatusPending, resp.NextPollSeconds, nil
}

// awaitAuthorization waits for the operator to authorize, printing the outcome.
// An interrupt during the wait is reported as safe (the service keeps polling).
func awaitAuthorization(ctx context.Context, api *serverapi.Client, name, token string, pollSeconds int) error {
	fmt.Println()
	fmt.Println("Waiting for authorization from the web console (approve it at your console › Clients)...")

	if err := waitForAuthorization(ctx, api, token, pollSeconds); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			fmt.Println("\n(installer interrupted; the systemd service keeps polling, so authorize any time)")
			return nil
		}
		return err
	}
	fmt.Printf("\n✓ %s was authorized and is now ACTIVE.\n", name)
	fmt.Printf("  manage:  systemctl status %s\n", identity.ServiceName())
	return nil
}

func resolveKey(fromFlag string) (string, error) {
	if fromFlag != "" {
		return fromFlag, nil
	}
	if !isTerminal(os.Stdin) {
		return "", errors.New("no registration key: set the REGISTRATION_KEY environment variable or pass --key")
	}
	key := prompt("Paste your registration key: ")
	if key == "" {
		return "", errors.New("a registration key is required")
	}
	return key, nil
}

func confirmName(defaultName string) string {
	if !isTerminal(os.Stdin) {
		return defaultName
	}
	fmt.Printf("Detected hostname: %s\n", defaultName)
	v := prompt(fmt.Sprintf("Client name [%s]: ", defaultName))
	if v == "" {
		return defaultName
	}
	return v
}

// register submits a fresh registration, regenerating the instance ID if the
// Server reports it is taken.
func register(ctx context.Context, api *serverapi.Client, key, name, serverURL string) (wire.RegistrationResponse, string, error) {
	for range maxInstanceIDAttempts {
		instanceID, err := identity.NewInstanceID()
		if err != nil {
			return wire.RegistrationResponse{}, "", err
		}
		diag := hostinfo.Collect()
		fmt.Printf("✓ host  %s · %s\n", diag.OS, diag.HostType)
		fmt.Printf("→ submitting registration to %s\n", serverURL)

		resp, err := api.Register(ctx, wire.RegistrationRequest{
			RegistrationKey: key,
			InstanceID:      instanceID,
			ProposedName:    name,
			AgentVersion:    Version,
			ProtocolVersion: wire.ProtocolVersion,
			Diagnostics:     diag,
		})
		if err == nil {
			return resp, instanceID, nil
		}
		if apiErr, ok := errors.AsType[*serverapi.APIError](err); ok {
			switch apiErr.Code {
			case wire.CodeInstanceIDTaken:
				continue // regenerate and retry
			case wire.CodeInvalidRegistrationKey:
				return wire.RegistrationResponse{}, "", errors.New("registration failed: the registration key was not accepted")
			}
		}
		return wire.RegistrationResponse{}, "", fmt.Errorf("registration failed: %w", err)
	}
	return wire.RegistrationResponse{}, "", errors.New("registration failed: could not obtain a unique instance ID")
}

// waitForAuthorization polls until the Client is active, the token is rejected,
// or the context is canceled. Transient network errors are retried.
func waitForAuthorization(ctx context.Context, api *serverapi.Client, token string, pollSeconds int) error {
	if pollSeconds <= 0 {
		pollSeconds = 3
	}
	for {
		resp, err := api.Checkin(ctx, token, wire.CheckinRequest{AgentVersion: Version})
		switch {
		case err == nil && resp.Status == wire.StatusActive:
			return nil
		case err == nil:
			pollSeconds = resp.NextPollSeconds
		default:
			if isUnknownToken(err) {
				return errors.New("registration was rejected (or the token was revoked)")
			}
			// transient error: keep the current cadence and retry
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(pollSeconds) * time.Second):
		}
	}
}

// isUnknownToken reports whether err is the Server's unknown-token response.
func isUnknownToken(err error) bool {
	apiErr, ok := errors.AsType[*serverapi.APIError](err)
	return ok && apiErr.Code == wire.CodeUnknownToken
}

// --- small terminal helpers (stdlib only) ---

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func prompt(label string) string {
	fmt.Print(label)
	sc := bufio.NewScanner(os.Stdin)
	if sc.Scan() {
		return strings.TrimSpace(sc.Text())
	}
	return ""
}
