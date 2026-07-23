// Package flow drives the interactive line-based registration session (S4 US1):
// resolve the registration key, confirm the Client name, register (regenerating
// the instance ID on a collision), store the token, install the systemd unit,
// and wait for the operator to authorize from the console. It is plain
// stdin/stdout — no full-screen TUI in this slice.
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

// Register runs the registration session end to end. A context cancellation
// (Ctrl-C) during the wait is not an error: the installed systemd service keeps
// polling, so authorization can still complete later.
func Register(ctx context.Context, opts Options) error {
	fmt.Printf("easySSL  client installer · v%s\n", Version)
	fmt.Println("Register this host to an easySSL organization.")
	fmt.Println()

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
	if err := identity.SaveToken(instanceID, resp.ClientToken); err != nil {
		return fmt.Errorf("save token: %w", err)
	}
	fmt.Printf("✓ receiving client token — stored in %s (0600)\n", identity.TokenPath(instanceID))

	if err := sysd.InstallAndStart(instanceID); err != nil {
		return fmt.Errorf("installing systemd unit: %w", err)
	}
	fmt.Printf("✓ installing systemd unit %s\n", identity.ServiceName(instanceID))

	fmt.Println()
	fmt.Println("Waiting for authorization from the web console…")
	fmt.Printf("    client %s · approve it at your console › Clients\n", instanceID)

	if err := waitForAuthorization(ctx, api, resp.ClientToken, resp.NextPollSeconds); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			fmt.Println("\n(installer interrupted — the systemd service keeps polling; authorize any time)")
			return nil
		}
		return err
	}
	fmt.Printf("\n✓ %s is now ACTIVE — a member of the organization.\n", name)
	fmt.Printf("  manage:  systemctl status %s\n", identity.ServiceName(instanceID))
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

// register submits the registration, regenerating the instance ID if the Server
// reports it is taken.
func register(ctx context.Context, api *serverapi.Client, key, name, serverURL string) (wire.RegistrationResponse, string, error) {
	for range maxInstanceIDAttempts {
		instanceID, err := identity.NewInstanceID()
		if err != nil {
			return wire.RegistrationResponse{}, "", err
		}
		diag := hostinfo.Collect(instanceID)
		fmt.Println("✓ capturing host diagnostics")
		fmt.Printf("    machine-id %s · %s · %s\n", shortID(diag.MachineID), diag.OS, diag.HostType)
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
		var apiErr *serverapi.APIError
		if errors.As(err, &apiErr) {
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
			if apiErr, ok := errors.AsType[*serverapi.APIError](err); ok && apiErr.Code == wire.CodeUnknownToken {
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

func shortID(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:8] + "…" + s[len(s)-4:]
}
