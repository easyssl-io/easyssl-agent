// Command easyssl-client is the easySSL Client binary. Subcommands:
//
//	register --server <url> [--key <key>]   run the interactive registration flow
//	run --instance <id>                     the systemd service loop (periodic check-in)
//	status [--instance <id>] [--json]       print local registration state
//
// Per Principle II the CLI writes human output to stdout, JSON where asked, and
// errors to stderr; connections are only ever made from Client to Server.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/easyssl-io/easyssl-contract/wire"
	"github.com/easyssl-io/easyssl-client/internal/flow"
	"github.com/easyssl-io/easyssl-client/internal/identity"
	"github.com/easyssl-io/easyssl-client/internal/serverapi"
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
	fmt.Fprintln(os.Stderr, "usage: easyssl-client <register|run|status> [flags]")
}

func cmdRegister(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("register", flag.ExitOnError)
	server := fs.String("server", "", "easySSL Server base URL (required)")
	key := fs.String("key", os.Getenv("REGISTRATION_KEY"), "organization registration key (defaults to $REGISTRATION_KEY)")
	_ = fs.Parse(args)
	if *server == "" {
		return errors.New("register: --server is required")
	}
	return flow.Register(ctx, flow.Options{ServerURL: *server, RegistrationKey: *key})
}

func cmdRun(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	instance := fs.String("instance", "", "Client instance ID (required)")
	_ = fs.Parse(args)
	if *instance == "" {
		return errors.New("run: --instance is required")
	}
	cfg, err := identity.LoadConfig(*instance)
	if err != nil {
		return fmt.Errorf("run: load config for %s: %w", *instance, err)
	}
	token, err := identity.LoadToken(*instance)
	if err != nil {
		return fmt.Errorf("run: load token for %s: %w", *instance, err)
	}

	api := serverapi.New(cfg.ServerURL)
	poll := 60
	for {
		resp, err := api.Checkin(ctx, token, wire.CheckinRequest{AgentVersion: flow.Version})
		if err == nil {
			poll = resp.NextPollSeconds
		} else if apiErr, ok := errors.AsType[*serverapi.APIError](err); ok && apiErr.Code == wire.CodeUnknownToken {
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

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	instance := fs.String("instance", "", "Client instance ID (defaults to the sole installed instance)")
	asJSON := fs.Bool("json", false, "print JSON")
	_ = fs.Parse(args)

	id := *instance
	if id == "" {
		only, err := soleInstance()
		if err != nil {
			return err
		}
		id = only
	}
	cfg, err := identity.LoadConfig(id)
	if err != nil {
		return fmt.Errorf("status: %w", err)
	}
	_, tokErr := identity.LoadToken(id)
	registered := tokErr == nil

	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(map[string]any{
			"instanceId":  cfg.InstanceID,
			"displayName": cfg.DisplayName,
			"serverUrl":   cfg.ServerURL,
			"serviceName": identity.ServiceName(cfg.InstanceID),
			"registered":  registered,
		})
	}
	fmt.Printf("instance   %s\n", cfg.InstanceID)
	fmt.Printf("name       %s\n", cfg.DisplayName)
	fmt.Printf("server     %s\n", cfg.ServerURL)
	fmt.Printf("service    %s\n", identity.ServiceName(cfg.InstanceID))
	fmt.Printf("registered %t\n", registered)
	return nil
}

// soleInstance returns the instance ID when exactly one is installed.
func soleInstance() (string, error) {
	entries, err := os.ReadDir(identity.BaseDir)
	if err != nil {
		return "", fmt.Errorf("status: no instances under %s: %w", identity.BaseDir, err)
	}
	var ids []string
	for _, e := range entries {
		if e.IsDir() {
			if _, err := os.Stat(filepath.Join(identity.BaseDir, e.Name(), "config.json")); err == nil {
				ids = append(ids, e.Name())
			}
		}
	}
	switch len(ids) {
	case 0:
		return "", errors.New("status: no registered Client instances found")
	case 1:
		return ids[0], nil
	default:
		return "", fmt.Errorf("status: multiple instances installed; pass --instance (found %v)", ids)
	}
}
