// Command easyssl-client is the easySSL Client binary. Subcommands:
//
//	register --server <url> [--key <key>] [--name <name>]   interactive registration
//	run                                                     the systemd service loop (periodic check-in)
//	status [--json]                                         print local registration state
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
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/easyssl-io/easyssl-client/internal/flow"
	"github.com/easyssl-io/easyssl-client/internal/identity"
	"github.com/easyssl-io/easyssl-client/internal/serverapi"
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
		return fmt.Errorf("run: load config: %w", err)
	}
	token, err := identity.LoadToken()
	if err != nil {
		return fmt.Errorf("run: load token: %w", err)
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
	asJSON := fs.Bool("json", false, "print JSON")
	_ = fs.Parse(args)

	cfg, err := identity.LoadConfig()
	if err != nil {
		return fmt.Errorf("status: %w", err)
	}
	_, tokErr := identity.LoadToken()
	registered := tokErr == nil

	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(map[string]any{
			"instanceId":  cfg.InstanceID,
			"displayName": cfg.DisplayName,
			"serverUrl":   cfg.ServerURL,
			"serviceName": identity.ServiceName(),
			"registered":  registered,
		})
	}
	fmt.Printf("instance   %s\n", cfg.InstanceID)
	fmt.Printf("name       %s\n", cfg.DisplayName)
	fmt.Printf("server     %s\n", cfg.ServerURL)
	fmt.Printf("service    %s\n", identity.ServiceName())
	fmt.Printf("registered %t\n", registered)
	return nil
}
