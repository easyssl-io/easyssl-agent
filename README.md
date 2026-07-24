# easyssl-client

The open-source easySSL Client: a single, auditable Go binary that registers a
host with an easySSL Server, polls for certificate configuration, deploys
certificates through on-demand plugins, and reports inventory and health.

Everything that runs on the Client side is open source, so it can be
independently inspected and audited. Connections are only ever initiated from
the Client to the Server, so the Client can run inside an isolated network zone.

The shared Client-to-Server contract lives in the separate `easyssl-contract`
module; wire types are not duplicated here.

## Commands

```
easyssl-client register --server <url> [--key <key>]   register this host with a Server
easyssl-client run --instance <id>                     the systemd service loop (periodic check-in)
easyssl-client status [--instance <id>] [--json]       print local registration state
```

Human-readable output goes to stdout (JSON with `--json`); errors go to stderr.

## How registration works

`register` runs an interactive line-based session:

1. Resolves the organization registration key from `--key` or the
   `REGISTRATION_KEY` environment variable, prompting for it only on a terminal.
2. Generates a stable 16-hex **instance ID** (embedded in the systemd unit name,
   so several Clients can coexist on one host) and captures best-effort host
   diagnostics (machine ID, hostname, OS, host type).
3. Checks in with the Server, which returns a one-time bearer token. The token
   is stored root-only (`0600`) under `/etc/easyssl/<instance-id>/`; the Server
   keeps only its hash. If the Server reports the instance ID is already taken,
   the installer regenerates it and retries.
4. Installs and starts the per-instance systemd unit
   `easyssl-client@<instance-id>.service`, which runs `run` to check in
   periodically.
5. Waits for an operator to authorize the Client from the web console. This wait
   is safe to interrupt: the installed service keeps polling, so authorization
   can complete at any later time.

The installer is served by the Server, so the usual one-liner is:

```
curl -sSL <server-url>/install | sudo REGISTRATION_KEY=<key> bash
```

This slice is Linux + systemd and root-only; the Client stores no encryption key
and sends none to the Server.

