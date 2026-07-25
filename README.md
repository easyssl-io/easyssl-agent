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
easyssl-client register --server <url> [--key <key>] [--name <name>]   register this host
easyssl-client run                                                     the systemd service loop (periodic check-in)
easyssl-client status [--json]                                         print local registration state
```

Human-readable output goes to stdout (JSON with `--json`); errors go to stderr.

## How registration works

A host runs a single Client. `register` runs an interactive line-based session:

1. Resolves the organization registration key from `--key` or the
   `REGISTRATION_KEY` environment variable, prompting for it when neither is set.
2. Resolves the Client's name: `--name` or `CLIENT_NAME` if given, otherwise the
   host's hostname offered as an editable default at the prompt.
3. Generates a stable 16-hex **instance ID** once and persists it, then captures
   best-effort host diagnostics (machine ID, hostname, OS, host type). If the
   Server reports the instance ID is already taken, the installer regenerates it
   and retries.
4. Checks in with the Server, which returns a one-time bearer token. The config
   and token are stored root-only (`0600`) under `/etc/easyssl/`; the Server
   keeps only the token's hash.
5. Installs and starts the systemd unit `easyssl-client.service`, which runs
   `run` to check in periodically.
6. Waits for an operator to authorize the Client from the web console. This wait
   is safe to interrupt: the installed service keeps polling, so authorization
   can complete at any later time.

Re-running the installer on an already-registered host is idempotent: it
refreshes the binary, restarts the service, and reports the current state
instead of registering a second Client. If the Client was removed from the
console, the reinstall re-registers it under the same instance ID.

The installer is served by the Server, so the usual one-liner is:

```
curl -sSL <server-url>/install | sudo REGISTRATION_KEY=<key> bash
```

The prompts still work in that form: the script arrives on stdin, so the Client
reads the operator from the controlling terminal (`/dev/tty`) instead. Where
there is no terminal at all (cloud-init, CI), pass the name up front and it
never prompts:

```
curl -sSL <server-url>/install | sudo REGISTRATION_KEY=<key> CLIENT_NAME=web-01 bash
```

This slice is Linux + systemd and root-only; the Client stores no encryption key
and sends none to the Server.

