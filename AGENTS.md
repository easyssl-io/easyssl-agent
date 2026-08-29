# AGENTS.md

Guidance for AI coding agents working in `easyssl-agent`. The file is named
`AGENTS.md` because that is the name the tools read; "agent" in this file means
an AI coding agent, while **Agent** capitalized means easySSL's own
host-installed component. `README.md` describes what the Agent does, its
commands, and how registration and uninstall work; this file is what a change
to it must respect.

## Build

```bash
go build ./... && go test ./... && go vet ./...
```

`easyssl-contract` resolves through a `replace` pointing at a sibling checkout,
so a clone of this repository on its own does not build yet. Build from a
checkout that has `easyssl-contract` beside it, and read `replacement directory
../contract does not exist` as an environment problem rather than a defect in
the change under review.

`register`, `run` and `uninstall` drive systemd, `/etc/easyssl/` and the network,
so they are exercised on a real Linux host or a systemd-enabled container.

## Code Review Rules

Everything here runs on a customer's machine, and is open source so they can
verify what it does. Flag any of the following.

- **Standard library first.** A new third-party dependency is a finding unless
  the change says why the standard library cannot do the job. The binary also
  installs on constrained devices, so capabilities not every install needs do not
  belong in it.
- **The Agent only ever dials out.** No listening socket, no inbound callback,
  no Server-triggered action. The Server can never make an Agent uninstall
  itself; that is a host-side decision.
- **Server traffic goes through `internal/serverapi`, with one exception that is
  a known gap.** It is meant to be a single funnel so an audit mode can later
  record every interaction with no unaudited paths. `internal/pluginmgr` is not
  in it: it fetches the Marketplace catalog and downloads a Plugin artifact
  without going through `serverapi`, leaving its own `HTTP` field nil so the
  requests run on the process-wide `http.DefaultClient`, which carries no
  timeout. The funnel is not complete until those move behind the wrapper.
  Anywhere else, a direct `http.Get` or a new `http.Client` is a finding even
  when it works. Inside `serverapi`, `SubscribeCommands` builds its own
  client deliberately, the shared 30-second timeout being one that would sever a
  stream meant to stay open.
- **No private key material reaches the Server**, sent or logged. P0.
- **Secrets stay root-only**, `0600` under `/etc/easyssl/`, never printed.
- **Local state is not proof.** A stored token means one was issued once, not
  that this Agent is still registered or authorized; that comes from the Server.
  A status read must not count as a check-in, or a stopped Agent can be made to
  look alive.
- **The two sides upgrade independently.** An installed Agent cannot be forced
  to update, so changes must tolerate a Server older or newer than this build.
- **Reinstall reconciles, never duplicates.** One host runs one Agent, keyed by
  a stable instance ID, and every install step must be safe to interrupt.
- **CLI contract.** Human output on stdout, machine output behind `--json`,
  errors on stderr, non-zero exit on failure. `--json` codes are a stable
  interface: adding one is fine, redefining one is not.

## Conventions

American English. Capitalize Organization, Agent, Server, Plugin, Certificate,
Target and Deployment whenever they name easySSL's own records or components;
write "web console" in full for easySSL's browser UI. Keep a genuinely generic
technical role lowercase, such as an ACME client or a CNAME target. This
repository is public and self-contained: never cite a document, identifier, or
issue that lives in a private repository. State the property directly instead.
