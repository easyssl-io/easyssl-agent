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

`easyssl-contract` is required at a released version, so a clone of this
repository builds on its own.

`register`, `run` and `uninstall` drive the host's init system, `/etc/easyssl/`, `/var/lib/easyssl/`
and the network, so they are exercised on a real Linux host or a container
running an init system; `internal/service`'s tests cover each init system's
files and commands against a fake root.

## Code Review Rules

Everything here runs on a customer's machine, and its source is published so
they can verify what it does. Flag any of the following.

- **Standard library first.** A new third-party dependency is a finding unless
  the change says why the standard library cannot do the job. The binary also
  installs on constrained devices, so capabilities not every install needs do not
  belong in it.
- **The Agent only ever dials out.** No listening socket, no inbound callback,
  no Server-triggered action. The Server can never make an Agent uninstall
  itself; that is a host-side decision.
- **Server traffic goes through `internal/serverapi`, with one exception that is
  a known gap.** It is meant to be a single funnel so an audit mode can later
  record every interaction with no unaudited paths. `pluginmgr.HTTPCatalog` is
  not in it: its two requests, fetching the Marketplace catalog and downloading
  a Plugin artifact, reach the Server without going through `serverapi`. Both
  construction sites in `cmd/easyssl-agent` leave its `HTTP` field unset, so the
  requests run on the process-wide `http.DefaultClient`, which carries no
  timeout. Three call sites issue them, and the funnel is not complete until all
  three move behind the wrapper. The rest of `pluginmgr` is in it: it reports an
  installed Plugin through `serverapi` like everything else.
  Anywhere else, a direct `http.Get` or a new `http.Client` is a finding even
  when it works. Inside `serverapi`, `SubscribeCommands` builds its own
  client deliberately, the shared 30-second timeout being one that would sever a
  stream meant to stay open.
- **No private key material reaches the Server**, sent or logged. P0.
- **Secrets stay root-only**, `0600` under `/var/lib/easyssl/`, never printed.
- **Local state is not proof.** A stored token means one was issued once, not
  that this Agent is still registered or authorized; that comes from the Server.
  A status read must not count as a check-in, or a stopped Agent can be made to
  look alive.
- **The two sides upgrade independently.** An installed Agent cannot be forced
  to update, so changes must tolerate a Server older or newer than this build.
- **Reinstall reconciles, never duplicates.** One host runs one Agent, keyed by
  a stable instance ID, and every install step must be safe to interrupt.
- **CLI contract.** Output on stdout for a person, errors on stderr, non-zero
  exit on failure, a declined prompt included. The CLI offers no
  machine-readable output and promises scripts nothing beyond success or
  failure, so its wording stays free to change.

## Messages

Everything a command says to a person goes through `internal/msg`: output,
prompts, errors that reach stderr, usage and flag help.

- **An explicit ID, the English beside it.** `msg.T("uninstall.aborted",
  "Aborted; nothing was changed.")`. The ID names where the message appears,
  lowercase and dotted; it is never derived from the English, and two places do
  not share one because their English happens to match.
- **One sentence is one message.** Values are named placeholders (`{path}`)
  filled by `"path", value` pairs, which a translation may reorder. Never
  concatenate translated fragments. A message that depends on a count uses
  `msg.N` with `{n}`.
- **Literals are not translated**: commands, flags, paths, environment
  variables, Plugin ids, URLs and `easySSL` stay as they are inside every
  language's text.
- **An error is `msg.Err.T(id, english, args...)`.** It is rendered when read,
  so a package-level sentinel speaks the host's language and `errors.Is` keeps
  working; an error passed as an argument is wrapped, as `%w` would.
- **A text sent to the Server is `msg.Text`**, which carries every language,
  because its reader is not this host's. An error sent there is
  `msg.TextOf(err)`: every language of one made with `msg.Err.T`, and English
  alone of any other, whose words are whatever produced it.
- **Spanish goes in `internal/msg/locales/es.json`** in the same change: neutral
  Spanish addressing the reader as "tú", as short as the English, with
  Organización, Usuario, Agente, Servidor, consola web, Plugin, Marketplace,
  Certificado, Destino, Despliegue and Clave for the domain names.
- **`TestCatalog` in `internal/msg` is the check.** It reads every `T`, `N` and
  `Text` call in the module and fails on a message with no translation, a
  translation no message uses, one ID with two English texts, or placeholders
  that differ. The English must be a string literal for it to read.
- **What is not for a person does not vary with the language**: the service's logs (`run` switches to English once it has started), anything
  sent to the Server, files written to the host, exit codes. A change that makes
  any of them depend on the language is a finding.
- **Adding a language is a catalog**, `locales/<code>.json`, once
  `easyssl-contract` lists the code. Nothing changes where messages are used.

## Conventions

American English. Capitalize Organization, Agent, Server, Plugin, Certificate,
Target and Deployment whenever they name easySSL's own records or components;
write "web console" in full for easySSL's browser UI. Keep a genuinely generic
technical role lowercase, such as an ACME client or a CNAME target. This
repository is public and self-contained: never cite a document, identifier, or
issue that lives in a private repository. State the property directly instead.
