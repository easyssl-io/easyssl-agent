# easyssl-agent

The open-source easySSL Agent: a single, auditable Go binary that registers a
host with an easySSL Server, polls for certificate configuration, deploys
certificates through on-demand plugins, and reports inventory and health.

Everything that runs on the Agent side is open source, so it can be
independently inspected and audited. Connections are only ever initiated from
the Agent to the Server, so the Agent can run inside an isolated network zone.

The shared Agent-to-Server contract lives in the separate `easyssl-contract`
module; wire types are not duplicated here.

## Commands

```
easyssl-agent register --server <url> [--key <key>] [--name <name>]   register this host
easyssl-agent run                                                     the systemd service loop (periodic check-in)
easyssl-agent status [--json]                                         print local state and what the Server says
easyssl-agent uninstall [--yes]                                       unregister and remove the Agent
```

Human-readable output goes to stdout (JSON with `--json`); errors go to stderr.
This slice is root-only: every operational command refuses before reading a
specific file or contacting the Server when run as another user, and names the
corresponding `sudo easyssl-agent …` command. Top-level help and usage errors do
not need root.

## How registration works

A host runs a single Agent. `register` runs an interactive line-based session:

1. Resolves the Organization registration key from `--key` or the
   `REGISTRATION_KEY` environment variable, prompting for it when neither is set.
2. Resolves the Agent's name: `--name` or `AGENT_NAME` if given, otherwise the
   host's hostname offered as an editable default at the prompt.
3. Generates a stable 16-hex **instance ID** once and persists it, then captures
   best-effort host diagnostics (machine ID, hostname, OS, host type). If the
   Server reports the instance ID is already taken, the installer regenerates it
   and retries.
4. Checks in with the Server, which returns a one-time bearer token. The config
   and token are stored root-only (`0600`) under `/etc/easyssl/`; the Server
   keeps only the token's hash.
5. Installs and starts the systemd unit `easyssl-agent.service`, which runs
   `run` to check in periodically.
6. Prints the web console Plugin Marketplace URL, then waits for an operator to
   authorize the Agent. The URL remains visible if the wait is interrupted;
   the installed service keeps polling, so authorization can complete later.

Re-running the installer on an already-registered host is idempotent: it
refreshes the binary, restarts the service, and reports the current state
instead of registering a second Agent. If the Agent was removed from the
web console, the reinstall re-registers it under the same instance ID.

The installer is served by the Server, so the usual one-liner is:

```
curl -sSL <server-url>/install | sudo REGISTRATION_KEY=<key> bash
```

The prompts still work in that form: the script arrives on stdin, so the Agent
reads the operator from the controlling terminal (`/dev/tty`) instead. Where
there is no terminal at all (cloud-init, CI), pass the name up front and it
never prompts:

```
curl -sSL <server-url>/install | sudo REGISTRATION_KEY=<key> AGENT_NAME=web-01 bash
```

## Receiving work from the Server

Once authorized, the Agent holds one long-lived connection open to the Server
and asks for outstanding work whenever the Server nudges it. It also asks on
every check-in regardless, and that is the part that guarantees the work
happens: the connection only makes it prompt. So an Agent behind a proxy that
kills idle connections, or one that simply cannot keep the stream up, still does
everything asked of it, just at check-in speed.

A dropped connection is ordinary rather than a fault, and the service reconnects
with a widening delay without ever exiting. The one thing it does not retry is a
rejected credential: if the Server no longer recognizes the token, waiting
cannot repair it and re-registration is required.

Work is reported finished only after its outcome has been recorded, never
before. An Agent that dies in between is handed the same instruction again on
restart, which is why running one twice has to be safe.

## Checking state

`status` prints what the host knows (instance ID, name, Server URL, the systemd
unit and whether it is running, whether a token is stored) and then asks the
Server what this Agent actually is: `authorized`, `pending authorization`, or
no longer registered because it was removed or revoked there. A stored token
proves only that one was issued once, so registration is never inferred locally.

Asking is a plain read (`GET` on the Agent's own registration), not a check-in,
so running `status` never refreshes the Agent's last-seen and cannot make a
stopped Agent look alive in the web console. When the Server cannot be reached,
the state is reported as unknown with the reason, and the local facts still
print. `--json` reports a short stable code (`authorized`, `pending`,
`not-registered`, `unknown`) instead of the sentence.

## Seeing what a Plugin was asked to do

The Agent hands work to a Plugin over stdio: the operation on argv, JSON in,
JSON out. None of that is visible by default, and what reaches the Server is
only the Plugin's own account of itself, so an argument the Agent got wrong, or
a Plugin that failed before printing anything, leaves no trace anywhere.

Two switches make it visible, and they are separate because they differ in one
respect that matters.

**`EASYSSL_LOG_LEVEL=debug`** logs every exchange with the private key removed:
the operation, the binary, the arguments, the request, the response, the
Plugin's stderr, its exit code and how long it took. Safe to leave on, safe on
somebody else's host, safe to paste into an issue.

```sh
sudo systemctl edit easyssl-agent      # [Service] / Environment=EASYSSL_LOG_LEVEL=debug
sudo systemctl restart easyssl-agent
journalctl -u easyssl-agent -f
```

The same variable works on the subcommands, so `EASYSSL_LOG_LEVEL=debug
easyssl-agent plugin install <name>` shows the `describe` exchange without the
service in the way. That is usually the one you want while writing a Plugin:
what a build declares about itself is where it most often disagrees with what
its author meant.

**`EASYSSL_LOG_FORMAT=json`** switches the Agent to the same JSON lines the
Server writes, which turns reading an exchange into one `jq` call rather than a
parser for Go's quoting:

```sh
journalctl -u easyssl-agent -f -o cat \
  | jq -r 'select(.msg == "plugin exchange") | .stdin'
```

The redacted request stays valid JSON — the placeholder that replaces the key
carries no newline of its own, for exactly this reason — so `| jq .` on that
output works too. Text remains the default, since somebody reading
`journalctl` without a pipeline should not have to.

**`EASYSSL_PLUGIN_TRACE=<path>`** writes the literal bytes of every exchange to
that file, private key included, mode 600, with a warning at the top of the
file and one in the journal saying it is on. Only for the rare case where the
exact bytes matter, and never set by the installer.

An install request carries the certificate's private key, which is why the two
are not one switch: the journal persists, is readable by anyone in
`systemd-journal`, and is usually shipped off the host, so enabling key logging
has to be a decision of its own. Naming a file for the keys to go into is what
makes it one. Delete the file when you are done.

## Private keys

Every certificate's private key is generated here, on this host, and never sent
anywhere. The Server receives only a certificate signing request, so it has no
key to store and none to lose.

```text
/etc/easyssl/keys/<fingerprint>.key    the key, PKCS#8 PEM, ECDSA P-256
/etc/easyssl/certs/<certificate>.json  names the key that certificate uses
```

A key is named by the SHA-256 of its own public key, so the directory can be
checked against itself and one key can serve several certificates without the
secret being copied. Both directories are `0700`, the files are `0600`, and
everything is owned by root. Nothing about the format is specific to easySSL:

```bash
sudo openssl pkey -in /etc/easyssl/keys/<fingerprint>.key -noout -text
```

**What this protects against, and what it does not.** The keys are stored
unencrypted, and filesystem permissions are the whole of their protection.
Anyone who is root on this host, or who holds a backup or a disk image of it,
holds the private keys. There is deliberately no passphrase: the Agent renews
and deploys certificates unattended, so any key that unlocked the keystore would
have to sit on the same disk and would stop nobody who could already read it.

**Nothing is ever deleted.** There is no pruning, no expiry sweep and no purge
command. A new key is generated for every issuance, renewals included, so the
keystore grows by one key each time a certificate is renewed, and every key
stays until an operator removes it by hand. Deleting a key is the one operation
here with no recovery, which is why the Agent does not do it at all.

## Uninstalling

`easyssl-agent uninstall` removes the Agent from the host: it unregisters
itself from the Server first (so the host also disappears from the web console),
then stops and removes the systemd unit, deletes the config and token from
`/etc/easyssl/`, and deletes the binary. It asks for confirmation, refusing to
run unattended unless `--yes` is passed, and is idempotent on a host with
nothing or only remnants installed. If the Server cannot be reached the local
removal still completes and you are told the Agent may still be listed in the
web console.

**Private keys are not deleted, and uninstall says so.** They are the only copy
on this host, and an uninstall is too ordinary a command to destroy something
unrecoverable, so `/etc/easyssl/keys/` and `/etc/easyssl/certs/` survive it and
the command reports how many keys remain. If the machine is being
decommissioned, delete that directory by hand; if certificates using those keys
are still in service, keep a copy first.

Certificates and keys the Agent deployed elsewhere on the host are also left in
place, since deleting them could take the host's own services down. Uninstall is
host-side only: the Server can never trigger it.

This slice is Linux + systemd and root-only; the Agent stores no encryption key
and sends none to the Server.
