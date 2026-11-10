# easyssl-agent

The easySSL Agent: a single, auditable Go binary that registers a
host with an easySSL Server, polls for certificate configuration, deploys
certificates through on-demand plugins, and reports inventory and health.

Everything that runs on the Agent side has its source published, so it can be
independently inspected and audited. The Agent is under FSL-1.1-ALv2
(`LICENSE.md`): you may patch it for your own hosts without sharing the
patches, but not ship it in a competing product.

Connections are only ever initiated from the Agent to the Server, so the Agent
can run inside an isolated network zone.

The shared Agent-to-Server contract lives in the separate `easyssl-contract`
module; wire types are not duplicated here.

## Commands

```
easyssl-agent register --server <url> [--registration-key <key>] [--agent-name <name>] [--lang <code>]   register this host
easyssl-agent register --server <url> --reactivation-token <token>    resume a deactivated Agent on this host
easyssl-agent run                                                     the service loop (periodic check-in)
easyssl-agent status                                                  print local state and what the Server says
easyssl-agent uninstall [--yes]                                       deactivate and remove the Agent
easyssl-agent migrate                                                 move what the Plugins serve out of certbot's directories
easyssl-agent language [<code>]                                       print or change the language the commands speak
```

Output goes to stdout and errors to stderr, both written in the host's language
(Language below). A failure exits non-zero, including a declined prompt. The CLI
is for a person: it has no machine-readable output, and its text may change.
This slice is root-only: every operational command refuses before reading a
specific file or contacting the Server when run as another user, and names the
corresponding `sudo easyssl-agent …` command. Top-level help and usage errors do
not need root.

## The connection to the Server

`--server` must be an `https://` URL, and the Agent refuses to start with
anything else. Everything it sends is either a credential or a secret: the
Organization registration key, the bearer token that stands for this host
afterwards, and the private key material of every certificate it installs.

Certificate verification is never relaxed. There is no flag, environment
variable or configuration file entry that turns it off, and no code path that
sets one: the Agent uses Go's defaults, which verify the chain against the
host's trust store and the hostname against the URL. Add your CA to the host's
trust store if the Server presents a private certificate.

A redirect that changes the scheme is refused rather than followed. Go drops
the `Authorization` header when a redirect crosses to an unrelated host, but it
compares hostnames only, so a redirect from `https://server` to `http://server`
would otherwise send the bearer token in the clear.

`http://` is accepted for `localhost`, `127.0.0.0/8` and `::1`, so a Server
running on the same machine during development needs no certificate. It is
restricted to loopback deliberately: no real host can be reached that way, so
there is nothing to get wrong by copying a working command off a laptop.

## How registration works

A host runs a single Agent. `register` runs an interactive line-based session.
It settles the language first (Language below), so everything after it is read
in the language chosen, and then:

1. Resolves the credential: the Organization registration key from `--registration-key` or
   `EASYSSL_REGISTRATION_KEY`, or a reactivation token from `--reactivation-token` or
   `EASYSSL_REACTIVATION_TOKEN`. When neither is set it prompts once, and either may
   be pasted: a token starts with `esrt_`, a key with `esrk_`.
2. With a registration key, resolves the Agent's name: `--agent-name` or
   `EASYSSL_AGENT_NAME` if given, otherwise the host's hostname offered as an editable
   default at the prompt. A reactivation token names an Agent that already has
   a name, so nothing is asked.
3. Captures best-effort host diagnostics (hostname, OS, host type) and submits
   the registration. The Server names Agents: it mints the public id
   (`agnt-…`) and returns it with a one-time bearer token. The host persists
   the Server URL in `/etc/easyssl/config.json` and the token in
   `/var/lib/easyssl/agent.token`, both root-only (`0600`), and
   neither the id nor the name: both are the Server's to say, and any
   authenticated call answers them. The Server keeps only the token's hash.
4. Installs and starts the service, which runs `run` to check in
   periodically, under whichever init system the host runs:

   | Init system | Service | Restarts on exit | Output |
   |---|---|---|---|
   | systemd | `easyssl-agent.service` | yes | journal |
   | OpenRC | `/etc/init.d/easyssl-agent` under `supervise-daemon` | yes | `/var/log/easyssl-agent.log` |
   | runit | `/etc/sv/easyssl-agent`, linked into the watched service directory | yes | `/var/log/easyssl-agent/current` (svlogd) |
   | sysvinit | `/etc/init.d/easyssl-agent` via `start-stop-daemon`, enabled with `update-rc.d`, `chkconfig` or `insserv` | no | `/var/log/easyssl-agent.log` |
   | BusyBox init | a `respawn` line in `/etc/inittab` | yes | `/var/log/easyssl-agent.log` |

   The init system is the one running as PID 1. On any other, `register`
   refuses before contacting the Server; run `easyssl-agent run` under the
   host's own supervisor instead.
5. With a registration key, prints the web console Plugin Marketplace URL, then
   waits for an operator to authorize the Agent. The URL remains visible if
   the wait is interrupted; the installed service keeps polling, so
   authorization can complete later. With a reactivation token the Agent is
   active at once, minting the token having been the operator's review, and
   the installer offers to install the Plugins its Targets are configured with
   and this host lacks, so the first Deployment does not fail for want of one.

Re-running the installer on an already-registered host is idempotent: it
refreshes the binary, restarts the service, and reports the current state
instead of registering a second Agent. If the Server no longer accepts the
host's token, because the Agent was deactivated or removed in the web console,
the installer registers the host again with whatever credential this run was
given: a reactivation token resumes the same Agent, a registration key makes a
new one.

The installer is served by the Server, so the usual one-liner is:

```
curl -fsSL <server-url>/install | sudo EASYSSL_REGISTRATION_KEY=<key> bash
```

The prompts still work in that form: the script arrives on stdin, so the Agent
reads the operator from the controlling terminal (`/dev/tty`) instead. Where
there is no terminal at all (cloud-init, CI), pass the name up front and it
never prompts:

```
curl -fsSL <server-url>/install | sudo EASYSSL_REGISTRATION_KEY=<key> EASYSSL_AGENT_NAME=web-01 bash
```

A deactivated Agent's page in the web console generates the reactivation form
of the same command, with a single-use token that expires after a day:

```
curl -fsSL <server-url>/install | sudo EASYSSL_REACTIVATION_TOKEN=<token> bash
```

## Language

The Agent's commands speak English (`en`) or Spanish (`es`). A regional variant
(`es-PE`, `es_419`) is its base language.

The installer's first step, before it prints anything else, offers each language
under its own name with a default marked; Enter accepts it, and the number or
the code chooses another:

```
Language / Idioma
    1  English (en)
  * 2  Español (es)
[2]:
```

The default is the first of these that names a supported language:

1. `EASYSSL_LANG`, which the install command given by the web console carries,
   set to the language its reader uses there.
2. The language already saved on a host that is being re-registered.
3. The operating system's locale: the first of `LC_ALL`, `LC_MESSAGES` and
   `LANG` that is set.
4. English.

`--lang <code>` decides without asking, and a code that is not supported is
refused. Without a terminal (cloud-init, CI) nothing is asked and the default is
taken. `EASYSSL_LANG` deliberately does not skip the step: every command the web
console gives carries it, and the host's operator may read another language
than whoever copied the command.

The choice is saved as `language` in `/etc/easyssl/config.json` and every later
command speaks it. `easyssl-agent language` prints it and `sudo easyssl-agent
language <code>` changes it; re-running the installer asks again. `EASYSSL_LANG`
overrides the saved language for one run:

```
sudo EASYSSL_LANG=en easyssl-agent status
```

A configuration with no language reads as the locale's, else English. A yes/no
prompt accepts the language's own affirmative (`s`, `sí` in Spanish) and always
`y`.

Only what a command says to a person is translated. These are the same in every
language: the service's logs and its status line, everything
sent to the Server, the files written to the host, exit codes, and whatever a
Plugin or another program printed. The flag package's own text under `--help`
(default values, its parse errors) is in English too. The Server is never told
the host's language; a text the Agent writes for the web console, the warning
for a Plugin that did not answer `describe` or `discover`, is sent in every
language so each reader gets their own.

A Plugin's own text (its Marketplace description in `easyssl-agent plugin
catalog`) is shown in the host's language when the Plugin supplies it, and in
English otherwise.

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

## Files another ACME client manages

A file that certbot, acme.sh, dehydrated or lego rewrites on its own schedule is
not one easySSL deploys to, since that client would undo the Deployment or be
broken by it. The Agent decides this itself, on every value of a setting a
Plugin declares as a path: it is managed when it lies, as written or with
symlinks followed, in a certbot directory (`/etc/letsencrypt`, any directory a
certbot command in a systemd unit or cron entry names with `--config-dir`, the
`config-dir` of a `cli.ini`, or one a lineage's layout reveals), when it holds
the current certificate of a certbot lineage (what a deploy hook's copy looks
like), or when it lies in acme.sh's, dehydrated's or lego's default directory.
Such a certificate is reported with a warning saying what to do, so it is never
suggested as a Target, and a Deployment to such a path fails before its Plugin
runs.

`sudo easyssl-agent migrate` moves certificates out of certbot's directories.
It lists the ACME clients it found and what it can move, asks which to move,
shows every file it will copy and every configuration line it will change, and
only after a yes copies each file to `/etc/ssl/easyssl/<name>/` (keeping its
owner, group and mode, and never overwriting anything) and asks each Plugin to
point its configuration at the copies, which the Plugin tests and reloads, and
undoes if that fails. certbot itself is left alone: the command only prints the
`certbot delete` that stops a lineage renewing once nothing its Plugins read
uses it. It then sends the host inventory, so the web console suggests the
moved certificates straight away.

## Checking state

`status` prints what the host knows (Server URL, Organization, the service
and whether it is running, whether a token is stored) and then asks the
Server what this Agent actually is: its id and name, and `authorized`,
`pending authorization`, or no longer registered because it was deactivated or
removed there. A stored token proves only that one was issued once, so
registration is never inferred locally, and the id and name are printed only
when the Server answered.

Asking is a plain read (`GET` on the Agent's own registration), not a check-in,
so running `status` never refreshes the Agent's last-seen and cannot make a
stopped Agent look alive in the web console. When the Server cannot be reached,
the state is reported as unknown with the reason, and the local facts still
print.

## Seeing what a Plugin was asked to do

The Agent hands work to a Plugin over stdio: the operation on argv, JSON in,
and out either JSON (`describe`, `discover`) or the process's own exit status
and streams (`deploy`). None of that is visible by default, and what reaches
the Server is only the Plugin's own account of itself, so an argument the Agent
got wrong, or a Plugin that failed before printing anything, leaves no trace
anywhere.

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

A deploy request carries the certificate's private key, which is why the two
are not one switch: the journal persists, is readable by anyone in
`systemd-journal`, and is usually shipped off the host, so enabling key logging
has to be a decision of its own. Naming a file for the keys to go into is what
makes it one. Delete the file when you are done.

## Private keys

Every certificate's private key is generated here, on this host, and never sent
anywhere. The Server receives only a certificate signing request, so it has no
key to store and none to lose.

```text
/var/lib/easyssl/keys/<fingerprint>.key    the key, PKCS#8 PEM, ECDSA P-256
```

A key is named by the SHA-256 of its own public key, so the directory can be
checked against itself and one key can serve several certificates without the
secret being copied. Which certificate uses which key is the Server's record,
taken from the public key of each signing request it accepts, and every
request or deployment names the key it is about; the host keeps no copy of that
link. The directory is `0700`, the files are `0600`, and everything is owned by
root. Nothing about the format is specific to easySSL:

```bash
sudo openssl pkey -in /var/lib/easyssl/keys/<fingerprint>.key -noout -text
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

`easyssl-agent uninstall` takes the Agent off the host. It first tells the
Server the token is done with, which **deactivates** the Agent rather than
removing it: the token stops working, and the Agent's Targets, key records and
history stay in the web console, where a reactivation command can bring the
same Agent back on this host or another. Then, whether or not the Server could
be reached, it stops and removes the service, deletes `/etc/easyssl/config.json`
and `/var/lib/easyssl/agent.token`, and deletes the binary. It asks for confirmation,
refusing to run unattended unless `--yes` is passed, and is idempotent on a
host with nothing or only remnants installed.

When the Server cannot be reached the local removal still completes and the
output says, in as many words, that the Server still accepts the host's token
and that the Agent has to be deactivated from the web console, naming the
Server, the Organization and the host. Removing the Agent for good, which
erases its Targets, is only ever done from the web console, and only on an
Agent that is already deactivated: a host can never remove its own record.

Two more things are offered afterwards, each behind its own prompt and only
when there is a terminal. `--yes` consents to uninstalling the Agent, not to
everything it could take with it, so an unattended run leaves both in place and
says where they are.

- **Plugins.** The executables under `/var/lib/easyssl/plugins/` are listed and
  the directory is deleted on a `y`.
- **Private keys.** The keystore under `/var/lib/easyssl/keys/` is the Agent's only
  copy of them, and nothing recovers a deleted key: a Certificate whose key is
  gone cannot be deployed or renewed from the host again, and reactivating the
  Agent on another host needs the files copied there first. So the prompt says
  so, defaults to keeping them, and deletes only when `delete keys` is typed
  out. Copies a Deployment installed elsewhere on the host are never touched.

Certificates and keys the Agent deployed elsewhere on the host are always left
in place, since deleting them could take the host's own services down.
Uninstall is host-side only: the Server can never trigger it.

This slice is Linux-only and root-only; the Agent stores no encryption key
and sends none to the Server.
