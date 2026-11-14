# Changelog

Every release of the easySSL Agent, newest first. `scripts/release.sh` tags
no version this file has no entry for.

## 0.2.5

Built against `easyssl-contract` 0.2.3. A command's help runs without root
also after a flag that takes a value (`register --server <url> --help`): the
root check reads the arguments with the command's own flags.

## 0.2.4

Built against `easyssl-contract` 0.2.3.

- `easyssl-agent migrate` asks the Plugins to leave a note on each
  configuration line they change, in the host's language: "now managed by
  easySSL; check nothing else here still uses /etc/letsencrypt".
- The warnings on a path another ACME client manages read the same for one
  path or several ("Certbot manages `/etc/letsencrypt`, …"), since the web
  console lists several paths under one copy.
- Every command's `-help` prints its usage and what it does, and lists flags
  only when it has some; a command's help runs without root.

## 0.2.3

- Built with Go 1.26.11, which fixes GO-2026-6859 in `net/http`.
- `easyssl-agent update` and `plugin update` hold a host-wide lock while they
  change the installed builds, so a second one refuses at once instead of
  overwriting the first's kept build, which could leave no working Agent to
  roll back to.

## 0.2.2

- `easyssl-agent update` updates the Agent to the build the Server's catalog
  offers, checking its SHA-256 and that it runs before swapping it in, keeping
  the previous build and putting it back if the service does not check in on
  the new one; then it updates the Plugins. `--agent-only` leaves the Plugins
  alone, `--check` only says what would change, and an older build is never
  taken. It refuses, before replacing anything, an Agent build that would
  refuse an installed Plugin. Built against `easyssl-contract` 0.2.1, whose
  catalog names the Agent build.
- `easyssl-agent plugin update [name...]` installs the catalog's build of each
  installed Plugin whose bytes differ; one the catalog no longer offers, or
  offers at a lower version, is left as it is unless `--allow-downgrade` is
  passed. The plan shows each Plugin's installed and offered versions.
- A Plugin build on a contract this Agent does not run is never downloaded:
  `update` and `plugin update` leave it and say it needs a newer Agent, and
  `plugin install` refuses it, like any Plugin it could not install, before
  asking to authorize the install. The refusal names the contract this Agent
  speaks and the ones it runs.
- `easyssl-agent plugin list` and `plugin catalog` show each Plugin's contract
  version; `plugin catalog` no longer prints the party.
- `easyssl-agent version` prints the version alone; `--contract` the contract
  version it speaks, `--contracts` the ones it runs a Plugin built against.
- A Server that no longer speaks this Agent's contract version is reported as
  such: `easyssl-agent status` says the Agent is refused and to run
  `sudo easyssl-agent update`, the service logs it at error level, and its
  systemd status line says so, instead of reading as unreachable or healthy.
- `easyssl-agent uninstall` also removes the builds `update` keeps beside the
  binary, `easyssl-agent.prev` and `easyssl-agent.new`.

## 0.2.1

Fixes in what 0.2.0 added.

- A Target path with `..` after a symlink (`/opt/alias/../x`) is checked where
  the kernel opens it: it was checked as if `..` applied to the name, so a
  Deployment into certbot's directories through such a path was not refused.
- `easyssl-agent migrate` checks the directories of copies an earlier run left,
  and reuses only a file that is exactly the copy (not a symlink, same owner,
  group and mode), before the confirmation and again before changing any
  configuration.
- `easyssl-agent migrate` no longer hangs when `/etc/ssl/easyssl` or a
  certificate's directory there is not a directory; it says why and stops.

## 0.2.0

Built against `easyssl-contract` 0.2.0. It still runs 0.1 Plugins, and a
Server answers it and 0.1 Agents alike.

- Knows the directories other ACME clients manage (certbot's, read from its
  systemd units, cron jobs and `cli.ini`, and acme.sh's, dehydrated's and
  lego's defaults): a discovered certificate there carries a warning and is
  not suggested, and a Deployment there is refused before any Plugin runs.
- Adds `easyssl-agent migrate`, which moves the certificates such a client
  manages into `/etc/ssl/easyssl` and points the web server at the copies
  through the Plugin's `relocate`, after confirming each move, so easySSL can
  take over their renewal. It names a Plugin too old to relocate.
- Refuses a destination directory a non-root user could change before writing
  a private key into it.
- Ctrl+C at an interactive prompt ends the command.

## 0.1.0

The first release, built against `easyssl-contract` 0.1.0.

- Installed by the Server's install script, it runs as a service under
  systemd, OpenRC, runit or sysvinit.
- Registers with an Organization's registration key, or with a reactivation
  token for a deactivated Agent, then checks in, runs the commands the Server
  queues, and reports the host's inventory.
- Generates each private key on the host and sends the Server only CSRs; no
  private key leaves the host.
- Installs Plugins from the Server's catalog after checking each one's
  SHA-256, and runs them to discover and deploy Certificates.
- An interactive CLI (`register`, `run`, `status`, `uninstall`, `plugin`,
  `language`) in English and Spanish.
- Source-available under the Functional Source License (FSL-1.1-ALv2), which
  becomes Apache-2.0 two years after each release.
