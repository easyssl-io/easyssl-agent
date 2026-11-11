# Changelog

Every release of the easySSL Agent, newest first. `scripts/release.sh` tags
no version this file has no entry for.

## Unreleased

- A Server that no longer speaks this Agent's contract version is reported as
  such: `easyssl-agent status` says the Agent is refused and how to update it,
  the service logs it at error level, and its systemd status line says so,
  instead of reading as unreachable or healthy.

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
