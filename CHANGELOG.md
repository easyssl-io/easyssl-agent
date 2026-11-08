# Changelog

Every release of the easySSL Agent, newest first. `scripts/release.sh` tags
no version this file has no entry for.

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
