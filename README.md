# easyssl-client

The open-source easySSL Client: a single, auditable Go binary that registers a
host with an easySSL Server, polls for certificate configuration, deploys
certificates through on-demand plugins, and reports inventory and health.

Everything that runs on the Client side is open source, so it can be
independently inspected and audited. Connections are only ever initiated from
the Client to the Server, so the Client can run inside an isolated network zone.

The shared Client-to-Server contract lives in the separate `easyssl-contract`
module; wire types are not duplicated here.

