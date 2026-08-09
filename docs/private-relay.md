# Control-Managed Private Relay

Every private `as-relay` deployment, including a single-user personal relay,
uses `as-control` as its authorization authority. Simple mode remains available
for the official iroh relay network and ordinary custom relay URLs, but it does
not administer a private relay allowlist.

## Enroll and Run a Relay

Initialize and run Control as described in [control-plane.md](control-plane.md),
then create a relay invitation on the Control host:

```sh
as-control relay invite prod-sg https://relay.example.com
```

On the relay host, claim the invitation once and start the service from the same
state directory:

```sh
as-relay join '<join-url>' --qad-port 4433 \
  --state-dir /var/lib/agent-scale-relay
as-relay run \
  --relay-bind 127.0.0.1:3340 \
  --admin-bind 127.0.0.1:3341 \
  --qad-bind 0.0.0.0:7842 \
  --state-dir /var/lib/agent-scale-relay
```

For unattended first startup, combine enrollment and serving:

```sh
as-relay run \
  --join-if-needed /run/secrets/relay.join \
  --control-url https://control.example.com \
  --relay-bind 127.0.0.1:3340 \
  --admin-bind 127.0.0.1:3341 \
  --qad-bind 0.0.0.0:7842 \
  --qad-port 4433 \
  --state-dir /var/lib/agent-scale-relay
```

Once `control.json` exists, the invitation file and Control URL are ignored;
the Relay can restart from its verified offline snapshot while Control is down.

`as-relay run` requires the Control profile created by `as-relay join`. There is
no Client-signed initialization mode and no remote snapshot mutation endpoint.
The relay actively long-polls Control for complete, signed membership snapshots.

`--qad-port` is the externally reachable UDP port that the Relay reports to
Control; Control persists it and distributes it to Clients and Edges in the
signed NodeMap. An enrolled Relay started with a different explicit
`--qad-port` signs and reports the update before its next long poll completes.
Omitting it on later starts retains the enrolled value; changing only
`--qad-bind` never changes the public port. `--qad-bind` is the Relay process's
local UDP address. During
first-run `as-relay run --join-if-needed`, an omitted `--qad-port` defaults to
the port in `--qad-bind`; standalone `as-relay join` defaults it to `7842`
because it has no bind address. The public and bind ports may differ, for
example with `4433/udp -> 7842/udp` behind Docker or NAT. The Relay cannot infer
an external NAT or container port mapping, so configure `--qad-port` explicitly
in that case. QAD is enabled by default; pass `--no-qad` to `as-relay join` or
first-run `as-relay run --join-if-needed` to disable it. QAD lets iroh discover each
endpoint's observed UDP address and materially improves direct hole-punching;
Relay traffic still falls back to the WebSocket data plane when a direct path
cannot be made.

Control owns a private Relay CA. During enrollment the Relay generates its TLS
key locally and sends a signed CSR; Control returns a certificate whose SAN is
restricted to the host in the invited Relay URL. The CA certificate and QAD port
are covered by Control's signed NodeMap, so no certificate or CA file needs to
be installed manually on individual Relays, Clients, or Edges. Back up the
entire Control state directory, including `relay-ca.key` and `relay-ca.der`.

The WebSocket and admin listeners use plain HTTP. Put TLS in front of the public
relay listener in production; its proxy route must preserve WebSocket upgrade
headers. Keep the administrative listener private. It exposes only `/healthz`
and the read-only `/v1/status` endpoint. QAD is a separate UDP/QUIC listener and
already uses the Control-issued TLS certificate; do not send it through the
HTTP reverse proxy.

iroh captive-portal detection requires plain HTTP access to the exact
`/generate_204` path and does not follow redirects. Route only that path to the
Relay ahead of any HTTPS redirect; the Relay returns `204 No Content` with the
matching `X-Iroh-Response`. Redirecting it causes a false captive-portal report.
This is an iroh requirement, not an agent-scale management endpoint.

## Membership and Failure Behavior

Control derives relay membership from its committed Client, Edge, and Relay
topology. Accepted snapshots are flushed and atomically renamed before becoming
active. Removed EndpointIds are disconnected immediately.

The relay keeps the last verified snapshot in
`/var/lib/agent-scale-relay/membership.json`. If Control is temporarily
unavailable, existing authorized connections and relay restarts continue from
that snapshot; new allocations and authorization changes wait for Control to
return. Removing the relay with `as-control relay rm prod-sg` causes its watcher
to fail closed and disconnect all clients.

Relay authorization controls relay resource use. Edge command access remains
independently protected by the Edge's pinned Client identity.
