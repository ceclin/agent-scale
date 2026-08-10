# Control-Managed Private Relay

Every private `as-relay` deployment, including a single-user personal relay,
uses `as-control` as its authorization authority. Simple mode remains available
for the official iroh relay network and ordinary custom relay URLs, but it does
not issue credentials for a private Relay.

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
the Relay can restart from its cached, verified revocation state while Control is down.

`as-relay run` requires the Control profile created by `as-relay join`. There is
no Client-signed initialization mode and no remote state mutation endpoint.
Clients and Edges receive EndpointId-bound credentials in their signed NodeMaps;
the Relay verifies those credentials locally and long-polls Control only for
signed, revisioned revocation deltas. Enrollment therefore does not wait for
every Relay to acknowledge a new topology revision, and iroh remains free to
select the best Relay from the complete catalog.

Adding a Client or Edge sends no authorization update to Relays. A removal
sends one small delta to each enrolled Relay, so this path scales with the Relay
count rather than the total Client and Edge population.

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

## Authorization and Failure Behavior

Credentials are valid for seven days and are renewed through the normal Control
watch before their final two days. Each credential is bound to the Control
audience, EndpointId, subject kind, and generation. Removing a Client or Edge
adds a signed generation tombstone; Relays merge and persist the delta
before activating it and disconnect that EndpointId immediately.

The Relay keeps the last verified state in
`/var/lib/agent-scale-relay/revocations.json`. If Control is temporarily
unavailable, unexpired credentials continue to work across Relay restarts;
enrollment, renewal, and revocation changes wait for Control to return. Removing
the Relay with `as-control relay rm prod-sg` durably marks that enrollment as
revoked and disconnects all clients. Re-enrollment requires a fresh Relay state
directory and identity.

Relay authorization controls relay resource use. Edge command access remains
independently protected by the Edge's pinned Client identity.
