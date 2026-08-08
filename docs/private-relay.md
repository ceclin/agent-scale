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
as-relay join '<join-url>' --state-dir /var/lib/agent-scale-relay
as-relay run \
  --relay-bind 127.0.0.1:3340 \
  --admin-bind 127.0.0.1:3341 \
  --state-dir /var/lib/agent-scale-relay
```

For unattended first startup, combine enrollment and serving:

```sh
as-relay run \
  --join-if-needed /run/secrets/relay.join \
  --control-url https://control.example.com \
  --relay-bind 127.0.0.1:3340 \
  --admin-bind 127.0.0.1:3341 \
  --state-dir /var/lib/agent-scale-relay
```

Once `control.json` exists, the invitation file and Control URL are ignored;
the Relay can restart from its verified offline snapshot while Control is down.

`as-relay run` requires the Control profile created by `as-relay join`. There is
no Center-signed initialization mode and no remote snapshot mutation endpoint.
The relay actively long-polls Control for complete, signed membership snapshots.

Both listeners use plain HTTP. Put TLS in front of the public relay listener in
production; its proxy route must preserve WebSocket upgrade headers. Keep the
administrative listener private. It exposes only `/healthz` and the read-only
`/v1/status` endpoint.

## Membership and Failure Behavior

Control derives relay membership from its committed Center, Edge, and Relay
topology. Accepted snapshots are flushed and atomically renamed before becoming
active. Removed EndpointIds are disconnected immediately.

The relay keeps the last verified snapshot in
`/var/lib/agent-scale-relay/membership.json`. If Control is temporarily
unavailable, existing authorized connections and relay restarts continue from
that snapshot; new allocations and authorization changes wait for Control to
return. Removing the relay with `as-control relay rm prod-sg` causes its watcher
to fail closed and disconnect all clients.

Relay authorization controls relay resource use. Edge command access remains
independently protected by the Edge's pinned Center identity.
