# Legacy Single-Center Private Relay

For new deployments with multiple centers, use the managed control-plane flow
in [control-plane.md](control-plane.md). The setup below is retained for
standalone deployments that deliberately pin one relay to one center.

`as-relay` is an iroh relay whose users are controlled by one pinned
`agent-scale` center identity. Unknown endpoints complete neither relay
registration nor traffic forwarding.

## Start A Relay

Print the center identity on the development machine:

```sh
agent-scale keygen
```

Start the relay on the relay host:

```sh
as-relay run \
  --relay-bind 127.0.0.1:3340 \
  --admin-bind 127.0.0.1:3341 \
  --center <CENTER_ENDPOINT_ID> \
  --audience prod-sg \
  --state-dir /var/lib/agent-scale-relay
```

Both listeners use plain HTTP. Keep the admin listener on loopback and put TLS
in front of both listeners. The public relay route must preserve WebSocket
upgrade headers. A typical proxy exposes the relay at
`https://relay.example.com/` and proxies
`https://relay.example.com/admin/` to the admin listener.

Register it on the center:

```sh
agent-scale relay add prod-sg https://relay.example.com \
  --admin-url https://relay.example.com/admin/ \
  --audience prod-sg
```

The management URL must use HTTPS unless it targets loopback. No bearer token
is exchanged: updates are signed by the center's existing Ed25519 identity,
and `as-relay` verifies that pinned public key.

## Membership

An edge becomes a relay member when its normalized relay URL matches a managed
relay:

```sh
agent-scale edge add win-box <EDGE_ENDPOINT_ID> \
  --relay https://relay.example.com
```

`edge add`, edge re-key, and `edge rm` submit a complete desired membership
snapshot before committing the local edge change. If any affected relay is
unreachable, the edge command fails and the local registry remains unchanged.
Retry the command after connectivity is restored.

Manual inspection and reconciliation are available:

```sh
agent-scale relay ls
agent-scale relay status prod-sg
agent-scale relay sync prod-sg
```

Snapshots have a monotonically increasing version, a five-minute timestamp
window, and a relay-specific audience. An exact retry is idempotent; an older
version or different content at an existing version is rejected. Accepted
snapshots are flushed and atomically renamed before becoming active. Revoked
EndpointIds are disconnected from the relay immediately.

Removing a managed relay first requires moving or removing every edge that
uses it:

```sh
agent-scale relay rm prod-sg
```

This sends a center-only snapshot before removing the local relay entry.

## Operational Notes

- Back up `/var/lib/agent-scale-relay/membership.json`. It is not secret, but
  it carries the anti-rollback version.
- Keep the center key under `$AGENT_SCALE_HOME/center.key` private. It is the
  relay administration credential.
- The unsigned status endpoint exposes only audience, center EndpointId,
  version, and member count. Membership identities are never returned.
- Relay authorization controls use of relay resources. Edge command access is
  independently protected by the edge's pinned center identity.
- Use firewall and proxy rate limits as defense in depth against unauthenticated
  connection attempts before the iroh handshake is rejected.
