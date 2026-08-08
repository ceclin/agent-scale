# Simple Mode

Simple mode connects one center directly to one or more edges without deploying
`as-control` or a private relay. It uses the official relay map bundled with the
installed iroh version and still upgrades to a direct peer-to-peer path whenever
the network permits it.

## Try It

On the test machine, manually download `as-edge`, create an identity, and start
it:

```sh
as-edge id test
as-edge run test
```

Copy the printed EndpointId to the development machine:

```sh
agent-scale edge add test <EDGE_ENDPOINT_ID>
agent-scale -e test exec -- uname -a
```

The edge trusts the first authenticated center that connects and persists that
center's EndpointId. Later connections are strict. To avoid trust-on-first-use,
run `agent-scale keygen` on the development machine and start the edge with
`as-edge run test --center <CENTER_ENDPOINT_ID>`.

For a persistent current-user service on Linux, macOS, or Windows:

```sh
as-edge service install test
as-edge service status test
```

## Custom Relay

Simple mode can use an ordinary custom or development relay without adding a
control plane. It cannot administer a private relay allowlist. Pass the same
relay URL on both machines:

```sh
as-edge run test --relay https://relay.example.com
agent-scale edge add test <EDGE_ENDPOINT_ID> --relay https://relay.example.com
```

Repeat `--relay` to configure more than one custom relay. Supplying any custom
relay replaces the official default set.

## Security And Scope

Relay operators forward encrypted iroh traffic but cannot impersonate either
endpoint or read command payloads. Edge command access is authorized separately
by its pinned center key. The official relay service is shared infrastructure,
so its availability, capacity, and acceptable-use policy remain external
dependencies.

Use simple mode for evaluation, personal setups, and small static fleets. Use
the [multi-center control plane](control-plane.md) when you need invitations,
roles, edge ownership transfer, centrally managed private relays, or dynamic
revocation.
