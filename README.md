# agent-scale

Use your development machine to run commands, transfer files, reach private
services, and connect to MCP servers on remote test machines.

agent-scale connects the two machines over authenticated
[iroh](https://iroh.computer/) peer-to-peer transport. Test machines do not
need public IP addresses or inbound ports. A Relay helps the peers find each
other and carries encrypted traffic when a direct path is unavailable.

> agent-scale is pre-release software. Configuration and network protocols may
> change incompatibly before 1.0.

## Choose a setup

| | Simple mode | Managed mode |
| --- | --- | --- |
| Best for | Trying agent-scale, personal use, and a small static set of machines | Teams, private infrastructure, and dynamically allocated machines |
| Infrastructure | None; uses iroh's public Relays by default | One Control and one or more private Relays |
| Enrollment | Copy an Edge EndpointId; optionally use trust on first use | One-time Client, Edge, and Relay invitations |
| Lifecycle | Manage Edges directly from one Client | Central ownership, immediate revocation, and Provisioner automation |

Start with simple mode if you are unsure. Both modes use the same Client and
Edge commands after enrollment.

## Install

Download the archive for your platform from
[GitHub Releases](https://github.com/ceclin/agent-scale/releases):

- install `agent-scale` on your development machine;
- install `as-edge` on every test machine you want to access.

Extract the executable and place it somewhere on `PATH`. Each release includes
`SHA256SUMS`; from the download directory, verify an archive with:

```console
sha256sum --check --ignore-missing SHA256SUMS
```

Releases also publish a GitHub attestation for that manifest; verify it with
`gh attestation verify SHA256SUMS --repo ceclin/agent-scale` before trusting the
listed hashes.

On Windows, use `Get-FileHash -Algorithm SHA256 <archive>` in PowerShell and
compare it with the corresponding entry in `SHA256SUMS`.

Linux and macOS builds are available for x86-64 and ARM64. Windows builds are
available for x86-64. Android `as-edge` builds are available for ARMv7, ARM64,
and x86-64 and run in the foreground from `adb shell`. Windows and Android
support are experimental and have not yet been validated through the complete
workflow on physical devices.

Control and private Relay deployments use the separately published
`as-control` and `as-relay` Linux binaries, or these multi-architecture images:

```text
ghcr.io/ceclin/agent-scale-control:<version>
ghcr.io/ceclin/agent-scale-relay:<version>
```

## Connect your first test machine

Simple mode needs no Control deployment and uses iroh's public relays. On the
test machine, create an Edge identity and start it:

```console
as-edge id test
as-edge run test
```

Copy the printed EndpointId, then register it on your development machine:

```console
agent-scale edge add test <EDGE_ENDPOINT_ID>
agent-scale -e test exec -- uname -a
```

The first authenticated Client to connect is trusted and persistently pinned by
the Edge. If you prefer to pin it before the first connection, run
`agent-scale keygen` and pass the printed ID to `as-edge run test --client
<CLIENT_ENDPOINT_ID>`.

The Client starts its local connection manager automatically; there is no
daemon to launch by hand. To keep a simple-mode Edge running after logout, stop
the foreground process with Ctrl-C and install its current-user service:

```console
as-edge service install test
as-edge service status test
```

The service does not require root or Administrator privileges. See
[Simple mode](docs/simple-mode.md) for custom Relay configuration and identity
management.

## Use an Edge

Commands stream stdout and stderr as they run. Ctrl-C cancels the remote child:

```console
agent-scale -e test exec -- cargo test
agent-scale -e test exec -- rg TODO /work/project
```

Transfer files in either direction:

```console
agent-scale -e test upload ./build.zip /tmp/build.zip
agent-scale -e test download /tmp/results.json ./results.json
```

Reach a database or another service visible only from the test machine:

```console
agent-scale -e test proxy start tcp database \
  --listen 127.0.0.1:15432 \
  --target postgres.internal:5432
```

Applications on your development machine can now connect to
`127.0.0.1:15432`. A SOCKS5 proxy is also available for dynamic TCP and UDP
destinations. Local listeners are intentionally unauthenticated, so bind them
to loopback unless you intend to share Edge network access. See
[Service proxying](docs/proxy.md).

## Use remote MCP servers

Register a server that runs on, or is locally reachable from, an Edge:

```console
agent-scale -e test mcp add debugger -- lldb-mcp
agent-scale -e test mcp add database --http http://127.0.0.1:8080/mcp
agent-scale -e test mcp check debugger
```

Synchronize the selected Edge's servers into the current project:

```console
agent-scale -e test mcp sync --client codex --client claude
```

agent-scale writes project-scoped proxy entries while preserving handwritten
configuration. The MCP client sees an ordinary stdio server; agent-scale
bridges stdio, Streamable HTTP, and legacy SSE transports over the Edge
connection. See [Remote MCP servers](docs/mcp.md).

## Run a managed private network

Use managed mode when you need multiple Clients, private Relays, invitations,
central ownership, or immediate revocation. `as-control` distributes signed
authorization state; it never receives command output, transferred files, MCP
traffic, or proxied service traffic.

The included Compose stack starts one Control and one private Relay behind
Traefik. Configure its public Control and Relay hostnames as described in the
[Control plane guide](docs/control-plane.md), then start it and enroll the first
Client:

```console
docker compose up -d --wait
agent-scale control join "$(docker compose exec -T \
  control as-control client invite laptop)"
```

Create an Edge invitation from the enrolled Client and redeem it on the test
machine:

```console
# Development machine
agent-scale edge invite test

# Test machine, using the invitation printed above
as-edge join '<EDGE_INVITATION>' --install
```

A real deployment needs externally reachable Control and Relay URLs, HTTPS, and
the Relay UDP port. Follow the [Private Relay](docs/private-relay.md) guide
before exposing it publicly.

## Automate provisioning

The Provisioner API connects agent-scale to systems that create test machines
on demand, such as CI workers, VM managers, Kubernetes controllers, or an
internal scheduler. Register each controller's Ed25519 identity on the Control
host:

```console
as-control provisioner add lab-controller <CONTROLLER_ENDPOINT_ID>
```

The controller can then use signed HTTPS requests to read its isolated
Client-to-Edge partition, create repeatable enrollment invitations, revoke
unused invitations, and remove or transfer identities during cleanup. Request
IDs make invitation retries idempotent, and topology revisions support safe
reconciliation after controller restarts.

Control manages authorization and enrollment only. The Provisioner remains
responsible for allocating machines, delivering join invitations, starting
Edges, and deleting workloads. The API is language-independent and does not
require embedding agent-scale or Rust code. See the
[Provisioner API](docs/provisioner-api.md) for the request format, signing
example, and reconciliation lifecycle.

## Security model

- Client and Edge identities are Ed25519 keys. Each connection authenticates
  both peers, and dialing uses the expected public EndpointId.
- Relays forward end-to-end encrypted iroh traffic and cannot impersonate a
  Client or Edge or read application payloads.
- In managed mode, Relay admission and topology are signed by Control. A
  definitive revocation disconnects live sessions.
- Existing enrolled nodes can continue using the last verified authorization
  map while Control is temporarily unavailable.
- Identities and configuration live under `~/.agent-scale` by default. Back up
  the complete Control and Relay state directories for durable deployments.

Report suspected vulnerabilities privately by following [SECURITY.md](SECURITY.md).

## More information

- [Simple mode](docs/simple-mode.md)
- [Control plane](docs/control-plane.md)
- [Private Relay](docs/private-relay.md)
- [Service proxying](docs/proxy.md)
- [Remote MCP servers](docs/mcp.md)
- [Contributing](CONTRIBUTING.md)

Licensed under the [Apache License, Version 2.0](LICENSE).
