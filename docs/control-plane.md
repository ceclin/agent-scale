# Multi-Client Control Plane

For evaluation or a small static setup, [simple mode](simple-mode.md) uses the
official iroh relays and requires no control-plane deployment.

`as-control` is the coordination authority for a private agent-scale network.
It owns the network signing key, registers multiple clients, assigns every edge
to exactly one client, and distributes the global iroh relay map. It does not
proxy command or service traffic; local proxy listeners remain runtime state in
the Client daemon.

## Deploy Control

### Docker Compose

The repository's `compose.yaml` starts one Control and one enrolled Relay:

```sh
docker compose up -d --wait
agent-scale control join "$(docker compose exec -T \
  control as-control client invite main)"
```

Compose uses the native `as-control bootstrap` command to initialize durable
state and atomically write the Relay enrollment invitation. Client enrollment
remains an explicit administration action after Control starts. The Relay runs
`as-relay run --join-if-needed`; it enrolls itself on the first start and later
starts directly from its persisted profile and revocation state, without a
shell init script or a Control-health dependency.

Released deployments pull `ghcr.io/ceclin/agent-scale-control:latest` and
`ghcr.io/ceclin/agent-scale-relay:latest` by default. During local development,
build the static binaries on the host and use the local override:

```sh
scripts/build-compose-image.sh
docker compose -f compose.yaml -f compose.local.yaml up -d --wait
agent-scale control join "$(docker compose \
  -f compose.yaml -f compose.local.yaml exec -T \
  control as-control client invite main)"
```

The default URLs (`http://localhost:3350` and `http://localhost:3340`) are for a
same-machine evaluation. State is kept in named Docker volumes, so subsequent
`docker compose up -d` calls retain all identities and enrollment.
The containers use read-only root filesystems with writable state volumes,
drop Linux capabilities, and rotate their local JSON logs at three 10 MiB
files per service.

For use from other machines, create `.env` with externally reachable URLs:

```dotenv
CONTROL_PUBLIC_URL=https://control.example.com
RELAY_PUBLIC_URL=https://relay.example.com
CONTROL_AUDIENCE=prod
RELAY_NAME=primary
RELAY_QAD_PORT=4433
RELAY_QAD_BIND_PORT=7842
```

Publish those HTTPS routes through a reverse proxy. Control targets port 3350;
the Relay data plane targets port 3340 and must preserve WebSocket upgrades.
iroh also requires plain HTTP access to the Relay's exact `/generate_204` path;
see [Private Relay](private-relay.md) for the redirect exception.
The Relay management port 3341 stays bound to host loopback. Compose also maps
the chosen public QAD UDP port to the independently configurable container bind
port (both default to 7842). Control automatically issues and distributes the private QAD TLS chain;
you still provision DNS and the HTTPS certificate used by the WebSocket reverse
proxy.

Inspect or stop the stack with:

```sh
docker compose ps
docker compose logs -f control relay
docker compose down
```

`docker compose down -v` also destroys the Control authority and Relay identity.
Back up both `control-state` and `relay-state`
for durable deployments. After Client and Relay enrollment, `bootstrap-data`
contains only consumed invitation artifacts and is not needed to authorize the
existing deployment.

### Manual Deployment

Choose one state directory for the service and every local administration
command:

```sh
export AS_CONTROL_STATE_DIR=/var/lib/agent-scale-control
```

When the variable is unset, it defaults to `~/.agent-scale-control`. The
administration socket is always `$AS_CONTROL_STATE_DIR/admin.sock` and has
no independent option. This keeps the identity, durable state, instance lock,
and local administration endpoint in one instance directory.

Durable topology lives in `$AS_CONTROL_STATE_DIR/control.db`. Control uses one
bundled SQLite connection with foreign keys, WAL, full synchronization, and
explicit schema migrations. It remains a single-instance service; SQLite is
not an HA or multi-writer boundary.

Initialize the durable identity once:

```sh
as-control init \
  --public-url https://control.example.com \
  --audience prod
```

Start Control, then create the first Client invitation from another shell:

```sh
as-control run --bind 127.0.0.1:3350

# In another shell on the Control host:
as-control client invite main
```

Put TLS in front of port 3350. Plain HTTP is accepted only for loopback URLs.
Stop Control and back up the entire state directory, including `control.key`,
`control.db`, and its SQLite sidecar files. Possession of `control.key` is authority
over the entire network. The initial Client URL is single-use and expires after
15 minutes.

On the first development machine, use the URL printed by `client invite`:

```sh
agent-scale control join '<client-url>'
```

## Add Clients And Edges

Global network administration is local-only: run `as-control` on the Control
host or through `docker compose exec`. An enrolled Client may remotely create
invitations for Edges owned by itself and remove those Edges later. Clients
only receive the Edges assigned to their authenticated EndpointId.

```sh
# Control host
docker compose exec control as-control client invite laptop-b

# laptop-b
agent-scale control join '<client-url>'

# laptop-b: create an invitation for its own Edge
agent-scale edge invite win-box

# Test machine, after manually downloading as-edge
as-edge join '<edge-url>'

# laptop-b: remove its own Edge when the machine is deallocated
agent-scale edge rm win-box
```

Other local administration commands follow the same shape:

```sh
docker compose exec control as-control status
docker compose exec control as-control client ls
docker compose exec control as-control edge ls
docker compose exec control as-control relay ls
docker compose exec control as-control invite ls
docker compose exec control as-control invite revoke <invite-id>
docker compose exec control as-control edge rm laptop-b/win-box
docker compose exec control as-control client rm laptop-b
```

The Control host can also create an Edge invitation for a specific Client:

```sh
docker compose exec control \
  as-control edge invite win-box --owner laptop-b
```

Client-created invitations and removals are signed with the Client identity.
Control derives the owner from that verified identity, so neither request can
act on another Client's partition. Removal also identifies the current Edge
EndpointId, preventing a delayed request from deleting a same-name replacement.
There is no invitation quota, but each invitation still has a bounded TTL
(`--ttl-secs`, 15 minutes by default and at most 7 days).

The administration socket is mode `0600` and is not published or mounted into
the Relay container. CLI mutations go through the running Control process, so
state persistence and watcher notifications remain atomic.

## External Controllers

An external scheduler controller can be registered as a Provisioner and
reconcile its own Client-to-Edge topology through a signed remote API. Control
does not create Kubernetes Jobs, Pods, VMs, or processes; the controller owns
those resources and their lifecycle. Control persists the authoritative
identity grouping and isolates each Provisioner's partition.

In a hosted deployment, Control remotely manages authorization topology only.
Allocation, environment metadata, workload lifecycle, and command routing stay
in the external controller or scheduler. A typical Agent Job creates one
temporary Client; reallocating a machine destroys and recreates its Edge
identity instead of transferring it. `edge transfer` remains available for
manual administration, but is not the recommended hosted lifecycle.

```sh
docker compose exec control \
  as-control provisioner add lab-controller <controller-endpoint-id>
```

Claimed nodes never expire automatically. The controller explicitly removes an
Edge and then its empty Client when their workloads are deleted. Enrollment
invitations retain a bounded TTL because they are bearer capabilities. See the
[Provisioner reconcile API](provisioner-api.md) for signing, idempotency,
revision, and action details.

Interactive edge enrollment offers a persistent current-user service. For
automation, choose explicitly:

```sh
as-edge join '<edge-url>' --foreground
as-edge join '<edge-url>' --install
```

Linux installation uses a systemd user unit and copies the binary to
`~/.local/bin/as-edge`. macOS installation uses a per-user LaunchAgent and
copies the binary to `~/Library/Application Support/AgentScale/bin/as-edge`.
Windows installation uses a current-user logon task and copies it to
`%LOCALAPPDATA%\AgentScale\bin\as-edge.exe`. None of these modes requests root,
Administrator, or LocalSystem privileges.

## Add A Private Relay

Create the relay invitation on the Control host:

```sh
docker compose exec control as-control relay invite \
  prod-sg https://relay-sg.example.com
```

On the relay host:

```sh
as-relay join '<relay-url>' --qad-port 4433 \
  --state-dir /var/lib/agent-scale-relay
as-relay run \
  --relay-bind 127.0.0.1:3340 \
  --qad-bind 0.0.0.0:7842 \
  --state-dir /var/lib/agent-scale-relay
```

Clients and Edges present Control-signed, EndpointId-bound credentials to every
Relay. The Relay verifies admission locally, pulls only signed revocation deltas over
HTTPS, and immediately disconnects revoked EndpointIds. Its data-plane route still needs a TLS reverse proxy with
WebSocket upgrades. The admin listener defaults to loopback and is only needed
for local health/status inspection. Publish `4433/udp` to the example local
QAD port `7842/udp`; these ports do not need to be equal.

## Ownership And Offline Behavior

Every edge accepts only its current owner client's authenticated EndpointId.
Control administrators do not receive implicit command access. Ownership
changes are explicit and retain the edge identity:

```sh
docker compose exec control as-control edge transfer laptop-b/win-box main
```

The edge closes connections from the old owner as soon as it receives the new
signed map. A client cannot be removed while it still owns edges.

Clients, edges, and relays cache the last verified map and continue operating
during a control outage. New enrollment and revocation require control to be
available; an offline node applies revocation when it reconnects. This is the
same availability tradeoff used by coordination systems that retain their last
network map.

Simple `as-edge run --relay ...` remains available with official or ordinary
open custom relays. Every authorization-enforcing private `as-relay` uses the
Control-managed flow, including personal single-Client deployments.
