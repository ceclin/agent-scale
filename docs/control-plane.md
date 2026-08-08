# Multi-Center Control Plane

For evaluation or a small static setup, [simple mode](simple-mode.md) uses the
official iroh relays and requires no control-plane deployment.

`as-control` is the coordination authority for a private agent-scale network.
It owns the network signing key, registers multiple centers, assigns every edge
to exactly one center, and distributes the global iroh relay map. It does not
proxy command traffic.

## Deploy Control

### Docker Compose

The repository's `compose.yaml` starts one Control and one enrolled Relay:

```sh
docker compose up -d
agent-scale control join "$(docker compose run --rm center-invite)"
```

Released deployments pull
`ghcr.io/agent-scale/agent-scale-infrastructure:latest` by default. During local
development, build the static binaries on the host and use the local override:

```sh
scripts/build-compose-image.sh
docker compose -f compose.yaml -f compose.local.yaml up -d
agent-scale control join "$(docker compose \
  -f compose.yaml -f compose.local.yaml run --rm center-invite)"
```

The default URLs (`http://localhost:3350` and `http://localhost:3340`) are for a
same-machine evaluation. State is kept in named Docker volumes, so subsequent
`docker compose up -d` calls retain all identities and enrollment.

For use from other machines, create `.env` with externally reachable URLs:

```dotenv
CONTROL_PUBLIC_URL=https://control.example.com
RELAY_PUBLIC_URL=https://relay.example.com
CONTROL_AUDIENCE=prod
CONTROL_CENTER_NAME=main
RELAY_NAME=relay-a
```

Publish those HTTPS routes through a reverse proxy. Control targets port 3350;
the Relay data plane targets port 3340 and must preserve WebSocket upgrades.
The Relay management port 3341 stays bound to host loopback. Compose does not
provision DNS or TLS certificates.

Inspect or stop the stack with:

```sh
docker compose ps
docker compose logs -f control relay
docker compose down
```

`docker compose down -v` also destroys the Control authority, enrollment, and
initial Center invitation. Back up the `control-state` volume for durable
deployments.

### Manual Deployment

Initialize the durable identity once:

```sh
as-control init \
  --public-url https://control.example.com \
  --audience prod \
  --state-dir /var/lib/agent-scale-control
```

Create the first Center invitation while the service is stopped, then start it:

```sh
as-control bootstrap center main \
  --state-dir /var/lib/agent-scale-control

as-control --admin-socket /run/agent-scale-control/admin.sock run \
  --bind 127.0.0.1:3350 \
  --state-dir /var/lib/agent-scale-control
```

Put TLS in front of port 3350. Plain HTTP is accepted only for loopback URLs.
Back up `control.key` and `state.json`; possession of `control.key` is authority
over the entire network. The initial Center URL is single-use and expires after
15 minutes.

On the first development machine, use the URL printed by `bootstrap`:

```sh
agent-scale control join '<center-url>'
```

## Add Centers And Edges

Network administration is local-only: run `as-control` on the Control host or
through `docker compose exec`. An enrolled Center has one self-service ability:
it may create any number of invitations for Edges owned by itself. Centers only
receive the Edges assigned to their authenticated EndpointId.

```sh
# Control host
docker compose exec control as-control center invite laptop-b

# laptop-b
agent-scale control join '<center-url>'

# laptop-b: create an invitation for its own Edge
agent-scale edge invite win-box

# Test machine, after manually downloading as-edge
as-edge join '<edge-url>'
```

Other local administration commands follow the same shape:

```sh
docker compose exec control as-control status
docker compose exec control as-control center ls
docker compose exec control as-control edge ls
docker compose exec control as-control relay ls
docker compose exec control as-control invite ls
docker compose exec control as-control invite revoke <invite-id>
docker compose exec control as-control edge rm laptop-b/win-box
docker compose exec control as-control center rm laptop-b
```

The Control host can also create an Edge invitation for a specific Center:

```sh
docker compose exec control \
  as-control edge invite win-box --owner laptop-b
```

Center-created invitations are signed with the Center identity. Control derives
the owner from that verified identity; the request cannot name another Center.
There is no invitation quota, but each invitation still has a bounded TTL
(`--ttl-secs`, 15 minutes by default and at most 7 days).

The administration socket is mode `0600` and is not published or mounted into
the Relay container. CLI mutations go through the running Control process, so
state persistence and watcher notifications remain atomic.

## External Controllers

An external scheduler controller can be registered as a Provisioner and
reconcile its own Center-to-Edge topology through a signed remote API. Control
does not create Kubernetes Jobs, Pods, VMs, or processes; the controller owns
those resources and their lifecycle. Control persists the authoritative
identity grouping and isolates each Provisioner's partition.

```sh
docker compose exec control \
  as-control provisioner add lab-controller <controller-endpoint-id>
```

Claimed nodes never expire automatically. The controller explicitly removes an
Edge and then its empty Center when their workloads are deleted. Enrollment
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
`~/.local/bin/as-edge`. Windows installation uses a current-user logon task and
copies it to `%LOCALAPPDATA%\AgentScale\bin\as-edge.exe`. Neither mode requests
root, Administrator, or LocalSystem privileges.

## Add A Private Relay

Create the relay invitation on the Control host:

```sh
docker compose exec control as-control relay invite \
  prod-sg https://relay-sg.example.com
```

On the relay host:

```sh
as-relay join '<relay-url>' --state-dir /var/lib/agent-scale-relay
as-relay run \
  --relay-bind 127.0.0.1:3340 \
  --state-dir /var/lib/agent-scale-relay
```

The relay pulls control-signed membership over HTTPS and immediately disconnects
revoked EndpointIds. Its data-plane route still needs a TLS reverse proxy with
WebSocket upgrades. The admin listener defaults to loopback and is only needed
for local health/status inspection.

## Ownership And Offline Behavior

Every edge accepts only its current owner center's authenticated EndpointId.
Control administrators do not receive implicit command access. Ownership
changes are explicit and retain the edge identity:

```sh
docker compose exec control as-control edge transfer laptop-b/win-box main
```

The edge closes connections from the old owner as soon as it receives the new
signed map. A center cannot be removed while it still owns edges.

Centers, edges, and relays cache the last verified map and continue operating
during a control outage. New enrollment and revocation require control to be
available; an offline node applies revocation when it reconnects. This is the
same availability tradeoff used by coordination systems that retain their last
network map.

Legacy `as-edge run --relay ...` and single-center `as-relay run --center ...`
remain available for standalone deployments and cannot be mixed with a
control-managed profile.
