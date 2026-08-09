# Provisioner Reconcile API

The Provisioner API lets an external controller reconcile agent-scale topology
without making `as-control` aware of Kubernetes or any other scheduler. The
controller owns workloads and process lifecycle; `as-control` remains the
authority for identities, enrollment, and the persisted Client-to-Edge
grouping.

## Trust A Provisioner

Give each controller a durable Ed25519 identity and register its public
`EndpointId` locally on the Control host:

```sh
as-control provisioner add lab-controller <endpoint-id>
as-control provisioner ls
```

Provisioners are administrative principals. Registration is deliberately
available only through the mode-`0600` local admin socket. Removing one is
blocked while it still manages a Client or has an active pending invitation:

```sh
as-control provisioner rm lab-controller
```

## Reconcile Model

Send a JSON request to `POST /v1/provisioner`. Authentication is independent of
Rust and requires only Ed25519, SHA-256, and hexadecimal encoding. Production
callers must use the Control HTTPS endpoint.

The body contains `protocol_version`, `audience`, `request_id`, `issued_at`, an
optional `expected_revision`, and the tagged `action`. Sign these exact bytes:

```text
preimage = "agent-scale-control-provisioner-http-v1\0POST\0/v1/provisioner\0"
           || SHA256(exact_http_body_bytes)
signature = Ed25519.Sign(controller_private_key, preimage)
```

Set the header to:

```text
Authorization: AgentScale-Ed25519 <lowercase-hex-public-key>:<lowercase-hex-signature>
```

The public key is the controller `EndpointId` registered with `as-control`.
The body digest prevents any field or JSON byte from being changed after
signing, while the domain binds the signature to this HTTP method and path.
Marshal the body only once: sign that byte slice and send the same slice.

### Go signing example

The controller needs no Rust or agent-scale library:

```go
package controlclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
)

const provisionerDomain = "agent-scale-control-provisioner-http-v1\x00POST\x00/v1/provisioner\x00"

func postProvisioner(ctx context.Context, client *http.Client, controlURL string,
	privateKey ed25519.PrivateKey, value any) (*http.Response, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(body)
	preimage := append([]byte(provisionerDomain), digest[:]...)
	signature := ed25519.Sign(privateKey, preimage)
	endpointID := hex.EncodeToString(privateKey.Public().(ed25519.PublicKey))
	authorization := fmt.Sprintf("AgentScale-Ed25519 %s:%s", endpointID,
		hex.EncodeToString(signature))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		controlURL+"/v1/provisioner", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authorization)
	return client.Do(req)
}
```

For example, a topology query body is:

```json
{
  "protocol_version": 4,
  "audience": "prod",
  "request_id": "reconcile-01JXYZ",
  "issued_at": 1700000000,
  "expected_revision": null,
  "action": { "action": "get_topology" }
}
```

Keep the Ed25519 private key in a Kubernetes Secret or external secret manager
and reuse it across controller restarts. Register its 32-byte public key,
encoded as lowercase hexadecimal, with `as-control provisioner add`.

### Compatibility test vector

Implementations can verify their encoding against this non-secret test vector:

```text
seed (32 bytes hex):
0707070707070707070707070707070707070707070707070707070707070707

endpoint id:
ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c

exact body (one line, no trailing newline):
{"protocol_version":4,"audience":"prod","request_id":"request-1","issued_at":1700000000,"expected_revision":7,"action":{"action":"remove_client","name":"job-1"}}

authorization:
AgentScale-Ed25519 ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c:7feb27e70f4a4569db5c8f299b6056eb3d84bc74d0897fe498996e0a6119b4b05af57a820eeb4236de88cb16a077ad2fdc0d155baa0cda0513484ae4ce07e90f
```

The repository asserts this vector in `control-api`, so an incompatible wire
change fails tests.

`GetTopology` returns only the caller's partition:

```text
Provisioner
├── Client (name, EndpointId)
│   └── Edge (name, EndpointId)
└── invitations (pending, claimed, or revoked)
```

The supported mutation actions are:

- `InviteClient { name, ttl_secs, secret }`
- `InviteEdge { owner, name, ttl_secs, secret }`
- `RevokeInvite { invite_id }`
- `RemoveClient { name }`
- `RemoveEdge { owner, name }`
- `TransferEdge { owner, name, endpoint_id, new_owner }`

Use a unique `request_id` for each logical operation. Invitation retries with
the same request ID and action return the same join URL; reusing the ID for a
different action is rejected. Deletes are semantically idempotent. Transfers
include the Edge `endpoint_id` so a retry cannot mistake another same-named Edge
for the original one. Invitation request-ID idempotency lasts until the record
is cleaned up: claimed and revoked records remain for seven days after their
terminal transition, while expired pending records remain for seven days after
expiration.

For optimistic concurrency, copy the `revision` returned by `GetTopology` into
`expected_revision` on a mutation. A stale revision returns HTTP 409. A
successful mutation advances the revision, including invitation creation and
revocation.

A typical controller loop is:

1. Read the scheduler's desired workload state.
2. Request the Provisioner's current topology from `as-control`.
3. Create Client or Edge invitations for missing identities and pass the join
   URLs to the corresponding workloads through the scheduler's secret/config
   mechanism.
4. Wait for those identities to claim their invitations and appear in the
   topology.
5. Transfer or remove Edges, then remove an empty Client, when desired state
   changes.
6. Re-read and retry after a revision conflict.

One Provisioner cannot observe or mutate another Provisioner's topology.
Transfers are permitted only between Clients managed by the same Provisioner.
A Client cannot be removed while it owns an Edge or has an active pending Edge
invitation. An expired invitation no longer reserves its name or blocks cleanup.

## Lifecycle Semantics

Invitation TTL is bounded to seven days because an invitation is a bearer
enrollment capability. Expiration only invalidates that unclaimed capability.
Pending invitations are retained through expiry. Claimed, revoked, and expired
records are cleaned up after a further seven days; this history cleanup does not
remove nodes, advance the authorization revision, or notify NodeMap watchers.

Claimed Clients and Edges have no lease or automatic expiry. A missed heartbeat,
scheduler outage, or temporarily disconnected node therefore cannot silently
erase authorization state. The external controller explicitly removes topology
through the Provisioner API after it has reconciled the workload lifecycle.
This same API works for Kubernetes Jobs and Pods, VMs, bare-metal services, or
another scheduler without changing Control.
