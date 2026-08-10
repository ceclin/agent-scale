# Access services through an Edge

The Client daemon can expose a service reachable from an Edge without opening
an inbound port on the test machine. The Edge performs the outbound connection
and resolves target hostnames in its own network.

For a fixed service such as a database:

```console
agent-scale -e linux-box proxy start tcp database \
  --listen 127.0.0.1:15432 --target postgres.internal:5432
```

Applications on the development machine can now connect to
`127.0.0.1:15432`. TCP bytes pass directly over an iroh QUIC stream after the
Edge confirms the target connection.

For applications that support SOCKS5:

```console
agent-scale -e linux-box proxy start socks5 test-network \
  --listen 127.0.0.1:1080
```

The SOCKS listener supports TCP CONNECT and UDP ASSOCIATE with IPv4, IPv6, and
domain targets. BIND is not supported. UDP packets use a reliable framed QUIC
stream rather than QUIC datagrams. This preserves packet boundaries and works
through the same Relay path, but loss can delay later packets in that
association; it is intended for development access, not latency-sensitive UDP
workloads.

Both listener types are intentionally unauthenticated. Bind to a loopback
address unless every host that can reach the selected interface should receive
the Edge's full network access. Agent-scale does not restrict destination
addresses or ports because an Edge is already fully owned by its enrolled
Client.

## Lifecycle

```console
agent-scale proxy ls
agent-scale proxy stop database
```

`start` verifies the Edge name and binds the local socket, then exits; the
background daemon owns the listener and active sessions. It does not require
the Edge to be online at startup. Each incoming connection uses the current
Edge configuration, so a temporarily unavailable Edge produces a connection
failure without removing the listener.

Proxy definitions are process-local and are never written to `config.json`.
They keep the daemon from idle shutdown, disappear on `daemon --stop` or a
daemon restart, and must be started again when needed. Removing or revoking an
Edge closes its current iroh connection; the listener remains present, but new
sessions fail until that Edge name is configured and reachable again.

Use `--connect-timeout-secs` on `proxy start` to change the default ten-second
Edge-side TCP connection or DNS resolution timeout. A listen port of zero asks
the operating system to select a free port; the chosen address is printed by
the command and shown by `proxy ls`.
