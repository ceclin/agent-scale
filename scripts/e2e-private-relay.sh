#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BIN="$ROOT/target/debug"
TMP=$(mktemp -d)
CENTER_HOME="$TMP/center"
EDGE_HOME="$TMP/edge"
RELAY_STATE="$TMP/relay"
CONTROL_URL=http://127.0.0.1:35350
RELAY_URL=http://127.0.0.1:35340
RELAY_ADMIN_URL=http://127.0.0.1:35341
control_pid=
relay_pid=
edge_pid=

cleanup() {
    AGENT_SCALE_HOME="$CENTER_HOME" "$BIN/agent-scale" daemon --stop >/dev/null 2>&1 || true
    for pid in "$edge_pid" "$relay_pid" "$control_pid"; do
        if [ -n "$pid" ]; then kill "$pid" >/dev/null 2>&1 || true; fi
    done
    for pid in "$edge_pid" "$relay_pid" "$control_pid"; do
        if [ -n "$pid" ]; then wait "$pid" >/dev/null 2>&1 || true; fi
    done
    rm -r -- "$TMP"
}
trap cleanup EXIT INT TERM

cd "$ROOT"
cargo build -q -p agent-scale -p as-control -p as-edge -p as-relay

export AS_CONTROL_STATE_DIR="$TMP/control"
"$BIN/as-control" init --public-url "$CONTROL_URL" --audience e2e >/dev/null
center_join=$("$BIN/as-control" bootstrap center center)
"$BIN/as-control" run --bind 127.0.0.1:35350 >"$TMP/control.out" 2>&1 &
control_pid=$!

i=0
until curl -fsS "$CONTROL_URL/healthz" >/dev/null 2>&1; do
    i=$((i + 1)); [ "$i" -lt 100 ] || { echo "as-control did not start" >&2; exit 1; }
    sleep 0.05
done

AGENT_SCALE_HOME="$CENTER_HOME" "$BIN/agent-scale" control join "$center_join" >/dev/null
relay_join=$("$BIN/as-control" relay invite relay-a "$RELAY_URL")
"$BIN/as-relay" join "$relay_join" --state-dir "$RELAY_STATE" >/dev/null
"$BIN/as-relay" run --relay-bind 127.0.0.1:35340 --admin-bind 127.0.0.1:35341 \
    --state-dir "$RELAY_STATE" >"$TMP/relay.out" 2>&1 &
relay_pid=$!

i=0
until curl -fsS "$RELAY_ADMIN_URL/healthz" >/dev/null 2>&1; do
    i=$((i + 1)); [ "$i" -lt 100 ] || { echo "as-relay did not start" >&2; exit 1; }
    sleep 0.05
done
status=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$RELAY_ADMIN_URL/v1/snapshot")
[ "$status" = 404 ]

edge_join=$(AGENT_SCALE_HOME="$CENTER_HOME" "$BIN/agent-scale" edge invite test)
AGENT_SCALE_HOME="$EDGE_HOME" "$BIN/as-edge" join "$edge_join" --foreground >"$TMP/edge.out" 2>&1 &
edge_pid=$!

i=0
until output=$(AGENT_SCALE_HOME="$CENTER_HOME" AGENT_SCALE_DIAL_SECS=2 \
    "$BIN/agent-scale" -e test exec -- sh -c 'printf relay-e2e-ok' 2>/dev/null) && \
    [ "$output" = relay-e2e-ok ]; do
    i=$((i + 1)); [ "$i" -lt 40 ] || { echo "edge did not become reachable" >&2; exit 1; }
    sleep 0.1
done

# Restart from the last verified snapshot while Control is unavailable.
kill "$control_pid"; wait "$control_pid" >/dev/null 2>&1 || true; control_pid=
kill "$relay_pid"; wait "$relay_pid" >/dev/null 2>&1 || true; relay_pid=
"$BIN/as-relay" run --relay-bind 127.0.0.1:35340 --admin-bind 127.0.0.1:35341 \
    --state-dir "$RELAY_STATE" >"$TMP/relay.out" 2>&1 &
relay_pid=$!

i=0
until curl -fsS "$RELAY_ADMIN_URL/v1/status" 2>/dev/null | grep '"members":2' >/dev/null; do
    i=$((i + 1)); [ "$i" -lt 100 ] || { echo "relay did not restore its snapshot" >&2; exit 1; }
    sleep 0.05
done

"$BIN/as-control" run --bind 127.0.0.1:35350 >"$TMP/control.out" 2>&1 &
control_pid=$!
i=0
until curl -fsS "$CONTROL_URL/healthz" >/dev/null 2>&1; do
    i=$((i + 1)); [ "$i" -lt 100 ] || { echo "as-control did not restart" >&2; exit 1; }
    sleep 0.05
done

"$BIN/as-control" edge rm center/test >/dev/null
i=0
until curl -fsS "$RELAY_ADMIN_URL/v1/status" 2>/dev/null | grep '"members":1' >/dev/null; do
    i=$((i + 1)); [ "$i" -lt 100 ] || { echo "relay did not apply revocation" >&2; exit 1; }
    sleep 0.05
done

echo "control-managed private relay e2e: ok"
