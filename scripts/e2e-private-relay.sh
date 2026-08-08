#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BIN="$ROOT/target/debug"
TMP=$(mktemp -d)
CENTER_HOME="$TMP/center"
EDGE_HOME="$TMP/edge"
RELAY_STATE="$TMP/relay"
RELAY_LOG="$TMP/relay.out"
EDGE_LOG="$TMP/edge.out"
relay_pid=
edge_pid=

cleanup() {
    AGENT_SCALE_HOME="$CENTER_HOME" "$BIN/agent-scale" daemon --stop >/dev/null 2>&1 || true
    if [ -n "$edge_pid" ]; then kill "$edge_pid" >/dev/null 2>&1 || true; fi
    if [ -n "$relay_pid" ]; then kill "$relay_pid" >/dev/null 2>&1 || true; fi
    if [ -n "$edge_pid" ]; then wait "$edge_pid" >/dev/null 2>&1 || true; fi
    if [ -n "$relay_pid" ]; then wait "$relay_pid" >/dev/null 2>&1 || true; fi
    rm -r -- "$TMP"
}
trap cleanup EXIT INT TERM

cargo build --manifest-path "$ROOT/Cargo.toml" -p agent-scale -p as-edge -p as-relay

center_id=$(AGENT_SCALE_HOME="$CENTER_HOME" "$BIN/agent-scale" keygen)
"$BIN/as-relay" run \
    --relay-bind 127.0.0.1:0 \
    --admin-bind 127.0.0.1:0 \
    --center "$center_id" \
    --audience e2e \
    --state-dir "$RELAY_STATE" >"$RELAY_LOG" 2>&1 &
relay_pid=$!

i=0
while [ "$(wc -l <"$RELAY_LOG")" -lt 3 ]; do
    i=$((i + 1))
    if [ "$i" -ge 200 ]; then
        echo "as-relay did not start" >&2
        exit 1
    fi
    sleep 0.05
done
relay_url=$(sed -n 's/^relay=//p' "$RELAY_LOG")
admin_url=$(sed -n 's/^admin=//p' "$RELAY_LOG")

AGENT_SCALE_HOME="$CENTER_HOME" "$BIN/agent-scale" relay add e2e "$relay_url" \
    --admin-url "$admin_url" --audience e2e
edge_id=$(AGENT_SCALE_HOME="$EDGE_HOME" "$BIN/as-edge" id test)
AGENT_SCALE_HOME="$CENTER_HOME" "$BIN/agent-scale" edge add test "$edge_id" \
    --relay "$relay_url"

AGENT_SCALE_HOME="$EDGE_HOME" "$BIN/as-edge" run test \
    --relay "$relay_url" --center "$center_id" >"$EDGE_LOG" 2>&1 &
edge_pid=$!

i=0
while :; do
    if output=$(AGENT_SCALE_HOME="$CENTER_HOME" AGENT_SCALE_DIAL_SECS=2 \
        "$BIN/agent-scale" -e test exec -- sh -c 'printf relay-e2e-ok' 2>/dev/null); then
        [ "$output" = "relay-e2e-ok" ]
        break
    fi
    i=$((i + 1))
    if [ "$i" -ge 15 ]; then
        echo "edge did not become reachable" >&2
        exit 1
    fi
done

# Revocation is fail-closed: an unavailable relay makes edge removal fail and
# leaves the local desired state intact. Restarting with the durable snapshot
# lets the exact same command complete.
kill "$relay_pid"
wait "$relay_pid" >/dev/null 2>&1 || true
relay_pid=
if AGENT_SCALE_HOME="$CENTER_HOME" "$BIN/agent-scale" edge rm test >/dev/null 2>&1; then
    echo "edge removal unexpectedly succeeded while relay was offline" >&2
    exit 1
fi
AGENT_SCALE_HOME="$CENTER_HOME" "$BIN/agent-scale" edge ls | grep '^test$' >/dev/null

: >"$RELAY_LOG"
"$BIN/as-relay" run \
    --relay-bind "${relay_url#http://}" \
    --admin-bind "${admin_url#http://}" \
    --center "$center_id" \
    --audience e2e \
    --state-dir "$RELAY_STATE" >"$RELAY_LOG" 2>&1 &
relay_pid=$!
i=0
while [ "$(wc -l <"$RELAY_LOG")" -lt 3 ]; do
    i=$((i + 1))
    if [ "$i" -ge 200 ]; then
        echo "as-relay did not restart" >&2
        exit 1
    fi
    sleep 0.05
done

AGENT_SCALE_HOME="$CENTER_HOME" "$BIN/agent-scale" edge rm test
status=$(curl --fail --silent "$admin_url/v1/status")
echo "$status" | grep '"version":3' >/dev/null
echo "$status" | grep '"members":1' >/dev/null

echo "private relay e2e: ok"
