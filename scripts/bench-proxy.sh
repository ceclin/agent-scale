#!/usr/bin/env bash
# Keep throughput observations out of e2e because host load and debug/release
# profiles make stable performance thresholds impractical.
set -euo pipefail
cd "$(dirname "$0")/.."

BIN=${BIN_DIR:-target/debug}
BYTES=${BENCH_BYTES:-268435456}
CLIENT_HOME=$(mktemp -d)
EDGE_HOME=$(mktemp -d)
RELAY_LOG=$(mktemp)
BACKEND_LOG=$(mktemp)

cleanup() {
  AGENT_SCALE_HOME="$CLIENT_HOME" "$BIN/agent-scale" daemon --stop >/dev/null 2>&1 || true
  [ -n "${EDGE_PID:-}" ] && kill "$EDGE_PID" 2>/dev/null || true
  [ -n "${RELAY_PID:-}" ] && kill "$RELAY_PID" 2>/dev/null || true
  [ -n "${BACKEND_PID:-}" ] && kill "$BACKEND_PID" 2>/dev/null || true
  rm -rf "$CLIENT_HOME" "$EDGE_HOME" "$RELAY_LOG" "$BACKEND_LOG"
}
trap cleanup EXIT

"$BIN/relay-dev" >"$RELAY_LOG" 2>/dev/null &
RELAY_PID=$!
for _ in $(seq 1 100); do
  RELAY_URL=$(head -n1 "$RELAY_LOG" 2>/dev/null || true)
  [ -n "$RELAY_URL" ] && break
  sleep 0.1
done
[ -n "${RELAY_URL:-}" ]

EDGE_ID=$(AGENT_SCALE_HOME="$EDGE_HOME" "$BIN/as-edge" id proxy-bench)
AGENT_SCALE_HOME="$CLIENT_HOME" "$BIN/agent-scale" edge add proxy-bench "$EDGE_ID" --relay "$RELAY_URL" >/dev/null
AGENT_SCALE_HOME="$EDGE_HOME" "$BIN/as-edge" run proxy-bench --relay "$RELAY_URL" >/dev/null 2>&1 &
EDGE_PID=$!

python3 scripts/e2e-proxy.py server >"$BACKEND_LOG" &
BACKEND_PID=$!
for _ in $(seq 1 100); do
  read -r TCP_PORT _ <"$BACKEND_LOG" || true
  [ -n "${TCP_PORT:-}" ] && break
  sleep 0.1
done
[ -n "${TCP_PORT:-}" ]

for _ in $(seq 1 100); do
  AGENT_SCALE_HOME="$CLIENT_HOME" "$BIN/agent-scale" -e proxy-bench exec -- true >/dev/null 2>&1 && break
  sleep 0.1
done

FIXED=$(AGENT_SCALE_HOME="$CLIENT_HOME" "$BIN/agent-scale" -e proxy-bench proxy start tcp fixed \
  --listen 127.0.0.1:0 --target "127.0.0.1:$TCP_PORT")
FIXED_PORT=$(sed -E 's/.*listening on [^:]+:([0-9]+).*/\1/' <<<"$FIXED")
SOCKS=$(AGENT_SCALE_HOME="$CLIENT_HOME" "$BIN/agent-scale" -e proxy-bench proxy start socks5 socks \
  --listen 127.0.0.1:0)
SOCKS_PORT=$(sed -E 's/.*listening on [^:]+:([0-9]+).*/\1/' <<<"$SOCKS")

echo "direct TCP baseline:"
python3 scripts/e2e-proxy.py fixed "$TCP_PORT" --size "$BYTES"
echo "fixed tunnel:"
python3 scripts/e2e-proxy.py fixed "$FIXED_PORT" --size "$BYTES"
echo "SOCKS5 CONNECT tunnel:"
python3 scripts/e2e-proxy.py socks-connect "$SOCKS_PORT" "$TCP_PORT" --size "$BYTES"
