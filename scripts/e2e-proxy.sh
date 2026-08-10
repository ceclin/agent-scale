#!/usr/bin/env bash
# Exercises the process boundaries that unit tests cannot model: runtime-owned
# listeners, SOCKS negotiation, Edge-side DNS, and UDP packet framing.
set -euo pipefail
cd "$(dirname "$0")/.."

BIN=target/debug
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

EDGE_ID=$(AGENT_SCALE_HOME="$EDGE_HOME" "$BIN/as-edge" id proxy-e2e)
AGENT_SCALE_HOME="$CLIENT_HOME" "$BIN/agent-scale" edge add proxy-e2e "$EDGE_ID" --relay "$RELAY_URL" >/dev/null
AGENT_SCALE_HOME="$EDGE_HOME" "$BIN/as-edge" run proxy-e2e --relay "$RELAY_URL" >/dev/null 2>&1 &
EDGE_PID=$!

python3 scripts/e2e-proxy.py server >"$BACKEND_LOG" &
BACKEND_PID=$!
for _ in $(seq 1 100); do
  read -r TCP_PORT UDP_PORT <"$BACKEND_LOG" || true
  [ -n "${UDP_PORT:-}" ] && break
  sleep 0.1
done
[ -n "${TCP_PORT:-}" ] && [ -n "${UDP_PORT:-}" ]

for _ in $(seq 1 100); do
  AGENT_SCALE_HOME="$CLIENT_HOME" "$BIN/agent-scale" -e proxy-e2e exec -- true >/dev/null 2>&1 && break
  sleep 0.1
done

FIXED=$(AGENT_SCALE_HOME="$CLIENT_HOME" "$BIN/agent-scale" -e proxy-e2e proxy start tcp echo \
  --listen 127.0.0.1:0 --target "localhost:$TCP_PORT")
FIXED_PORT=$(sed -E 's/.*listening on [^:]+:([0-9]+).*/\1/' <<<"$FIXED")
python3 scripts/e2e-proxy.py fixed "$FIXED_PORT"
echo "  PASS fixed TCP and Edge-side DNS"

SOCKS=$(AGENT_SCALE_HOME="$CLIENT_HOME" "$BIN/agent-scale" -e proxy-e2e proxy start socks5 dev \
  --listen 127.0.0.1:0)
SOCKS_PORT=$(sed -E 's/.*listening on [^:]+:([0-9]+).*/\1/' <<<"$SOCKS")
python3 scripts/e2e-proxy.py socks-connect "$SOCKS_PORT" "$TCP_PORT"
python3 scripts/e2e-proxy.py socks-udp "$SOCKS_PORT" "$UDP_PORT"
echo "  PASS SOCKS5 CONNECT and UDP ASSOCIATE"

PROXIES=$(AGENT_SCALE_HOME="$CLIENT_HOME" "$BIN/agent-scale" proxy ls)
grep -q '^echo:' <<<"$PROXIES"
grep -q '^dev:' <<<"$PROXIES"
AGENT_SCALE_HOME="$CLIENT_HOME" "$BIN/agent-scale" proxy stop echo
! AGENT_SCALE_HOME="$CLIENT_HOME" "$BIN/agent-scale" proxy ls | grep -q '^echo:'
echo "  PASS runtime list and stop"

AGENT_SCALE_HOME="$CLIENT_HOME" "$BIN/agent-scale" proxy stop dev
AGENT_SCALE_HOME="$CLIENT_HOME" "$BIN/agent-scale" daemon --stop >/dev/null
IDLE_PROXY=$(AGENT_SCALE_IDLE_SECS=1 AGENT_SCALE_HOME="$CLIENT_HOME" "$BIN/agent-scale" \
  -e proxy-e2e proxy start tcp idle --listen 127.0.0.1:0 --target "localhost:$TCP_PORT")
IDLE_PORT=$(sed -E 's/.*listening on [^:]+:([0-9]+).*/\1/' <<<"$IDLE_PROXY")
sleep 2
AGENT_SCALE_HOME="$CLIENT_HOME" "$BIN/agent-scale" daemon --status | grep -q 'proxies=1'
python3 scripts/e2e-proxy.py fixed "$IDLE_PORT" --size $((64 * 1024 * 1024))
echo "  PASS listener pins daemon; 64 MiB smoke completed"

AGENT_SCALE_HOME="$CLIENT_HOME" "$BIN/agent-scale" daemon --stop >/dev/null
[ "$(AGENT_SCALE_HOME="$CLIENT_HOME" "$BIN/agent-scale" proxy ls)" = "no proxies running" ]
echo "  PASS daemon restart boundary does not persist definitions"
