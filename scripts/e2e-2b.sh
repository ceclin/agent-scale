#!/usr/bin/env bash
# Milestone 2b end-to-end: relay + edge agent + auto-spawned center daemon,
# proving streaming exec, exit-code propagation, and the daemon lifecycle.
set -uo pipefail
cd "$(dirname "$0")/.."   # repo root (workspace); scripts live in scripts/

BIN=target/debug
AGENT=$BIN/as-edge
SCALE=$BIN/agent-scale
RELAY=$BIN/relay-dev

EDGE_HOME=$(mktemp -d)
CENTER_HOME=$(mktemp -d)
RELAY_LOG=$(mktemp)
EDGE_LOG=$(mktemp)
OUT=$(mktemp)
PROJECT=$(mktemp -d)
FAILED=0

cleanup() {
  AGENT_SCALE_HOME="$CENTER_HOME" "$SCALE" daemon --stop >/dev/null 2>&1 || true
  [ -n "${EDGE_PID:-}" ] && kill "$EDGE_PID" 2>/dev/null
  [ -n "${RELAY_PID:-}" ] && kill "$RELAY_PID" 2>/dev/null
  [ -n "${PYPID:-}" ] && kill "$PYPID" 2>/dev/null
  rm -rf "$EDGE_HOME" "$CENTER_HOME" "$PROJECT" "$RELAY_LOG" "$EDGE_LOG" "$OUT" "${PYSRV:-}" "${PYSRV:-}.port"
}
trap cleanup EXIT

check() { if [ "$1" = "PASS" ]; then echo "  ✅ $2"; else echo "  ❌ $2"; FAILED=1; fi; }

# 1. relay
"$RELAY" >"$RELAY_LOG" 2>/dev/null &
RELAY_PID=$!
URL=""
for _ in $(seq 1 50); do URL=$(head -n1 "$RELAY_LOG" 2>/dev/null); [ -n "$URL" ] && break; sleep 0.1; done
[ -n "$URL" ] || { echo "relay failed to start"; exit 1; }
echo "relay:  $URL"

# 2. edge identity (the only id a human copies — no CENTER_ID needed)
EDGE_ID=$(AGENT_SCALE_HOME="$EDGE_HOME" "$AGENT" id test)
echo "edge:   $EDGE_ID"

# 3. register the edge via the CLI (exercises `edge add` + `edge ls`)
AGENT_SCALE_HOME="$CENTER_HOME" "$SCALE" edge add test "$EDGE_ID" --relay "$URL" >/dev/null
AGENT_SCALE_HOME="$CENTER_HOME" "$SCALE" edge ls | grep -q "$EDGE_ID" \
  && echo "edge add/ls ok" || { echo "edge add/ls FAILED"; exit 1; }

# 4. start edge agent WITHOUT --center: it trusts the first center to connect
#    (TOFU). Give it time to come online.
AGENT_SCALE_HOME="$EDGE_HOME" "$AGENT" run test --relay "$URL" >"$EDGE_LOG" 2>&1 &
EDGE_PID=$!
sleep 3

echo "--- tests ---"

# Warm up: the first exec auto-spawns the daemon and dials the edge. Do it
# synchronously so the streaming check below races only the command, not the
# daemon cold-start.
AGENT_SCALE_HOME="$CENTER_HOME" "$SCALE" -e test exec -- true >/dev/null 2>&1
check $([ $? -eq 0 ] && echo PASS || echo FAIL) "warmup exec (auto-spawn daemon + dial edge)"
[ -f "$EDGE_HOME/test/trusted_center" ] && check PASS "TOFU: edge pinned center on first connect" || check FAIL "TOFU pin"

# T1: streaming. Command prints FIRST, waits 2s, prints SECOND. At t=1s FIRST
# must already be visible (streamed) and SECOND must not be (process still running).
AGENT_SCALE_HOME="$CENTER_HOME" "$SCALE" -e test exec -- sh -c 'echo FIRST; sleep 2; echo SECOND' >"$OUT" 2>/dev/null &
CPID=$!
sleep 1
if grep -q FIRST "$OUT" && ! grep -q SECOND "$OUT"; then check PASS "streaming: FIRST arrived ~1s before process exit"; else check FAIL "streaming"; fi
wait "$CPID"
grep -q SECOND "$OUT" && check PASS "full output received after exit" || check FAIL "missing SECOND"

# T2: exit-code propagation
AGENT_SCALE_HOME="$CENTER_HOME" "$SCALE" -e test exec -- sh -c 'exit 7' >/dev/null 2>&1
[ $? -eq 7 ] && check PASS "exit code 7 propagated" || check FAIL "exit code propagation"

# T3: stdout/stderr separation
AGENT_SCALE_HOME="$CENTER_HOME" "$SCALE" -e test exec -- sh -c 'echo to-out; echo to-err 1>&2' >"$OUT" 2>/dev/null
grep -q to-out "$OUT" && check PASS "stdout captured" || check FAIL "stdout"

# T4: daemon was auto-spawned and is registered/alive
STATUS=$(AGENT_SCALE_HOME="$CENTER_HOME" "$SCALE" daemon --status)
echo "  $STATUS"
echo "$STATUS" | grep -qE '^daemon pid=[0-9]+ version=[^ ]+ active=[0-9]+ edges=[0-9]+ socket=' \
  && check PASS "daemon auto-spawned and alive" || check FAIL "daemon status"

# T5: iroh-blobs file transfer round-trip (upload then download back)
SRC=$(mktemp); DL=$(mktemp); REMOTE=$(mktemp -u)
head -c 4000000 /dev/urandom >"$SRC"
AGENT_SCALE_HOME="$CENTER_HOME" "$SCALE" -e test upload "$SRC" "$REMOTE" >/dev/null 2>&1 \
  && check PASS "upload" || check FAIL "upload"
{ [ -f "$REMOTE" ] && cmp -s "$SRC" "$REMOTE"; } && check PASS "uploaded bytes match on edge" || check FAIL "upload content"
AGENT_SCALE_HOME="$CENTER_HOME" "$SCALE" -e test download "$REMOTE" "$DL" >/dev/null 2>&1 \
  && check PASS "download" || check FAIL "download"
cmp -s "$SRC" "$DL" && check PASS "downloaded bytes match" || check FAIL "download content"
rm -f "$SRC" "$DL" "$REMOTE"

# T6: MCP-proxy transparent pipe. `cat` stands in for an MCP server (echoes
# stdin->stdout); a line sent in must come back out through the whole chain.
AGENT_SCALE_HOME="$CENTER_HOME" "$SCALE" -e test mcp add echo -- cat >/dev/null
MCP_OUT=$(printf 'mcp-ping\n' | timeout 20 env AGENT_SCALE_HOME="$CENTER_HOME" "$SCALE" -e test mcp run echo 2>/dev/null | head -1)
[ "$MCP_OUT" = "mcp-ping" ] && check PASS "mcp-proxy round-trip (via cat)" || check FAIL "mcp-proxy (got '$MCP_OUT')"
AGENT_SCALE_HOME="$CENTER_HOME" "$SCALE" -e test mcp ls | grep -q '^echo:' \
  && check PASS "edge-owned mcp registry list" || check FAIL "mcp registry list"
[ -f "$EDGE_HOME/test/mcp.json" ] \
  && check PASS "mcp registry persisted on edge" || check FAIL "mcp registry persistence"
AGENT_SCALE_HOME="$CENTER_HOME" "$SCALE" -e test mcp sync \
  --client claude --client codex --project "$PROJECT" >/dev/null 2>&1
{ grep -q 'test__echo' "$PROJECT/.mcp.json" \
  && grep -q 'mcp_servers.test__echo' "$PROJECT/.codex/config.toml" \
  && grep -q 'test__echo' "$PROJECT/.agent-scale/mcp-sync.json"; } \
  && check PASS "project-level Claude/Codex mcp sync" || check FAIL "mcp project sync"

# T7: MCP-proxy HTTP (Streamable). A tiny Python echo server stands in for an
# HTTP-transport MCP server (like x64dbg's); a JSON-RPC POST must round-trip.
if command -v python3 >/dev/null; then
  PYSRV=$(mktemp --suffix=.py)
  cat >"$PYSRV" <<'PY'
import http.server, json, queue
Q = queue.Queue()
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # standalone server->client SSE stream
        self.send_response(200); self.send_header('content-type', 'text/event-stream'); self.end_headers()
        note = json.dumps({"jsonrpc": "2.0", "method": "notifications/message",
                           "params": {"text": "hi-from-server"}})
        self.wfile.write(('data: %s\n\n' % note).encode()); self.wfile.flush()
        while True:
            self.wfile.write(('data: %s\n\n' % Q.get()).encode()); self.wfile.flush()
    def do_POST(self):
        n = int(self.headers.get('content-length', 0)); msg = json.loads(self.rfile.read(n))
        if msg.get("method") == "initialize":
            result = {"protocolVersion": msg["params"]["protocolVersion"],
                      "capabilities": {},
                      "serverInfo": {"name": "e2e", "version": "1"}}
        else:
            result = {"echo": msg.get("method")}
        out = json.dumps({"jsonrpc": "2.0", "id": msg.get("id"),
                          "result": result}).encode()
        self.send_response(200); self.send_header('content-type', 'application/json')
        self.send_header('content-length', str(len(out))); self.end_headers(); self.wfile.write(out)
    def log_message(self, *a): pass
s = http.server.ThreadingHTTPServer(('127.0.0.1', 0), H)
print(s.server_address[1], flush=True)
s.serve_forever()
PY
  python3 "$PYSRV" >"$PYSRV.port" 2>/dev/null &
  PYPID=$!
  MPORT=""
  for _ in $(seq 1 50); do MPORT=$(head -n1 "$PYSRV.port" 2>/dev/null); [ -n "$MPORT" ] && break; sleep 0.1; done
  AGENT_SCALE_HOME="$CENTER_HOME" "$SCALE" -e test mcp add echo-http --http "http://127.0.0.1:$MPORT/" >/dev/null
  AGENT_SCALE_HOME="$CENTER_HOME" "$SCALE" -e test mcp check echo-http >/dev/null 2>&1 \
    && check PASS "mcp initialize health check" || check FAIL "mcp health check"
  AGENT_SCALE_HOME="$CENTER_HOME" "$SCALE" -e test exec -- true >/dev/null 2>&1
  HTTP_OUT=$( (printf '{"jsonrpc":"2.0","id":7,"method":"hello"}\n'; sleep 2) \
    | timeout 20 env AGENT_SCALE_HOME="$CENTER_HOME" "$SCALE" -e test mcp run echo-http 2>/dev/null)
  echo "$HTTP_OUT" | grep -q '"echo": *"hello"' \
    && check PASS "mcp-proxy http/streamable POST response" || check FAIL "mcp-proxy http POST (got '$HTTP_OUT')"
  echo "$HTTP_OUT" | grep -q 'hi-from-server' \
    && check PASS "mcp-proxy http/streamable server-initiated (GET-SSE)" || check FAIL "mcp-proxy GET-SSE (got '$HTTP_OUT')"
  kill "$PYPID" 2>/dev/null; PYPID=""

  # T8: MCP-proxy legacy HTTP+SSE. GET sse advertises a POST endpoint; the
  # response comes back asynchronously on the SSE stream.
  PYSSE=$(mktemp --suffix=.py)
  cat >"$PYSSE" <<'PY'
import http.server, json, queue
Q = queue.Queue()
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('content-type', 'text/event-stream'); self.end_headers()
        self.wfile.write(b'event: endpoint\ndata: /messages\n\n'); self.wfile.flush()
        while True:
            item = Q.get()
            self.wfile.write(('event: message\ndata: %s\n\n' % item).encode()); self.wfile.flush()
    def do_POST(self):
        n = int(self.headers.get('content-length', 0)); msg = json.loads(self.rfile.read(n))
        Q.put(json.dumps({"jsonrpc": "2.0", "id": msg.get("id"), "result": {"echo": msg.get("method")}}))
        self.send_response(202); self.end_headers()
    def log_message(self, *a): pass
s = http.server.ThreadingHTTPServer(('127.0.0.1', 0), H)
print(s.server_address[1], flush=True)
s.serve_forever()
PY
  python3 "$PYSSE" >"$PYSSE.port" 2>/dev/null &
  PYPID=$!
  SPORT=""
  for _ in $(seq 1 50); do SPORT=$(head -n1 "$PYSSE.port" 2>/dev/null); [ -n "$SPORT" ] && break; sleep 0.1; done
  AGENT_SCALE_HOME="$CENTER_HOME" "$SCALE" -e test mcp add echo-sse --sse "http://127.0.0.1:$SPORT/sse" >/dev/null
  AGENT_SCALE_HOME="$CENTER_HOME" "$SCALE" -e test exec -- true >/dev/null 2>&1
  SSE_OUT=$( (printf '{"jsonrpc":"2.0","id":8,"method":"legacy"}\n'; sleep 2) \
    | timeout 20 env AGENT_SCALE_HOME="$CENTER_HOME" "$SCALE" -e test mcp run echo-sse 2>/dev/null | head -1)
  echo "$SSE_OUT" | grep -q '"echo": *"legacy"' \
    && check PASS "mcp-proxy http/sse (legacy) round-trip" || check FAIL "mcp-proxy sse (got '$SSE_OUT')"
  kill "$PYPID" 2>/dev/null; PYPID=""
  rm -f "$PYSSE" "$PYSSE.port"
else
  echo "  (skipped http mcp test: no python3)"
fi

# T9: idle-shutdown must not kill in-flight work. Spawn a fresh daemon with a 2s
# idle timeout and run a 5s exec — it must survive (the old bug killed it at 2s).
AGENT_SCALE_HOME="$CENTER_HOME" "$SCALE" daemon --stop >/dev/null 2>&1
IDLE_OUT=$(AGENT_SCALE_IDLE_SECS=2 AGENT_SCALE_HOME="$CENTER_HOME" "$SCALE" -e test exec -- sh -c 'sleep 5; echo survived' 2>/dev/null)
[ "$IDLE_OUT" = "survived" ] && check PASS "idle timer doesn't kill in-flight exec" || check FAIL "idle killed exec (got '$IDLE_OUT')"
# ...and once the work is done, it should actually idle out (registry removed).
sleep 4
STATUS9=$(AGENT_SCALE_HOME="$CENTER_HOME" "$SCALE" daemon --status)
echo "$STATUS9" | grep -qE "no daemon|alive=false" && check PASS "daemon idles out once work is done" || check FAIL "daemon didn't idle out ($STATUS9)"

echo "--- $( [ $FAILED -eq 0 ] && echo ALL PASS || echo FAILURES ) ---"
exit $FAILED
