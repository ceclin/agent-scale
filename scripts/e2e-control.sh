#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d /tmp/agent-scale-control-e2e.XXXXXX)
control_pid=
relay_pid=
edge_pid=

cleanup() {
  for center_home in "$work/center-a" "$work/center-b"; do
    AGENT_SCALE_HOME="$center_home" target/debug/agent-scale daemon --stop >/dev/null 2>&1 || true
  done
  for pid in "$edge_pid" "$relay_pid" "$control_pid"; do
    if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || true; fi
  done
  rm -rf -- "$work"
}
trap cleanup EXIT

cd "$root"
cargo build -q -p as-control -p as-relay -p as-edge -p agent-scale

control_port=34350
relay_port=34340
relay_admin_port=34341
admin_socket="$work/control/admin.sock"
control_url="http://127.0.0.1:$control_port"
relay_url="http://127.0.0.1:$relay_port"
export AS_CONTROL_STATE_DIR="$work/control"
control=(target/debug/as-control)

"${control[@]}" init \
  --public-url "$control_url" \
  --audience e2e >/dev/null
"${control[@]}" run \
  --bind "127.0.0.1:$control_port" \
  >"$work/control.log" 2>&1 &
control_pid=$!

for _ in 1 2 3 4 5 6 7 8 9 10; do
  if curl -fsS "$control_url/healthz" >/dev/null && [[ -S "$admin_socket" ]]; then break; fi
  sleep 0.1
done

center_a_url=$("${control[@]}" center invite center-a)
AGENT_SCALE_HOME="$work/center-a" target/debug/agent-scale control join "$center_a_url" >/dev/null
relay_join=$("${control[@]}" relay invite relay-a "$relay_url")
printf '%s\n' "$relay_join" >"$work/relay.join"
target/debug/as-relay run \
  --relay-bind "127.0.0.1:$relay_port" \
  --admin-bind "127.0.0.1:$relay_admin_port" \
  --join-if-needed "$work/relay.join" \
  --control-url "$control_url" \
  --state-dir "$work/relay" >"$work/relay.log" 2>&1 &
relay_pid=$!

edge_join=$(AGENT_SCALE_HOME="$work/center-a" target/debug/agent-scale edge invite box)
AGENT_SCALE_HOME="$work/edge" target/debug/as-edge join "$edge_join" --foreground \
  >"$work/edge.log" 2>&1 &
edge_pid=$!

for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  if output=$(AGENT_SCALE_HOME="$work/center-a" target/debug/agent-scale -e box exec -- sh -c 'printf first-center' 2>/dev/null) \
      && [[ "$output" == "first-center" ]]; then
    break
  fi
  sleep 0.25
done
[[ "${output:-}" == "first-center" ]]
AGENT_SCALE_HOME="$work/center-a" target/debug/agent-scale -e box mcp add echo -- cat

# Restart Control and prove the SQLite-backed topology is restored before
# continuing reconciliation.
kill "$control_pid"
wait "$control_pid" 2>/dev/null || true
control_pid=
"${control[@]}" run --bind "127.0.0.1:$control_port" >"$work/control.log" 2>&1 &
control_pid=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if curl -fsS "$control_url/healthz" >/dev/null && [[ -S "$admin_socket" ]]; then break; fi
  sleep 0.1
done
"${control[@]}" status | grep -q '^edges:    1$'

center_b_join=$("${control[@]}" center invite center-b)
AGENT_SCALE_HOME="$work/center-b" target/debug/agent-scale control join "$center_b_join" >/dev/null
"${control[@]}" edge transfer center-a/box center-b

output=$(AGENT_SCALE_HOME="$work/center-b" target/debug/agent-scale -e box exec -- sh -c 'printf transferred')
[[ "$output" == "transferred" ]]
AGENT_SCALE_HOME="$work/center-b" target/debug/agent-scale -e box mcp ls | grep -q '^echo:'

if AGENT_SCALE_HOME="$work/center-a" target/debug/agent-scale -e box exec -- true >"$work/cross.out" 2>"$work/cross.err"; then
  echo "old owner unexpectedly retained the edge" >&2
  exit 1
fi
grep -q "unknown edge" "$work/cross.err"

# A recycled environment gets a new Edge identity rather than relying on
# transfer. Destroy the old identity, invite the same logical name, and verify
# the replacement executes before explicit Edge-first/Center-last cleanup.
old_edge_id=$("${control[@]}" edge ls | awk '/endpoint_id:/ { print $2; exit }')
"${control[@]}" edge rm center-b/box
kill "$edge_pid"
wait "$edge_pid" 2>/dev/null || true
edge_pid=
replacement_join=$(AGENT_SCALE_HOME="$work/center-b" target/debug/agent-scale edge invite box)
AGENT_SCALE_HOME="$work/edge-replacement" target/debug/as-edge join "$replacement_join" --foreground \
  >"$work/edge-replacement.log" 2>&1 &
edge_pid=$!
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  if output=$(AGENT_SCALE_HOME="$work/center-b" target/debug/agent-scale -e box exec -- sh -c 'printf replacement' 2>/dev/null) \
      && [[ "$output" == "replacement" ]]; then break; fi
  sleep 0.25
done
[[ "${output:-}" == "replacement" ]]
new_edge_id=$("${control[@]}" edge ls | awk '/endpoint_id:/ { print $2; exit }')
[[ "$new_edge_id" != "$old_edge_id" ]]
AGENT_SCALE_HOME="$work/center-b" target/debug/agent-scale edge rm box
"${control[@]}" center rm center-b
"${control[@]}" center rm center-a

for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  members=$(curl -fsS "http://127.0.0.1:$relay_admin_port/v1/status")
  if [[ "$members" == *'"members":0'* ]]; then break; fi
  sleep 0.1
done
[[ "$members" == *'"members":0'* ]]

status=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$control_url/v1/admin/overview")
[[ "$status" == "404" ]]
[[ "$(stat -c '%a' "$admin_socket")" == "600" ]]
"${control[@]}" status | grep -q '^centers:  0$'

echo "local-admin multi-center control e2e passed"
