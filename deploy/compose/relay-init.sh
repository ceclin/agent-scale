#!/bin/sh
set -eu

if [ -f /relay/control.json ]; then
  exit 0
fi

as-relay join "$(cat /bootstrap/relay.join)" \
  --control-url "$CONTROL_INTERNAL_URL" \
  --state-dir /relay
