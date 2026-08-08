#!/bin/sh
set -eu

if [ ! -f /control/state.json ]; then
  as-control init \
    --public-url "$CONTROL_PUBLIC_URL" \
    --audience "$CONTROL_AUDIENCE" \
    --state-dir /control
fi

if [ ! -f /bootstrap/center.join ]; then
  as-control bootstrap center "$CONTROL_CENTER_NAME" \
    --ttl-secs "$CONTROL_CENTER_TTL_SECS" \
    --state-dir /control > /bootstrap/center.join
fi

if [ ! -f /relay/control.json ]; then
  as-control bootstrap relay "$RELAY_NAME" "$RELAY_PUBLIC_URL" \
    --ttl-secs "$RELAY_INVITE_TTL_SECS" \
    --state-dir /control > /bootstrap/relay.join
fi
