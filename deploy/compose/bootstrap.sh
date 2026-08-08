#!/bin/sh
set -eu

if [ ! -f /control/control.db ]; then
  as-control init \
    --public-url "$CONTROL_PUBLIC_URL" \
    --audience "$CONTROL_AUDIENCE"
fi

if [ ! -f /bootstrap/center.join ]; then
  as-control bootstrap center "$CONTROL_CENTER_NAME" \
    --ttl-secs "$CONTROL_CENTER_TTL_SECS" > /bootstrap/center.join
fi

if [ ! -f /relay/control.json ]; then
  as-control bootstrap relay "$RELAY_NAME" "$RELAY_PUBLIC_URL" \
    --ttl-secs "$RELAY_INVITE_TTL_SECS" > /bootstrap/relay.join
fi
