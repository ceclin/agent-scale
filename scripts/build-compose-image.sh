#!/bin/sh
set -eu

case "$(uname -m)" in
  x86_64 | amd64) RUST_TARGET=x86_64-unknown-linux-musl ;;
  aarch64 | arm64) RUST_TARGET=aarch64-unknown-linux-musl ;;
  *) echo "unsupported host architecture: $(uname -m)" >&2; exit 1 ;;
esac
export RUST_TARGET

cargo zigbuild --locked --release \
  --target "$RUST_TARGET" \
  -p as-control \
  -p as-relay

docker compose -f compose.yaml -f compose.local.yaml build
