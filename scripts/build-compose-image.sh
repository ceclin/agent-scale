#!/bin/sh
set -eu

case "$(uname -m)" in
  x86_64 | amd64)
    RUST_TARGET=x86_64-unknown-linux-musl
    OCI_ARCH=amd64
    ;;
  aarch64 | arm64)
    RUST_TARGET=aarch64-unknown-linux-musl
    OCI_ARCH=arm64
    ;;
  *) echo "unsupported host architecture: $(uname -m)" >&2; exit 1 ;;
esac

cargo zigbuild --locked --release \
  --target "$RUST_TARGET" \
  -p as-control \
  -p as-relay

mkdir -p target/container-root/bin
cp "target/$RUST_TARGET/release/as-control" "target/container-root/bin/as-control-$OCI_ARCH"
cp "target/$RUST_TARGET/release/as-relay" "target/container-root/bin/as-relay-$OCI_ARCH"

docker compose -f compose.yaml -f compose.local.yaml build
