#!/usr/bin/env bash
set -euo pipefail

# Run from the workspace root regardless of where invoked (scripts live in scripts/).
cd "$(dirname "$0")/.."

PROFILE="${PROFILE:-release}"
PACKAGE="${PACKAGE:-as-edge}"
BIN_NAME="${BIN_NAME:-as-edge}"
DOCKER_IMAGE="${DOCKER_IMAGE:-ghcr.io/rust-cross/cargo-zigbuild}"
CACHE_ROOT="${CACHE_ROOT:-${PWD}/target/zigbuild-cache}"
ARTIFACT_ROOT="${ARTIFACT_ROOT:-${PWD}/target/zigbuild-${PROFILE}}"
# rustc passes `-Wl,-O1` to GNU-style linkers. Zig 0.16 accepts it but emits a
# false-positive deprecation message (rust-lang/rust#158192). Limit the
# suppression to Zig builds; linker failures still fail the command.
ZIGBUILD_RUSTFLAGS="${RUSTFLAGS:-} -A linker-messages"
ZIGBUILD_RUSTFLAGS="${ZIGBUILD_RUSTFLAGS# }"

default_targets=(
  x86_64-unknown-linux-musl
  aarch64-unknown-linux-musl
  x86_64-pc-windows-gnu
)

if [ "$#" -gt 0 ]; then
  targets=("$@")
else
  targets=("${default_targets[@]}")
fi

mkdir -p \
  "${CACHE_ROOT}/xdg-cache" \
  "${CACHE_ROOT}/cargo/registry" \
  "${CACHE_ROOT}/cargo/git" \
  "${CACHE_ROOT}/rustup"

docker_args=(
  --rm
  -v "${PWD}:/io"
  -v "${CACHE_ROOT}/cargo/registry:/usr/local/cargo/registry"
  -v "${CACHE_ROOT}/cargo/git:/usr/local/cargo/git"
  -v "${CACHE_ROOT}/rustup:/usr/local/rustup"
  -e XDG_CACHE_HOME=/io/target/zigbuild-cache/xdg-cache
  -e "RUSTFLAGS=${ZIGBUILD_RUSTFLAGS}"
  -w /io
)
if [ -t 0 ] && [ -t 1 ]; then
  docker_args=(-it "${docker_args[@]}")
fi
if command -v id >/dev/null 2>&1; then
  docker_args+=(--user "$(id -u):$(id -g)")
fi

for target in "${targets[@]}"; do
  echo "==> docker run ${DOCKER_IMAGE} rustup target add ${target} && cargo zigbuild --locked --profile ${PROFILE} -p ${PACKAGE} --target ${target}"
  docker run "${docker_args[@]}" "${DOCKER_IMAGE}" \
    sh -c 'rustup target add "$1" && cargo zigbuild --locked --profile "$2" -p "$3" --target "$1"' \
    sh "${target}" "${PROFILE}" "${PACKAGE}"

  artifact_name="${BIN_NAME}"
  if [[ "${target}" == *windows* ]]; then
    artifact_name="${artifact_name}.exe"
  fi
  built_artifact="${PWD}/target/${target}/${PROFILE}/${artifact_name}"
  collected_dir="${ARTIFACT_ROOT}/${target}"
  mkdir -p "${collected_dir}"
  cp -f "${built_artifact}" "${collected_dir}/${artifact_name}"
  cp -f LICENSE "${collected_dir}/"
  if [ "${PACKAGE}" = "as-edge" ]; then
    cp -f THIRD_PARTY.md "${collected_dir}/"
    mkdir -p "${collected_dir}/licenses/fd" "${collected_dir}/licenses/ripgrep"
    cp -f .upstreams/fd/LICENSE-APACHE .upstreams/fd/LICENSE-MIT "${collected_dir}/licenses/fd/"
    cp -f .upstreams/ripgrep/LICENSE-MIT .upstreams/ripgrep/UNLICENSE "${collected_dir}/licenses/ripgrep/"
  fi
  echo "    collected ${collected_dir}/${artifact_name}"
done
