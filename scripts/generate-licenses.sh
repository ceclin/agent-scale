#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

output_dir="licenses/dependencies"
checksum_file="$output_dir/SHA256SUMS"
check=false
if [ "${1:-}" = "--check" ]; then
  check=true
elif [ "$#" -ne 0 ]; then
  echo "usage: $0 [--check]" >&2
  exit 2
fi

mkdir -p "$output_dir"
staging="$(mktemp -d)"
cleanup() {
  find "$staging" -depth -delete
}
trap cleanup EXIT

notice_source=".upstreams/ripgrep/crates/core/flags/complete/rg.zsh"
notice_file="licenses/ripgrep/LICENSE-BSD-3-Clause-zsh-users"
notice_expected="$staging/LICENSE-BSD-3-Clause-zsh-users"
sed -n \
  '/^# Copyright (c) 2011 Github zsh-users/,/^# ------------------------------------------------------------------------------$/p' \
  "$notice_source" \
  | sed '$d; s/^# //; s/^#$//' > "$notice_expected"
if ! cmp -s "$notice_expected" "$notice_file"; then
  echo "$notice_file does not match the notice embedded in $notice_source" >&2
  exit 1
fi

crate_manifests=()
while IFS= read -r manifest; do
  crate_manifests+=("$manifest")
done < <(find crates -name Cargo.toml -type f | sort)
checksum_inputs=(
  Cargo.lock
  Cargo.toml
  about.toml
  scripts/generate-licenses.sh
  scripts/licenses.hbs
  scripts/sync-deps.py
  scripts/upstreams.lock
  "${crate_manifests[@]}"
  "$output_dir/agent-scale.html"
  "$output_dir/as-control.html"
  "$output_dir/as-edge.html"
  "$output_dir/as-relay.html"
)

write_checksums() {
  shasum -a 256 "${checksum_inputs[@]}"
}

if $check; then
  expected_checksums="$staging/SHA256SUMS"
  write_checksums > "$expected_checksums"
  if ! cmp -s "$expected_checksums" "$checksum_file"; then
    echo "dependency license bundles are out of date; run ./scripts/generate-licenses.sh" >&2
    exit 1
  fi
  echo "checked dependency license bundle inputs and outputs"
  exit 0
fi

if ! command -v cargo-about >/dev/null 2>&1 \
  || [ "$(cargo about --version)" != "cargo-about 0.9.1" ]; then
  echo "cargo-about 0.9.1 is required; run: cargo install --locked --features cli cargo-about@0.9.1" >&2
  exit 1
fi

# Fetch the lockfile graph once, then make generation consume only the packaged
# crate sources and notices in Cargo's local cache. This avoids output depending
# on availability or changing responses from external license databases.
cargo fetch --locked

packages=(agent-scale as-control as-edge as-relay)
for package in "${packages[@]}"; do
  generated="$staging/$package.html"
  cargo about generate \
    --all-features \
    --fail \
    --locked \
    --manifest-path "crates/$package/Cargo.toml" \
    --offline \
    --output-file "$generated" \
    scripts/licenses.hbs

  destination="$output_dir/$package.html"
  cp "$generated" "$destination"
  echo "wrote $destination"
done

write_checksums > "$checksum_file"
echo "wrote $checksum_file"
