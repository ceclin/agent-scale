#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 4 ]; then
  echo "usage: $0 <input-root> <binary> <version> <output-root>" >&2
  exit 2
fi

input_root="$1"
binary="$2"
version="$3"
output_root="$4"

if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?$ ]]; then
  echo "version must be an unprefixed semantic version without build metadata: $version" >&2
  exit 2
fi

case "$binary" in
  agent-scale | as-control | as-edge | as-relay) ;;
  *) echo "unsupported release binary: $binary" >&2; exit 2 ;;
esac

mkdir -p "$output_root"
# Packaging runs from a temporary staging directory, so callers may safely pass
# the relative output paths used by local and CI release commands.
output_root="$(cd "$output_root" && pwd -P)"
found=0

for target_dir in "$input_root"/*; do
  [ -d "$target_dir" ] || continue
  target="$(basename "$target_dir")"
  executable="$binary"
  extension="tar.gz"
  if [[ "$target" == *windows* ]]; then
    executable="${binary}.exe"
    extension="zip"
  fi
  [ -f "$target_dir/$executable" ] || continue

  found=1
  bundle="${binary}-v${version}-${target}"
  staging="$(mktemp -d)"
  cleanup() {
    find "$staging" -depth -delete
  }
  trap cleanup EXIT
  mkdir -p "$staging/$bundle"
  cp "$target_dir/$executable" "$staging/$bundle/"
  cp "$target_dir/LICENSE" "$staging/$bundle/"
  if [ ! -f "$target_dir/THIRD_PARTY_LICENSES.html" ]; then
    echo "$binary release input is missing THIRD_PARTY_LICENSES.html" >&2
    exit 1
  fi
  cp "$target_dir/THIRD_PARTY_LICENSES.html" "$staging/$bundle/"

  if [ "$binary" = "as-edge" ]; then
    for required in \
      THIRD_PARTY.md \
      licenses/fd/LICENSE-APACHE \
      licenses/fd/LICENSE-MIT \
      licenses/ripgrep/LICENSE-BSD-3-Clause-zsh-users \
      licenses/ripgrep/LICENSE-MIT \
      licenses/ripgrep/UNLICENSE; do
      if [ ! -f "$target_dir/$required" ]; then
        echo "as-edge release input is missing $required" >&2
        exit 1
      fi
    done
    cp "$target_dir/THIRD_PARTY.md" "$staging/$bundle/"
    cp -R "$target_dir/licenses" "$staging/$bundle/"
  fi

  archive="$output_root/${bundle}.${extension}"
  if [ "$extension" = "zip" ]; then
    (cd "$staging" && zip -q -r "$archive" "$bundle")
  else
    tar -C "$staging" -czf "$archive" "$bundle"
  fi
  (cd "$output_root" && sha256sum "$(basename "$archive")" > "$(basename "$archive").sha256")
  cleanup
  trap - EXIT
  echo "packaged $archive"
done

if [ "$found" -eq 0 ]; then
  echo "no $binary artifacts found under $input_root" >&2
  exit 1
fi
