# Distributing agent-scale

Distribution has three channels. Snapshots are repeatable builds of any ref and
do not create a Git tag or GitHub Release. Prereleases and releases are immutable
builds driven by version tags. All workspace crates use the version in
`Cargo.toml`; product crates are not published to crates.io.

## Snapshot

Run the `Distribution` workflow manually and optionally enter a branch, tag, or
commit in `ref`. Leaving it empty snapshots the ref selected in the workflow UI.
No version or changelog edit is required.

Snapshot archives use a version such as `0.9.0-snapshot.42.0123456789ab`, are
available as a single GitHub Actions artifact for 14 days, and include a
consolidated `SHA256SUMS`. Build jobs retain their internal transfer artifacts
for one day only. Control and Relay images receive three tags:

- the complete snapshot version;
- commit-addressed `snapshot-<12-character-commit>`;
- mutable `snapshot`, which always identifies the most recently completed push.

Snapshot publication never creates a GitHub Release and never advances
`preview` or `latest`.

## Prepare a prerelease or release

Set `[workspace.package].version` to the next base version immediately after a
stable release and keep completed work under `Unreleased`. For example, after
`v0.6.0`, advance the workspace and lockfile to `0.7.0`; snapshots then identify
the development line without further version edits.

Before publishing, run `cargo x lint`, `cargo x test`, and the relevant
end-to-end tests, then land the verified source on `main`:

- A prerelease tag such as `v0.7.0-preview.1` must target the workspace base
  version `0.7.0`. Preview numbering lives only in the tag, so later previews
  do not require Cargo or lockfile changes and the changelog remains
  `Unreleased`.
- Before the stable `v0.7.0` tag, move the completed entries into the exact
  dated heading `## 0.7.0 - YYYY-MM-DD` and update the default Control and Relay
  image tags in `compose.yaml` to `0.7.0`. The tag must exactly match the
  workspace version.
- After publishing the stable release, advance the workspace to the next
  planned base version and begin a new `Unreleased` section.

The release workflow rejects malformed tags, prereleases for a different base
version, stable tags that do not match the workspace version, and stable
versions without a dated changelog heading. Do not reuse or move a published
release tag.

A SemVer prerelease tag creates a GitHub Prerelease and advances the mutable
`preview` image tag. A stable tag creates a normal GitHub Release and advances
`latest`. Both channels also publish images under their exact immutable version;
prereleases never advance `latest`, and stable releases never advance `preview`.

## Published artifacts

The workflow creates versioned archives for:

- `as-edge`: Linux x86-64, Linux ARM64, Windows x86-64, macOS ARM64, and macOS
  x86-64;
- `agent-scale`: Linux x86-64, Linux ARM64, Windows x86-64, macOS ARM64,
  and macOS x86-64;
- `as-control`: Linux x86-64 and Linux ARM64;
- `as-relay`: Linux x86-64 and Linux ARM64.

Linux archives use Rust's static musl targets on matching x86-64 and ARM64
runners. Windows archives use the native `x86_64-pc-windows-msvc` toolchain;
the release workflow does not cross-compile either platform.

Every archive has an entry in the distribution's `SHA256SUMS`. Verify a download
from the directory containing both files with:

```console
sha256sum --check --ignore-missing SHA256SUMS
```

Every archive contains the project `LICENSE` and a generated
`THIRD_PARTY_LICENSES.html` covering the binary's complete non-development Rust
dependency graph. The Control and Relay container images carry the same files
under `/usr/share/licenses/agent-scale`. Regenerate the committed dependency
license bundles after dependency changes with `./scripts/generate-licenses.sh`;
`cargo x lint` rejects stale bundles using committed input/output checksums
without rerunning the comparatively expensive generator.

The same workflow publishes separate Control and Relay images for `linux/amd64`
and `linux/arm64` to `ghcr.io/ceclin/agent-scale-control:<version>` and
`ghcr.io/ceclin/agent-scale-relay:<version>`, then advances `preview` or `latest`
according to the channel.
The Compose file accepts `AGENT_SCALE_CONTROL_IMAGE` and
`AGENT_SCALE_RELAY_IMAGE` when immutable digests or private registry mirrors are
preferred. Client is distributed only as an `agent-scale` binary archive.

## Embedded upstream licenses

`as-edge` embeds pinned fd and ripgrep sources. Binary distributions select the
MIT option offered by both projects and include their copyright and full MIT
license texts. The alternative Apache-2.0 and Unlicense texts are included for
completeness. The ripgrep bundle also reproduces the BSD-3-Clause notice for
zsh-users code in its embedded zsh completion. Other agent-scale binaries do
not embed those upstream sources.
