# Contributing

Contributions are welcome. For behavior changes, open an issue first when the
design or compatibility impact is not obvious.

## Toolchain and checkout

agent-scale tracks the latest stable Rust toolchain and has no MSRV. Initialize
the pinned fd and ripgrep source cache after cloning:

```console
git clone https://github.com/ceclin/agent-scale.git
cd agent-scale
cargo x init
```

The generated `.upstreams/` directory is ignored. Do not edit or commit these
upstream checkouts; update `scripts/upstreams.lock` and regenerate the wrapper
manifests with `./scripts/sync-deps.py` instead.

Use the repository task runner before submitting a change:

```console
cargo x lint
cargo x test
cargo x build
```

Run `cargo x e2e` for transport, authorization, transfer, daemon, relay, or
control-plane changes; E2E is a local check rather than a CI job. Run
`cargo x zigbuild TARGET` for a fast development cross-build. Run `cargo x
dist` only while preparing a release. Docker is required for Zig builds and
some end-to-end scenarios.

## Supported targets

- center CLI/daemon: Linux and macOS;
- control and private relay: Linux;
- edge: Linux x86-64, Linux ARM64, and Windows x86-64.

Changes to platform-specific code should preserve these targets. CI checks the
native Linux workspace, macOS center, and Windows edge. The distribution task
cross-compiles the documented edge artifacts with `cargo-zigbuild`.

## Change discipline

- Keep one logical concern per change.
- Use Conventional Commit subjects such as `fix(exec): reap cancelled child`.
- Add regression tests for bugs and protocol/state invariants.
- Treat malformed durable state as an error; never silently replace identities
  or authorization data.
- Keep queues, frame sizes, transfers, and subprocess lifetimes bounded.
- Update user-facing docs when commands, configuration, or security behavior
  changes.

The repository uses Jujutsu locally, but pull requests are ordinary GitHub pull
requests and do not require contributors to use a particular VCS client.

Maintainers preparing a version tag should follow the
[release checklist](docs/releasing.md).
