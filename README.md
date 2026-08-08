# agent-scale

Run commands, move files, and use MCP servers on remote Linux and Windows test
machines over authenticated, direct [iroh](https://iroh.computer/) connections.
There is no shared command server and neither endpoint needs an inbound port.

agent-scale is pre-release software. Its configuration and wire protocols may
change incompatibly before 1.0.

## Components

| Binary | Runs on | Purpose |
| --- | --- | --- |
| `agent-scale` | Linux, macOS, or Windows x86-64 developer machine | CLI and auto-started local daemon |
| `as-edge` | Linux x86-64/ARM64 or Windows x86-64 | Authenticated command, transfer, and MCP endpoint |
| `as-relay` | Linux relay host | Private iroh relay with signed dynamic membership |
| `as-control` | Linux control host | Multi-center enrollment and signed desired state |

Versioned archives for all four binaries and the multi-architecture Control and
Relay images are published by GitHub Releases. Each release includes
a consolidated `SHA256SUMS`; see the [release guide](docs/releasing.md) for the
target matrix and verification command.

The center and edge pin each other's Ed25519 `EndpointId`. QUIC provides mutual
transport authentication; relay membership and control-plane maps are signed.
If Control is temporarily unavailable, enrolled nodes continue with their last
verified map. A definitive revocation response removes authorization and closes
live connections.

## Quick start

Build the workspace with the latest stable Rust toolchain:

```console
git clone https://github.com/ceclin/agent-scale.git
cd agent-scale
cargo x init
cargo build --release -p agent-scale -p as-edge
```

Start an edge and copy its printed ID:

```console
# Test machine
as-edge id test
as-edge run test --relay https://your-relay.example
```

Register it and execute a command:

```console
# Developer machine
agent-scale edge add test EDGE_ID --relay https://your-relay.example
agent-scale -e test exec -- cargo test
```

On a Windows development machine, download the Windows x86-64 `agent-scale`
archive, place `agent-scale.exe` on `PATH`, and run the same Center commands
from PowerShell. The background daemon is auto-started without a console window
and communicates through a current-user-local Named Pipe; it does not install a
service, require Administrator privileges, or open a listening network port.
Windows Center support is currently experimental: its build and local IPC tests
are wired into CI, but the complete Center-to-Edge workflow has not yet been
validated on a real Windows development host.

Without `--center`, an edge uses trust on first use and durably pins the first
center before authorizing it. Pass `--center ENDPOINT_ID` for an explicit pin.
See [simple mode](docs/simple-mode.md) and the
[control-plane guide](docs/control-plane.md) for complete setup.

## Capabilities

- live stdout/stderr command streaming with cancellation propagation;
- content-addressed, verified, disk-backed upload and download;
- built-in full `fd` and `rg` CLIs in the single `as-edge` multicall binary;
- transparent stdio, Streamable HTTP, and legacy SSE MCP proxying;
- Control-signed private relay membership with offline snapshot recovery;
- optional multi-center enrollment and hot-reloaded desired state;
- scheduler-neutral Provisioner API for isolated Center-to-Edge reconciliation.

More detail is in [MCP](docs/mcp.md), [private relay](docs/private-relay.md), and
[control plane](docs/control-plane.md). External controllers should also see the
[Provisioner API](docs/provisioner-api.md).

## Development

Repository tasks follow the FastLabs-style `cargo x` entry point:

```console
cargo x init
cargo x lint
cargo x test
cargo x build
cargo x e2e
cargo x zigbuild x86_64-unknown-linux-musl
```

`cargo x init` checks out the pinned fd and ripgrep revisions into the ignored
`.upstreams/` build-input cache. Those upstream trees are never tracked or
modified by repository tooling; wrapper builds copy their sources to Cargo's
`OUT_DIR` before adapting the entry points. Other `cargo x` tasks initialize the
cache automatically.

End-to-end tests are intentionally local-only. Run `cargo x e2e` when changing
transport or lifecycle behavior. Development cross-builds use `cargo x
zigbuild [TARGET...]` with Cargo's default release profile (no LTO, 16 codegen
units). Run `cargo x dist` only while preparing a release; it enables full LTO
with one codegen unit for the slower three-target Docker/cargo-zigbuild build.

`cargo x lint` checks formatting, strict Clippy, documentation, generated
wrapper manifests, TOML formatting, spelling, and dependency policy. The build
script never modifies tracked source: fd/ripgrep adapters are generated under
Cargo's `OUT_DIR`.

This project intentionally supports the latest stable Rust release only; it
does not declare an MSRV. Supported deployment targets are listed in
[CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Do not publish suspected vulnerabilities in a public issue. Follow
[SECURITY.md](SECURITY.md) to report them privately.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
