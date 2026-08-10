# Changelog

All notable changes to this project will be documented here.

The project uses semantic versioning after its first public release. Before
1.0, configuration and wire formats may change incompatibly.

## Unreleased

## 0.6.0 - 2026-08-09

- Standardized the development-side role as Client across CLI commands, signed
  APIs, persisted state, filesystem paths, and documentation; advanced the
  incompatible Control and RPC protocol versions.
- Added configurable Relay QAD UDP ports and Control-managed private TLS:
  Relays generate their own keys and CSRs, while Control signs certificates and
  distributes its dedicated CA through the signed topology.
- Allowed enrolled Clients to remove their own Control-managed Edges through
  signed, identity-bound requests.
- Replaced replicated Relay membership lists with EndpointId-bound admission
  credentials and a compact incremental revocation stream. New nodes can use any
  available Relay immediately, while removals still disconnect live sessions.

## 0.5.0 - 2026-08-07

- Added the `agent-scale` Client, `as-edge`, `as-control`, and `as-relay`
  binaries with authenticated iroh transport, streaming command execution,
  content-addressed file transfer, and transparent MCP proxying.
- Supported Windows x86-64 development hosts for the Client CLI and daemon
  through private local Named Pipe IPC.
- Added simple mode for zero-infrastructure trials and Control-managed mode for
  private Relay and multi-Client deployments.
- Persisted Control state in a versioned SQLite database with WAL, atomic
  topology revisions, restart recovery, and bounded invitation history.
- Made private Relay enrollment Control-only, with signed membership snapshots,
  offline recovery, revocation, and immediate disconnection of removed members.
- Added idempotent native Compose bootstrap through `as-control bootstrap` and
  `as-relay run --join-if-needed`, with explicit Client enrollment and no shell
  initialization services.
- Added signed Provisioner reconciliation scoped by owner, including idempotent
  invitations and explicit Client/Edge lifecycle management.
- Added repeatable snapshot distributions plus tag-driven prereleases and
  releases, with versioned binary archives, multi-architecture Control and
  Relay images, SHA-256 checksums, and complete third-party license bundles.
- Reorganized the workspace around explicit core, protocol, transport, and
  runtime responsibilities.
- Added typed protocol v3 framing and explicit signed protocol versions.
- Hardened durable state, authorization revocation, daemon coordination,
  subprocess cancellation, transfers, and MCP backpressure.
- Added repository-wide formatting, lint, test, dependency, and distribution
  tasks for the latest stable Rust toolchain.
