# Changelog

All notable changes to this project will be documented here.

The project uses semantic versioning after its first public release. Before
1.0, configuration and wire formats may change incompatibly.

## Unreleased

- Reorganized the workspace around explicit core, protocol, transport, and
  runtime responsibilities.
- Added typed protocol v3 framing and explicit signed protocol versions.
- Hardened durable state, authorization revocation, daemon coordination,
  subprocess cancellation, transfers, and MCP backpressure.
- Added repository-wide formatting, lint, test, dependency, and distribution
  tasks for the latest stable Rust toolchain.
