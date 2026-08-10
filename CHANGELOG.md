# Changelog

All notable changes to this project will be documented here.

The project uses semantic versioning after its first public release. Before
1.0, configuration and wire formats may change incompatibly.

## Unreleased

## 0.8.0 - 2026-08-10

- Initial public release of the Client, Edge, Control, and Relay components for
  authenticated remote command execution, file transfer, and MCP access.
- Connected Clients and Edges over direct iroh peer-to-peer paths with Relay
  discovery and fallback, without requiring inbound ports on test machines.
- Added fixed TCP forwarding and SOCKS5 proxying for reaching TCP and UDP
  services through an Edge.
- Added durable Control-managed enrollment, private Relay authorization and TLS,
  self-service Edge lifecycle, and immediate revocation.
- Added Compose bootstrap and a signed Provisioner API for automated
  deployments.
- Published multi-platform binary archives, multi-architecture Control and Relay
  images, SHA-256 checksums, and complete dependency license bundles.
