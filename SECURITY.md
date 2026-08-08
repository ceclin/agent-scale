# Security policy

## Reporting a vulnerability

Please use GitHub's **Report a vulnerability** form in the Security tab of
`ceclin/agent-scale`. Do not include exploit details, private endpoint IDs,
keys, tokens, or machine information in a public issue.

Include the affected revision, platform, expected impact, reproduction steps,
and any suggested mitigation. Maintainers will acknowledge a complete report
as soon as practical and coordinate disclosure after a fix is available.

## Supported versions

agent-scale is currently pre-release. Security fixes are made on the latest
development line; older snapshots are not supported. Users should update all
center, edge, relay, and control binaries together because protocol revisions
may be intentionally incompatible.

## Security boundaries

The project authenticates peers with pinned Ed25519 endpoint identities and
signed control/relay state. It does not sandbox commands executed by `as-edge`.
Run edge processes under an OS account, container, or VM whose privileges match
the trust granted to the pinned center.
