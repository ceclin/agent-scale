# Local patches

This directory vendors `iroh` 1.0.3 until an upstream release includes the
path-selection fix.

`RemoteStateActor` shares the selected network path across all connections to
an endpoint. A direct path can be abandoned by a large blob transfer while a
control connection keeps the same path healthy, causing the selector to pick
the failed direct path again. The patch temporarily excludes an abandoned
selected path from all candidates until the affected connection establishes a
replacement path. Relay remains a fallback; healthy direct paths are still
preferred.
