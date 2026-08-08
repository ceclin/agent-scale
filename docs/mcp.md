# Remote MCP servers

MCP definitions belong to an edge identity and are stored in
`$AGENT_SCALE_HOME/<who>/mcp.json`. The control plane and center cache do not
store them, so transferring an edge to another center preserves its MCP setup.

## Manage servers

Manage a running edge from the development machine:

```sh
agent-scale -e win-box mcp add x64dbg --http http://127.0.0.1:8888/mcp
agent-scale -e linux-box mcp add lldb --cwd /work/project -- lldb-mcp
agent-scale -e win-box mcp ls
agent-scale -e win-box mcp rm x64dbg
```

For offline setup, make the same changes locally on the test machine:

```sh
as-edge mcp --who test add lldb -- lldb-mcp
as-edge mcp --who test ls
```

`mcp run` is a transparent stdio proxy. It does not parse or aggregate MCP
messages. Startup failures and the real server's stderr are written to the
proxy's stderr without contaminating its JSON-RPC stdout.

```sh
agent-scale -e linux-box mcp run lldb
agent-scale -e linux-box mcp check lldb
```

`check` performs a real MCP initialize handshake and has a ten-second startup
timeout.

## Project sync

Sync is explicit and project-scoped. Select every edge and client that should
appear in the project:

```sh
agent-scale -e win-box -e linux-box mcp sync --client claude --client codex
agent-scale -e win-box mcp sync --client codex --check
```

Claude Code entries are merged into `.mcp.json`; Codex entries are merged into
`.codex/config.toml`. Codex only loads project configuration after the project
is trusted. Generated names use `<edge>__<server>`.

The committed `.agent-scale/mcp-sync.json` manifest records which entries were
generated. Sync never overwrites handwritten entries or entries changed since
the previous sync. It fetches every selected edge, optionally health-checks all
servers, and validates every client config before writing anything.

The project root is the nearest ancestor containing `.jj` or `.git`, falling
back to the current directory. Use `--project <path>` to select it explicitly.

Environment variables and secrets in edge MCP definitions are intentionally not
supported in the first version.
