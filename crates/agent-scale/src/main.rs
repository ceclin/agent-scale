//! The CLI remains a thin frontend so command lifetimes do not own network
//! connections or remote execution state.

mod client;
mod common;
mod control;
mod daemon;
mod edge;
mod local_ipc;
mod mcp_sync;

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "agent-scale", about = "Run commands on remote test machines over iroh")]
struct Cli {
    /// Select an edge for exec, transfer, or MCP operations. Repeat for MCP sync.
    #[arg(short = 'e', long = "edge")]
    edges: Vec<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Join or inspect the multi-client control plane.
    Control {
        #[command(subcommand)]
        cmd: ControlCmd,
    },
    /// Run a command on a test machine (edge), streaming output live.
    ///
    /// Example: `agent-scale -e win-box exec -- cargo test`
    Exec {
        /// Command and arguments (use `--` to separate from agent-scale flags).
        #[arg(trailing_var_arg = true, required = true)]
        argv: Vec<String>,
    },
    /// Upload a local file to a test machine (edge).
    Upload { local: String, remote: String },
    /// Download a file from a test machine (edge).
    Download { remote: String, local: String },
    /// MCP-proxy: run a remote MCP server, or manage the registry.
    Mcp {
        #[command(subcommand)]
        cmd: McpCmd,
    },
    /// Manage configured edges (test machines).
    Edge {
        #[command(subcommand)]
        cmd: EdgeCmd,
    },
    /// Ensure the client identity exists and print its EndpointId.
    Keygen,
    /// Daemon control: --status (default) or --stop.
    Daemon {
        #[arg(long)]
        status: bool,
        #[arg(long)]
        stop: bool,
    },
    /// Internal: run the daemon (auto-spawned by the client).
    #[command(name = "__daemon", hide = true)]
    Daemonize,
}

#[derive(Subcommand)]
enum McpCmd {
    /// Run the selected edge's named MCP proxy as a stdio MCP server.
    /// Put this in a project MCP config with `-e EDGE mcp run NAME`.
    Run { name: String },
    /// Register (or update) an MCP server on an edge. Give one of:
    /// `-- <command>` (stdio), `--http <url>` (Streamable HTTP), `--sse <url>`.
    Add {
        name: String,
        /// Streamable HTTP MCP endpoint URL.
        #[arg(long, conflicts_with_all = ["sse", "argv"])]
        http: Option<String>,
        /// Legacy HTTP+SSE MCP endpoint URL.
        #[arg(long, conflicts_with = "argv")]
        sse: Option<String>,
        /// Working directory for a stdio MCP server on the edge.
        #[arg(long)]
        cwd: Option<String>,
        /// stdio MCP command and args (after `--`).
        #[arg(trailing_var_arg = true)]
        argv: Vec<String>,
    },
    /// List MCP servers configured on an edge.
    Ls,
    /// Remove an MCP server from an edge.
    Rm { name: String },
    /// Connect and complete an MCP initialize handshake.
    Check { name: String },
    /// Synchronize selected edge MCP servers into project client configuration.
    Sync {
        /// Client configuration to update. Repeat to update both.
        #[arg(long, value_enum, required = true)]
        client: Vec<mcp_sync::ClientKind>,
        /// Project root. Defaults to the nearest .jj/.git ancestor.
        #[arg(long)]
        project: Option<std::path::PathBuf>,
        /// Complete an MCP initialize handshake for every server before writing.
        #[arg(long)]
        check: bool,
    },
}

#[derive(Subcommand)]
enum EdgeCmd {
    /// Create a one-time invitation for an edge owned by this Client.
    Invite {
        name: String,
        #[arg(long, default_value_t = 900)]
        ttl_secs: u64,
    },
    /// Add (or update) an edge in simple standalone mode.
    Add {
        name: String,
        endpoint_id: String,
        /// Custom relay URL(s). Omit to use the official relays bundled with
        /// iroh.
        #[arg(short = 'r', long = "relay")]
        relays: Vec<String>,
    },
    /// List configured edges.
    Ls,
    /// Remove an edge by name.
    Rm { name: String },
}

#[derive(Subcommand)]
enum ControlCmd {
    /// Enroll this client from a one-time control invitation.
    Join { join_url: String },
    /// Show this client's Control identity and cached map revision.
    Status,
    /// Fetch and apply the latest control map now.
    Sync,
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        if !cli.edges.is_empty()
            && !matches!(
                &cli.cmd,
                Cmd::Exec { .. } | Cmd::Upload { .. } | Cmd::Download { .. } | Cmd::Mcp { .. }
            )
        {
            eprintln!("agent-scale: -e/--edge is only valid for exec, upload, download, and mcp");
            return ExitCode::FAILURE;
        }
        let edges = cli.edges;
        match cli.cmd {
            Cmd::Control { cmd } => {
                let result = match cmd {
                    ControlCmd::Join { join_url } => control::join(join_url).await,
                    ControlCmd::Status => control::status().await,
                    ControlCmd::Sync => control::sync().await,
                };
                report(result, |()| ExitCode::SUCCESS)
            }
            Cmd::Edge { cmd } => {
                let r = match cmd {
                    EdgeCmd::Invite { name, ttl_secs } => control::edge_invite(name, ttl_secs).await,
                    EdgeCmd::Add {
                        name,
                        endpoint_id,
                        relays,
                    } => edge::add(name, endpoint_id, relays).await,
                    EdgeCmd::Ls => control::refresh_cache().await.and_then(|()| edge::ls()),
                    EdgeCmd::Rm { name } => edge::rm(name).await,
                };
                report(r, |()| ExitCode::SUCCESS)
            }
            Cmd::Keygen => report(common::load_or_create_key(), |key| {
                println!("{}", key.public());
                ExitCode::SUCCESS
            }),
            Cmd::Exec { argv } => match one_edge(&edges) {
                Ok(edge) => report(client::exec(edge, argv).await, code_exit),
                Err(error) => report::<()>(Err(error), |()| ExitCode::SUCCESS),
            },
            Cmd::Upload { local, remote } => match one_edge(&edges) {
                Ok(edge) => report(
                    client::transfer(edge, common::ClientOp::Upload { local, remote }).await,
                    code_exit,
                ),
                Err(error) => report::<()>(Err(error), |()| ExitCode::SUCCESS),
            },
            Cmd::Download { remote, local } => match one_edge(&edges) {
                Ok(edge) => report(
                    client::transfer(edge, common::ClientOp::Download { remote, local }).await,
                    code_exit,
                ),
                Err(error) => report::<()>(Err(error), |()| ExitCode::SUCCESS),
            },
            Cmd::Mcp { cmd } => match cmd {
                McpCmd::Run { name } => match one_edge(&edges) {
                    Ok(edge) => report(client::mcp_run(edge, name).await, |()| ExitCode::SUCCESS),
                    Err(error) => report::<()>(Err(error), |()| ExitCode::SUCCESS),
                },
                McpCmd::Add {
                    name,
                    http,
                    sse,
                    cwd,
                    argv,
                } => {
                    if cwd.is_some() && (http.is_some() || sse.is_some()) {
                        eprintln!("agent-scale: --cwd is only valid for stdio MCP servers");
                        return ExitCode::FAILURE;
                    }
                    let transport = http
                        .map(|url| protocol::McpTransport::Http { url })
                        .or_else(|| sse.map(|url| protocol::McpTransport::Sse { url }))
                        .or_else(|| {
                            argv.split_first().map(|(c, a)| protocol::McpTransport::Stdio {
                                command: c.clone(),
                                args: a.to_vec(),
                                cwd,
                            })
                        });
                    match (one_edge(&edges), transport) {
                        (Ok(edge), Some(transport)) => {
                            let result = client::mcp_upsert(edge.clone(), name.clone(), transport).await;
                            report(result, |()| {
                                println!("configured MCP '{name}' on edge '{edge}'");
                                ExitCode::SUCCESS
                            })
                        }
                        (Err(error), _) => report::<()>(Err(error), |()| ExitCode::SUCCESS),
                        (_, None) => {
                            eprintln!("agent-scale: specify `-- <command>`, `--http <url>`, or `--sse <url>`");
                            ExitCode::FAILURE
                        }
                    }
                }
                McpCmd::Ls => match one_edge(&edges) {
                    Ok(edge) => report(client::mcp_list(edge).await, print_mcp_catalog),
                    Err(error) => report::<()>(Err(error), |()| ExitCode::SUCCESS),
                },
                McpCmd::Rm { name } => match one_edge(&edges) {
                    Ok(edge) => {
                        let result = client::mcp_remove(edge.clone(), name.clone()).await;
                        report(result, |()| {
                            println!("removed MCP '{name}' from edge '{edge}'");
                            ExitCode::SUCCESS
                        })
                    }
                    Err(error) => report::<()>(Err(error), |()| ExitCode::SUCCESS),
                },
                McpCmd::Check { name } => match one_edge(&edges) {
                    Ok(edge) => report(client::mcp_check(edge.clone(), name.clone()).await, |()| {
                        println!("ok: {edge}/{name}");
                        ExitCode::SUCCESS
                    }),
                    Err(error) => report::<()>(Err(error), |()| ExitCode::SUCCESS),
                },
                McpCmd::Sync { client, project, check } => {
                    report(mcp_sync::sync(edges, client, project, check).await, |()| {
                        ExitCode::SUCCESS
                    })
                }
            },
            Cmd::Daemon { status, stop } => report(daemon::control(status, stop).await, |()| ExitCode::SUCCESS),
            Cmd::Daemonize => match daemon::run().await {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("daemon: {e:#}");
                    ExitCode::FAILURE
                }
            },
        }
    })
}

fn one_edge(edges: &[String]) -> anyhow::Result<String> {
    anyhow::ensure!(
        edges.len() == 1,
        "this command requires exactly one -e/--edge (got {})",
        edges.len()
    );
    Ok(edges[0].clone())
}

fn print_mcp_catalog(catalog: protocol::McpCatalog) -> ExitCode {
    if catalog.servers.is_empty() {
        println!("no MCP servers configured");
        return ExitCode::SUCCESS;
    }
    for (name, transport) in catalog.servers {
        let description = match transport {
            protocol::McpTransport::Stdio { command, args, cwd } => {
                let mut value = format!("stdio: {command}");
                if !args.is_empty() {
                    value.push(' ');
                    value.push_str(&args.join(" "));
                }
                if let Some(cwd) = cwd {
                    value.push_str(&format!(" (cwd: {cwd})"));
                }
                value
            }
            protocol::McpTransport::Http { url } => format!("http: {url}"),
            protocol::McpTransport::Sse { url } => format!("sse: {url}"),
        };
        println!("{name}: {description}");
    }
    ExitCode::SUCCESS
}

/// Map a command result to a process exit code, printing errors uniformly.
/// `ok` turns the success value into the exit code (e.g. `code_exit` for a
/// propagated remote status, or `|()| ExitCode::SUCCESS` for unit results).
fn report<T>(r: anyhow::Result<T>, ok: impl FnOnce(T) -> ExitCode) -> ExitCode {
    match r {
        Ok(v) => ok(v),
        Err(e) => {
            eprintln!("agent-scale: {e:#}");
            ExitCode::FAILURE
        }
    }
}

/// Propagate a remote exit status as this process's exit code (low byte).
fn code_exit(code: i32) -> ExitCode {
    ExitCode::from((code & 0xff) as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edge_scope_precedes_workload_command() {
        assert!(Cli::try_parse_from(["agent-scale", "-e", "win", "mcp", "rm", "debugger"]).is_ok());
        assert!(Cli::try_parse_from(["agent-scale", "mcp", "rm", "win", "debugger"]).is_err());
    }

    #[test]
    fn sync_accepts_multiple_edges_and_requires_client() {
        assert!(
            Cli::try_parse_from([
                "agent-scale",
                "-e",
                "win",
                "-e",
                "linux",
                "mcp",
                "sync",
                "--client",
                "codex"
            ])
            .is_ok()
        );
        assert!(Cli::try_parse_from(["agent-scale", "-e", "win", "mcp", "sync"]).is_err());
    }
}
