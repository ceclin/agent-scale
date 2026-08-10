//! Keeps CLI processes disposable while the daemon retains warm network state.

use std::time::Duration;

#[cfg(unix)]
use std::os::unix::process::CommandExt;
#[cfg(windows)]
use std::os::windows::process::CommandExt;

use anyhow::{Context, Result};
use protocol::{ExecParams, McpCatalog, McpTransport, RpcResult, TransferResult};
use rmcp::{ServiceExt, transport::TokioChildProcess};
use scale_transport::{Frame, T_DATA, T_EXIT, T_RESULT, T_START, T_STDERR, T_STDOUT, io_wire};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::common::{self, ClientOp, ClientReq, LOCAL_PROTOCOL_VERSION, LocalCommand, LocalRequest, VERSION};
use crate::common::{DaemonAdmin, DaemonStatus};

fn work_request(edge: String, op: ClientOp) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&LocalRequest {
        version: VERSION.into(),
        protocol_version: LOCAL_PROTOCOL_VERSION,
        command: LocalCommand::Work(ClientReq { edge, op }),
    })?)
}

async fn check_edge(edge: &str) -> Result<()> {
    crate::control::refresh_cache().await?;
    let cfg = common::load_config()?;
    anyhow::ensure!(
        cfg.edges.iter().any(|e| e.name == edge),
        "unknown edge '{edge}'; configured: [{}]",
        cfg.edges.iter().map(|e| e.name.as_str()).collect::<Vec<_>>().join(", ")
    );
    Ok(())
}

/// Run `argv` on `edge`. Returns the remote exit code.
pub async fn exec(edge: String, argv: Vec<String>) -> Result<i32> {
    check_edge(&edge).await?;
    let (command, args) = argv.split_first().context("empty command")?;
    let params = ExecParams {
        command: command.clone(),
        args: args.to_vec(),
        cwd: None,
    };

    let stream = ensure_daemon().await?;
    let (mut r, mut w) = tokio::io::split(stream);

    let payload = work_request(edge, ClientOp::Exec(params))?;
    io_wire::write_frame(&mut w, T_START, &payload).await?;

    let mut stdout = tokio::io::stdout();
    let mut stderr = tokio::io::stderr();
    let mut code = None;
    loop {
        match io_wire::read_frame(&mut r).await? {
            Some(Frame {
                tag: T_STDOUT,
                payload: p,
            }) => {
                stdout.write_all(&p).await?;
                stdout.flush().await?;
            }
            Some(Frame {
                tag: T_STDERR,
                payload: p,
            }) => {
                stderr.write_all(&p).await?;
                stderr.flush().await?;
            }
            Some(Frame { tag: T_EXIT, payload }) => {
                let bytes: [u8; 4] = payload
                    .as_slice()
                    .try_into()
                    .context("malformed EXIT frame: expected four bytes")?;
                code = Some(i32::from_le_bytes(bytes));
                break;
            }
            Some(frame) => anyhow::bail!("unexpected exec frame tag {}", frame.tag),
            None => break,
        }
    }
    code.context("edge closed the request without an exit status (authorization may have changed)")
}

/// Upload or download a file. The daemon does the file IO + iroh-blobs transfer
/// and reports the result. Returns 0 on success.
pub async fn transfer(edge: String, op: ClientOp) -> Result<i32> {
    check_edge(&edge).await?;
    let stream = ensure_daemon().await?;
    let (mut r, mut w) = tokio::io::split(stream);
    io_wire::write_frame(&mut w, T_START, &work_request(edge, op)?).await?;
    match io_wire::read_frame(&mut r).await? {
        Some(Frame {
            tag: T_RESULT,
            payload: p,
        }) => match serde_json::from_slice::<RpcResult<TransferResult>>(&p)? {
            RpcResult::Ok(TransferResult::Stored { bytes }) => {
                println!("ok ({bytes} bytes)");
                Ok(0)
            }
            RpcResult::Ok(TransferResult::DownloadReady { .. }) => {
                anyhow::bail!("daemon returned an intermediate download result")
            }
            RpcResult::Error(error) => anyhow::bail!("{}: {}", error.code, error.message),
        },
        Some(frame) => anyhow::bail!("unexpected daemon frame tag {}", frame.tag),
        None => anyhow::bail!("daemon closed without a result"),
    }
}

/// Run the MCP proxy: a transparent stdio<->daemon<->edge pipe for the edge's
/// named MCP server. Spawned by Claude Code as a stdio MCP server.
pub async fn mcp_run(edge: String, name: String) -> Result<()> {
    check_edge(&edge).await?;

    let stream = ensure_daemon().await?;
    let (mut r, mut w) = tokio::io::split(stream);
    io_wire::write_frame(&mut w, T_START, &work_request(edge, ClientOp::McpConnect { name })?).await?;

    match io_wire::read_frame(&mut r).await? {
        Some(Frame { tag: T_RESULT, payload }) => ensure_ok(&payload)?,
        Some(frame) => anyhow::bail!("unexpected daemon frame tag {} during MCP startup", frame.tag),
        None => anyhow::bail!("daemon closed during MCP startup"),
    }

    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut stdin_open = true;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        tokio::select! {
            n = stdin.read(&mut buf), if stdin_open => match n {
                // EOF is only half of an MCP session; the server may still have
                // final responses to deliver.
                Ok(0) | Err(_) => { let _ = w.shutdown().await; stdin_open = false; }
                Ok(n) => io_wire::write_frame(&mut w, T_DATA, &buf[..n]).await?,
            },
            f = io_wire::read_frame(&mut r) => match f? {
                Some(Frame { tag: T_DATA, payload: p }) => {
                    stdout.write_all(&p).await?;
                    stdout.flush().await?;
                }
                Some(Frame { tag: T_STDERR, payload: p }) => {
                    tokio::io::stderr().write_all(&p).await?;
                    tokio::io::stderr().flush().await?;
                }
                _ => break,
            },
        }
    }
    Ok(())
}

pub async fn mcp_list(edge: String) -> Result<McpCatalog> {
    let payload = mcp_control(edge, ClientOp::McpList).await?;
    match serde_json::from_slice::<RpcResult<McpCatalog>>(&payload)? {
        RpcResult::Ok(catalog) => Ok(catalog),
        RpcResult::Error(error) => anyhow::bail!("{}: {}", error.code, error.message),
    }
}

pub async fn mcp_upsert(edge: String, name: String, transport: McpTransport) -> Result<()> {
    let payload = mcp_control(edge, ClientOp::McpUpsert { name, transport }).await?;
    ensure_ok(&payload)
}

pub async fn mcp_remove(edge: String, name: String) -> Result<()> {
    let payload = mcp_control(edge, ClientOp::McpRemove { name }).await?;
    ensure_ok(&payload)
}

pub async fn mcp_check(edge: String, name: String) -> Result<()> {
    check_edge(&edge).await?;
    let executable = std::env::current_exe().context("resolve agent-scale executable")?;
    let mut command = tokio::process::Command::new(executable);
    command.args(["-e", &edge, "mcp", "run", &name]);
    let transport = TokioChildProcess::new(command).context("start MCP proxy")?;
    let service = tokio::time::timeout(Duration::from_secs(10), ().serve(transport))
        .await
        .context("MCP initialize timed out after 10 seconds")?
        .context("MCP initialize failed")?;
    service.cancel().await.context("close MCP health-check session")?;
    Ok(())
}

async fn mcp_control(edge: String, op: ClientOp) -> Result<Vec<u8>> {
    check_edge(&edge).await?;
    let stream = ensure_daemon().await?;
    let (mut r, mut w) = tokio::io::split(stream);
    io_wire::write_frame(&mut w, T_START, &work_request(edge, op)?).await?;
    match io_wire::read_frame(&mut r).await? {
        Some(Frame { tag: T_RESULT, payload }) => Ok(payload),
        Some(frame) => anyhow::bail!("unexpected daemon frame tag {}", frame.tag),
        None => anyhow::bail!("daemon closed without an MCP result"),
    }
}

fn ensure_ok(payload: &[u8]) -> Result<()> {
    match serde_json::from_slice::<RpcResult<()>>(payload)? {
        RpcResult::Ok(()) => Ok(()),
        RpcResult::Error(error) => anyhow::bail!("{}: {}", error.code, error.message),
    }
}

/// Connect to a live, version-matched daemon, spawning one if needed.
async fn ensure_daemon() -> Result<crate::local_ipc::Stream> {
    if let Some(status) = daemon_admin(DaemonAdmin::Status).await? {
        if status.version == VERSION && status.protocol_version == LOCAL_PROTOCOL_VERSION {
            return crate::local_ipc::connect()
                .await
                .context("reconnect to daemon after status check");
        }
        let _ = daemon_admin(DaemonAdmin::Shutdown).await?;
        for _ in 0..100 {
            if crate::local_ipc::connect().await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    spawn_daemon()?;
    for _ in 0..200 {
        if let Some(status) = daemon_admin(DaemonAdmin::Status).await?
            && status.version == VERSION
            && status.protocol_version == LOCAL_PROTOCOL_VERSION
        {
            return crate::local_ipc::connect()
                .await
                .context("connect to newly started daemon");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    anyhow::bail!("daemon did not come up within timeout");
}

pub async fn daemon_admin(command: DaemonAdmin) -> Result<Option<DaemonStatus>> {
    let mut stream = match crate::local_ipc::connect().await {
        Ok(stream) => stream,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error).context("connect to daemon control socket"),
    };
    let request = LocalRequest {
        version: VERSION.into(),
        protocol_version: LOCAL_PROTOCOL_VERSION,
        command: LocalCommand::Admin(command),
    };
    io_wire::write_frame(&mut stream, T_START, &serde_json::to_vec(&request)?).await?;
    match io_wire::read_frame(&mut stream).await? {
        Some(Frame { tag: T_RESULT, payload }) => match serde_json::from_slice::<RpcResult<DaemonStatus>>(&payload)? {
            RpcResult::Ok(status) => Ok(Some(status)),
            RpcResult::Error(error) => anyhow::bail!("{}: {}", error.code, error.message),
        },
        Some(frame) => anyhow::bail!("unexpected daemon admin frame {}", frame.tag),
        None => anyhow::bail!("daemon closed without an admin response"),
    }
}

fn spawn_daemon() -> Result<()> {
    std::fs::create_dir_all(common::daemon_dir())?;
    let exe = std::env::current_exe()?;
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(common::log_path())?;
    let log2 = log.try_clone()?;
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("__daemon")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(log))
        .stderr(std::process::Stdio::from(log2));
    // Detach from the controlling terminal so the daemon outlives this client
    // and is not hit by terminal control events.
    #[cfg(unix)]
    cmd.process_group(0);
    #[cfg(windows)]
    {
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
    }
    cmd.spawn().context("spawn daemon")?;
    Ok(())
}
