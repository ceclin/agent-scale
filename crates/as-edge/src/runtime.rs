//! Child-process lifecycle for remote exec and stdio MCP sessions.

use std::process::Stdio;

use anyhow::{Context, Result};
use iroh::endpoint::{RecvStream, SendStream};
use protocol::{ExecParams, RemoteError, RpcResult};
use scale_transport::{Frame, T_DATA, T_EXIT, T_RESULT, T_STDERR, T_STDOUT, iroh_wire};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::exec::build_command;

const CHUNK: usize = 16 * 1024;

pub(crate) async fn mcp_stdio(
    mut send: SendStream,
    mut recv: RecvStream,
    command: String,
    args: Vec<String>,
    cwd: Option<String>,
) -> Result<()> {
    let mut cmd = tokio::process::Command::new(&command);
    cmd.args(&args);
    if let Some(cwd) = cwd {
        cmd.current_dir(cwd);
    }
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    cmd.kill_on_drop(true);
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(error) => {
            return write_error(&mut send, anyhow::anyhow!("spawn MCP `{command}`: {error}")).await;
        }
    };
    let mut child_stdin = Some(child.stdin.take().context("no mcp stdin")?);
    let mut child_stdout = child.stdout.take().context("no mcp stdout")?;
    let mut child_stderr = child.stderr.take().context("no mcp stderr")?;
    iroh_wire::write_frame(&mut send, T_RESULT, &serde_json::to_vec(&RpcResult::Ok(()))?).await?;

    let mut center_open = true;
    let mut stdout_buf = vec![0u8; 64 * 1024];
    let mut stderr_buf = vec![0u8; CHUNK];
    let mut stderr_open = true;
    loop {
        tokio::select! {
            frame = iroh_wire::read_frame(&mut recv), if center_open => match frame? {
                Some(Frame { tag: T_DATA, payload }) => {
                    if let Some(stdin) = child_stdin.as_mut() {
                        stdin.write_all(&payload).await?;
                        stdin.flush().await?;
                    }
                }
                _ => {
                    child_stdin = None;
                    center_open = false;
                }
            },
            read = child_stdout.read(&mut stdout_buf) => match read {
                Ok(0) | Err(_) => break,
                Ok(count) => {
                    if iroh_wire::write_frame(&mut send, T_DATA, &stdout_buf[..count]).await.is_err() {
                        break;
                    }
                }
            },
            read = child_stderr.read(&mut stderr_buf), if stderr_open => match read {
                Ok(0) | Err(_) => stderr_open = false,
                Ok(count) => {
                    if iroh_wire::write_frame(&mut send, T_STDERR, &stderr_buf[..count]).await.is_err() {
                        break;
                    }
                }
            },
        }
    }
    terminate_child(&mut child).await;
    let _ = send.finish();
    Ok(())
}

pub(crate) async fn run_exec(mut send: SendStream, mut recv: RecvStream, params: ExecParams) -> Result<()> {
    let mut cmd = build_command(&params);
    cmd.args(&params.args);
    if let Some(ref cwd) = params.cwd {
        cmd.current_dir(cwd);
    }
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    cmd.kill_on_drop(true);

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(error) => {
            let _ = iroh_wire::write_frame(
                &mut send,
                T_STDERR,
                format!("failed to spawn `{}`: {error}", params.command).as_bytes(),
            )
            .await;
            let _ = iroh_wire::write_frame(&mut send, T_EXIT, &(-1i32).to_le_bytes()).await;
            let _ = send.finish();
            return Ok(());
        }
    };
    let mut stdout = child.stdout.take().context("no stdout pipe")?;
    let mut stderr = child.stderr.take().context("no stderr pipe")?;
    let mut stdout_buf = vec![0u8; CHUNK];
    let mut stderr_buf = vec![0u8; CHUNK];
    let mut stdout_done = false;
    let mut stderr_done = false;

    let stream_result: Result<bool> = loop {
        tokio::select! {
            read = stdout.read(&mut stdout_buf), if !stdout_done => match read {
                Ok(0) => stdout_done = true,
                Ok(count) => {
                    if iroh_wire::write_frame(&mut send, T_STDOUT, &stdout_buf[..count]).await.is_err() {
                        break Ok(true);
                    }
                },
                Err(error) => break Err(error).context("read child stdout"),
            },
            read = stderr.read(&mut stderr_buf), if !stderr_done => match read {
                Ok(0) => stderr_done = true,
                Ok(count) => {
                    if iroh_wire::write_frame(&mut send, T_STDERR, &stderr_buf[..count]).await.is_err() {
                        break Ok(true);
                    }
                },
                Err(error) => break Err(error).context("read child stderr"),
            },
            _ = recv.read_chunk(1), if !(stdout_done && stderr_done) => break Ok(true),
            else => break Ok(false),
        }
    };

    match stream_result {
        Ok(true) => {
            terminate_child(&mut child).await;
            return Ok(());
        }
        Err(error) => {
            terminate_child(&mut child).await;
            return Err(error);
        }
        Ok(false) => {}
    }

    let status = child.wait().await.context("wait child")?;
    let code = status.code().unwrap_or(-1);
    iroh_wire::write_frame(&mut send, T_EXIT, &code.to_le_bytes()).await?;
    send.finish().map_err(|error| anyhow::anyhow!("finish: {error}"))?;
    let _ = send.stopped().await;
    Ok(())
}

async fn write_error(send: &mut SendStream, error: anyhow::Error) -> Result<()> {
    let response: RpcResult<()> = RpcResult::Error(RemoteError::internal(format!("{error:#}")));
    iroh_wire::write_frame(send, T_RESULT, &serde_json::to_vec(&response)?).await?;
    let _ = send.finish();
    Ok(())
}

async fn terminate_child(child: &mut tokio::process::Child) {
    let _ = child.start_kill();
    let _ = child.wait().await;
}
