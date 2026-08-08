//! Normalizes edge-local HTTP transports here so the Center remains a blind
//! byte pipe and MCP clients need only one stdio-facing integration.

use anyhow::{Context, Result};
use eventsource_stream::Eventsource;
use futures_util::StreamExt;
use iroh::endpoint::{RecvStream, SendStream};
use protocol::RpcResult;
use scale_transport::{Frame, FrameTag, T_DATA, T_RESULT, T_STDERR, iroh_wire};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tracing::warn;

const OUTPUT_QUEUE_ITEMS: usize = 64;
const OUTPUT_BUDGET_BYTES: usize = 32 * 1024 * 1024;
const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

pub enum Kind {
    /// MCP Streamable HTTP (single endpoint, POST + optional SSE response).
    Streamable,
    /// Legacy MCP HTTP+SSE (GET sse stream advertises a POST endpoint).
    LegacySse,
}

pub async fn bridge(mut send: SendStream, recv: RecvStream, url: String, kind: Kind) -> Result<()> {
    reqwest::Url::parse(&url).context("parse mcp url")?;
    // No idle connection reuse: a long-lived SSE GET and request POSTs must not
    // contend for a pooled socket, and reusing a server-closed (HTTP/1.0)
    // connection would hang. MCP's request rate makes fresh conns a non-issue.
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(0)
        .build()
        .context("build http client")?;
    iroh_wire::write_frame(&mut send, T_RESULT, &serde_json::to_vec(&RpcResult::Ok(()))?).await?;
    let (raw_tx, mut rx) = mpsc::channel::<Output>(OUTPUT_QUEUE_ITEMS);
    let tx = OutputSender {
        tx: raw_tx,
        budget: std::sync::Arc::new(Semaphore::new(OUTPUT_BUDGET_BYTES)),
    };
    let writer = tokio::spawn(async move {
        let mut send = send;
        while let Some(output) = rx.recv().await {
            if iroh_wire::write_frame(&mut send, output.tag, &output.data)
                .await
                .is_err()
            {
                break;
            }
        }
        let _ = send.finish();
    });

    let res = match kind {
        Kind::Streamable => streamable(&client, &url, recv, tx.clone()).await,
        Kind::LegacySse => legacy_sse(&client, &url, recv, tx.clone()).await,
    };
    if let Err(error) = &res {
        let _ = tx.push_error(format!("MCP HTTP bridge: {error:#}")).await;
    }
    let _ = writer.await;
    res
}

/// Read the next newline-delimited JSON-RPC message from the iroh stream.
/// Returns `None` at end-of-stream (the center closed the session).
async fn read_message(recv: &mut RecvStream, buf: &mut Vec<u8>) -> Result<Option<Vec<u8>>> {
    loop {
        if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
            let mut line: Vec<u8> = buf.drain(..=pos).collect();
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            if line.is_empty() {
                continue;
            }
            return Ok(Some(line));
        }
        match iroh_wire::read_frame(recv).await? {
            Some(Frame {
                tag: T_DATA,
                payload: chunk,
            }) => {
                anyhow::ensure!(
                    buf.len().saturating_add(chunk.len()) <= MAX_MESSAGE_BYTES,
                    "MCP message exceeds {MAX_MESSAGE_BYTES} bytes"
                );
                buf.extend_from_slice(&chunk);
            }
            _ => {
                if buf.is_empty() {
                    return Ok(None);
                }
                return Ok(Some(std::mem::take(buf)));
            }
        }
    }
}

struct Output {
    tag: FrameTag,
    data: Vec<u8>,
    _budget: OwnedSemaphorePermit,
}

#[derive(Clone)]
struct OutputSender {
    tx: mpsc::Sender<Output>,
    budget: std::sync::Arc<Semaphore>,
}

impl OutputSender {
    async fn send(&self, tag: FrameTag, data: Vec<u8>) -> Result<()> {
        anyhow::ensure!(
            data.len() <= MAX_MESSAGE_BYTES,
            "MCP message exceeds {MAX_MESSAGE_BYTES} bytes"
        );
        let permits = u32::try_from(data.len()).context("MCP message size overflow")?;
        let budget = self
            .budget
            .clone()
            .acquire_many_owned(permits)
            .await
            .context("MCP output queue closed")?;
        self.tx
            .send(Output {
                tag,
                data,
                _budget: budget,
            })
            .await
            .map_err(|_| anyhow::anyhow!("MCP output writer closed"))
    }

    async fn push_line(&self, data: String) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let mut line = data.into_bytes();
        line.push(b'\n');
        self.send(T_DATA, line).await
    }

    async fn push_error(&self, error: impl std::fmt::Display) -> Result<()> {
        self.send(T_STDERR, format!("{error}\n").into_bytes()).await
    }
}

async fn read_bounded_body(response: reqwest::Response) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    let mut chunks = response.bytes_stream();
    while let Some(chunk) = chunks.next().await {
        let chunk = chunk.context("read MCP response body")?;
        anyhow::ensure!(
            body.len().saturating_add(chunk.len()) <= MAX_MESSAGE_BYTES,
            "MCP response exceeds {MAX_MESSAGE_BYTES} bytes"
        );
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

async fn streamable(client: &reqwest::Client, url: &str, mut recv: RecvStream, tx: OutputSender) -> Result<()> {
    let endpoint = reqwest::Url::parse(url).context("parse mcp url")?;
    let mut session: Option<String> = None;
    // Delay GET-SSE until a POST can establish the session id required by some
    // servers; opening it earlier silently loses server-initiated messages.
    let mut sse_task: Option<tokio::task::JoinHandle<()>> = None;
    let mut buf = Vec::new();

    while let Some(msg) = read_message(&mut recv, &mut buf).await? {
        let mut req = client
            .post(endpoint.clone())
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .body(msg);
        if let Some(sid) = &session {
            req = req.header("mcp-session-id", sid);
        }
        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                let _ = tx.push_error(format!("MCP POST failed: {e}")).await;
                warn!("mcp POST failed: {e}");
                break;
            }
        };
        if let Some(sid) = resp.headers().get("mcp-session-id").and_then(|v| v.to_str().ok()) {
            session = Some(sid.to_string());
        }
        if sse_task.is_none() {
            sse_task = Some(spawn_get_sse(
                client.clone(),
                endpoint.clone(),
                session.clone(),
                tx.clone(),
            ));
        }
        let is_sse = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|ct| ct.contains("text/event-stream"))
            .unwrap_or(false);

        if is_sse {
            let mut events = resp.bytes_stream().eventsource();
            while let Some(ev) = events.next().await {
                match ev {
                    Ok(ev) => tx.push_line(ev.data).await?,
                    Err(e) => {
                        let _ = tx.push_error(format!("MCP SSE error: {e}")).await;
                        warn!("mcp sse error: {e}");
                        break;
                    }
                }
            }
        } else {
            match read_bounded_body(resp).await {
                Ok(body) if !body.is_empty() => tx.push_line(String::from_utf8_lossy(&body).into_owned()).await?,
                Ok(_) => {}
                Err(e) => {
                    let _ = tx.push_error(format!("MCP response body error: {e}")).await;
                    warn!("mcp body error: {e}");
                }
            }
        }
    }
    if let Some(h) = sse_task {
        h.abort();
    }
    Ok(())
}

/// Call only after the first POST establishes any MCP session id. Servers that
/// reject the optional GET channel are intentionally tolerated.
fn spawn_get_sse(
    client: reqwest::Client,
    endpoint: reqwest::Url,
    session: Option<String>,
    tx: OutputSender,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut req = client.get(endpoint).header("accept", "text/event-stream");
        if let Some(sid) = session {
            req = req.header("mcp-session-id", sid);
        }
        match req.send().await {
            Ok(resp) if resp.status().is_success() => {
                let mut events = resp.bytes_stream().eventsource();
                while let Some(ev) = events.next().await {
                    match ev {
                        Ok(ev) => {
                            if tx.push_line(ev.data).await.is_err() {
                                break;
                            }
                        }
                        Err(error) => {
                            let _ = tx.push_error(format!("MCP GET-SSE error: {error}")).await;
                            break;
                        }
                    }
                }
            }
            Ok(_) => {}
            Err(error) => {
                let _ = tx.push_error(format!("MCP GET-SSE failed: {error}")).await;
            }
        }
    })
}

async fn legacy_sse(client: &reqwest::Client, url: &str, mut recv: RecvStream, tx: OutputSender) -> Result<()> {
    let base = reqwest::Url::parse(url).context("parse mcp url")?;
    let resp = client
        .get(base.clone())
        .header("accept", "text/event-stream")
        .send()
        .await
        .context("open sse stream")?;

    let (ep_tx, ep_rx) = tokio::sync::oneshot::channel::<reqwest::Url>();
    let reader_tx = tx.clone();
    let reader = tokio::spawn(async move {
        let mut events = resp.bytes_stream().eventsource();
        let mut ep_tx = Some(ep_tx);
        while let Some(ev) = events.next().await {
            let ev = match ev {
                Ok(e) => e,
                Err(_) => break,
            };
            if ev.event == "endpoint" {
                if let (Some(slot), Ok(u)) = (ep_tx.take(), base.join(&ev.data)) {
                    let _ = slot.send(u);
                }
            } else {
                if reader_tx.push_line(ev.data).await.is_err() {
                    break;
                }
            }
        }
    });

    let post_url = ep_rx.await.context("server sent no endpoint event")?;
    let mut buf = Vec::new();
    while let Some(msg) = read_message(&mut recv, &mut buf).await? {
        if let Err(e) = client
            .post(post_url.clone())
            .header("content-type", "application/json")
            .body(msg)
            .send()
            .await
        {
            let _ = tx.push_error(format!("MCP POST failed: {e}")).await;
            warn!("mcp POST failed: {e}");
            break;
        }
    }
    reader.abort();
    Ok(())
}
