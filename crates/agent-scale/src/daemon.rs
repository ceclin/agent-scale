//! The center daemon: one warm iroh endpoint multiplexing all edges, a private
//! local byte stream for clients, a verbatim frame relay for exec, and iroh-blobs file
//! transfer. Gradle-style: auto-spawned, registry-advertised, long idle,
//! version-guarded.

mod connection_pool;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use iroh::endpoint::Connection;
use iroh::protocol::ProtocolHandler;
use iroh::{Endpoint, EndpointAddr, EndpointId};
use iroh_blobs::BlobsProtocol;
use iroh_blobs::store::fs::FsStore;
use protocol::{EdgeReq, ExecParams, RemoteError, RpcResult, TransferResult};
use scale_transport::{Frame, T_DATA, T_EXIT, T_RESULT, T_START, T_STDERR, build_endpoint, io_wire, iroh_wire};
use tokio::io::AsyncReadExt;
use tokio::sync::{Mutex, mpsc};
use tracing::{info, warn};

use crate::common::{
    self, ClientOp, DaemonAdmin, DaemonStatus, EdgeCfg, LocalCommand, LocalRequest, Registry, VERSION,
};
use connection_pool::get_conn;

/// How long to wait for a dial to an edge before declaring it unreachable.
/// Overridable via `AGENT_SCALE_DIAL_SECS`. The default leaves room for ~2-3
/// QUIC handshake retransmits over the relay; setting it much lower risks
/// declaring a live-but-slow edge dead.
fn dial_timeout() -> Duration {
    Duration::from_secs(
        std::env::var("AGENT_SCALE_DIAL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(5),
    )
}

fn idle_secs() -> u64 {
    std::env::var("AGENT_SCALE_IDLE_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10_800)
}

#[derive(Clone)]
struct Ctx {
    endpoint: Endpoint,
    /// Swappable so local admin requests can hot-reload config without a restart.
    edges: Arc<Mutex<HashMap<String, EdgeCfg>>>,
    conns: Arc<Mutex<HashMap<String, Connection>>>,
    dials: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
    store: FsStore,
    center_id: EndpointId,
    /// In-flight client handlers; the daemon won't idle out while > 0.
    active: Arc<AtomicUsize>,
    /// Relay URLs currently installed in the live iroh endpoint.
    known_relays: Arc<Mutex<HashSet<String>>>,
}

/// Increments the active-handler count for its lifetime (RAII so it decrements
/// even on early return / panic).
struct ActiveGuard(Arc<AtomicUsize>);
impl ActiveGuard {
    fn new(c: &Arc<AtomicUsize>) -> Self {
        c.fetch_add(1, Ordering::SeqCst);
        Self(c.clone())
    }
}
impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

pub async fn run() -> Result<()> {
    scale_core::ensure_private_dir(&common::daemon_dir())?;
    let _instance_lock = scale_core::FileLock::try_acquire(&common::daemon_lock_path())
        .context("another agent-scale daemon is already running")?;
    let cfg = common::load_config()?;
    anyhow::ensure!(!cfg.edges.is_empty(), "no edges configured");
    let key = common::load_or_create_key()?;
    let center_id = key.public();

    let mut relays = Vec::new();
    for e in &cfg.edges {
        for r in &e.relays {
            let u = r
                .parse::<iroh::RelayUrl>()
                .with_context(|| format!("bad relay {r} for edge {}", e.name))?;
            if !relays.contains(&u) {
                relays.push(u);
            }
        }
    }
    let controlled = cfg.control.is_some();
    let known_relays: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(
        cfg.edges.iter().flat_map(|e| e.relays.iter().cloned()).collect(),
    ));
    // The daemon also *accepts* blobs connections (so edges can fetch during
    // upload), so it advertises the blobs ALPN.
    let endpoint = build_endpoint(key, &relays, vec![iroh_blobs::ALPN.to_vec()]).await?;
    let store = scale_transport::blobs::open_store(common::daemon_dir().join("blobs")).await?;

    let mut listener =
        crate::local_ipc::Listener::bind().with_context(|| format!("bind {}", common::local_endpoint()))?;

    let reg = Registry {
        pid: std::process::id(),
        endpoint: common::local_endpoint(),
        version: VERSION.into(),
    };
    scale_core::write_json(&common::registry_path(), &reg)?;
    info!(
        "daemon up pid={} endpoint={} version={}",
        reg.pid, reg.endpoint, VERSION
    );

    let edges: Arc<Mutex<HashMap<String, EdgeCfg>>> =
        Arc::new(Mutex::new(cfg.edges.into_iter().map(|e| (e.name.clone(), e)).collect()));
    let ctx = Ctx {
        endpoint: endpoint.clone(),
        edges: edges.clone(),
        conns: Arc::new(Mutex::new(HashMap::new())),
        dials: Arc::new(Mutex::new(HashMap::new())),
        store: store.clone(),
        center_id,
        active: Arc::new(AtomicUsize::new(0)),
        known_relays,
    };

    // Accept loop: serve blobs to known edges (upload direction).
    spawn_blobs_acceptor(endpoint.clone(), edges.clone(), store.clone());
    if controlled {
        spawn_control_watcher(ctx.clone());
    }

    let idle = Duration::from_secs(idle_secs());
    let (admin_tx, mut admin_rx) = mpsc::unbounded_channel();
    loop {
        tokio::select! {
            command = admin_rx.recv() => match command {
                Some(DaemonAdmin::Reload) => reload_edges(&ctx).await,
                Some(DaemonAdmin::Shutdown) | None => break,
                Some(DaemonAdmin::Status) => {}
            },
            accepted = tokio::time::timeout(idle, listener.accept()) => match accepted {
                Ok(Ok(stream)) => {
                    let ctx = ctx.clone();
                    let admin_tx = admin_tx.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_client(stream, ctx, admin_tx).await {
                            warn!("client error: {e}");
                        }
                    });
                }
                Ok(Err(e)) => warn!("accept error: {e}"),
                Err(_) => {
                    // Only idle out when nothing is in flight (a long exec /
                    // transfer / live MCP session keeps the daemon alive).
                    if ctx.active.load(Ordering::SeqCst) > 0 {
                        continue;
                    }
                    info!("idle for {}s; shutting down", idle.as_secs());
                    break;
                }
            }
        }
    }

    let _ = std::fs::remove_file(common::registry_path());
    endpoint.close().await;
    Ok(())
}

fn spawn_blobs_acceptor(endpoint: Endpoint, edges: Arc<Mutex<HashMap<String, EdgeCfg>>>, store: FsStore) {
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let edges = edges.clone();
            let store = store.clone();
            tokio::spawn(async move {
                let conn = match incoming.await {
                    Ok(c) => c,
                    Err(_) => return,
                };
                let remote = conn.remote_id();
                let known = {
                    let edges = edges.lock().await;
                    edges
                        .values()
                        .any(|e| e.endpoint_id.parse::<EndpointId>().ok() == Some(remote))
                };
                if known && conn.alpn() == iroh_blobs::ALPN {
                    let blobs = BlobsProtocol::new(&store, None);
                    let _ = blobs.accept(conn).await;
                } else {
                    conn.close(1u32.into(), b"unauthorized");
                }
            });
        }
    });
}

/// Re-read config.json and swap the edge set in place. Keeps warm connections
/// to unchanged edges; evicts those
/// whose edge was removed or re-keyed (cached connection no longer matches the
/// configured id). Avoids the cold restart (relay home + dial re-establishment).
async fn reload_edges(ctx: &Ctx) {
    let cfg = match common::load_config_or_default() {
        Ok(c) => c,
        Err(e) => {
            warn!("reload: {e}");
            return;
        }
    };
    let desired_relays: HashSet<String> = cfg.edges.iter().flat_map(|edge| edge.relays.iter().cloned()).collect();
    {
        let mut current = ctx.known_relays.lock().await;
        let added: Vec<_> = desired_relays.difference(&current).cloned().collect();
        let removed: Vec<_> = current.difference(&desired_relays).cloned().collect();
        // Install replacements before removing old relays so an address always
        // has the best chance of retaining a relay path during map rotation.
        for value in added {
            match value.parse::<iroh::RelayUrl>() {
                Ok(url) => {
                    ctx.endpoint
                        .insert_relay(url.clone(), Arc::new(iroh::RelayConfig::from(url)))
                        .await;
                    current.insert(value);
                }
                Err(error) => warn!("reload: invalid relay {value}: {error}"),
            }
        }
        for value in removed {
            if let Ok(url) = value.parse::<iroh::RelayUrl>() {
                ctx.endpoint.remove_relay(&url).await;
                current.remove(&value);
            }
        }
    }
    let new: HashMap<String, EdgeCfg> = cfg.edges.into_iter().map(|e| (e.name.clone(), e)).collect();
    // Evict cached connections for edges that are gone or now point at a
    // different id; keep the rest warm.
    let n = new.len();
    {
        // Keep the policy swap and cache eviction in one critical section.
        // `get_conn` takes these locks in the same order before publishing a
        // completed dial, so a revoked edge cannot be reinserted afterward.
        let mut edges = ctx.edges.lock().await;
        let mut conns = ctx.conns.lock().await;
        let evicted: Vec<_> = conns
            .iter()
            .filter(|(name, conn)| {
                !new.get(*name)
                    .and_then(|edge| edge.endpoint_id.parse::<EndpointId>().ok())
                    .is_some_and(|id| conn.remote_id() == id)
            })
            .map(|(name, _)| name.clone())
            .collect();
        for name in evicted {
            if let Some(connection) = conns.remove(&name) {
                connection.close(1u32.into(), b"edge authorization revoked");
            }
        }
        *edges = new;
    }
    info!("reloaded: {n} edge(s) configured");
}

fn spawn_control_watcher(ctx: Ctx) {
    tokio::spawn(async move {
        let mut backoff = 1u64;
        loop {
            let mut cfg = match common::load_config_or_default() {
                Ok(cfg) if cfg.control.is_some() => cfg,
                Ok(_) => return,
                Err(error) => {
                    warn!("control watch: {error}");
                    tokio::time::sleep(Duration::from_secs(backoff)).await;
                    backoff = (backoff * 2).min(60);
                    continue;
                }
            };
            match crate::control::watch_config(&mut cfg).await {
                Ok(crate::control::WatchOutcome::Updated) => {
                    if let Err(error) = common::save_config(&cfg) {
                        warn!("control watch persist: {error}");
                    } else {
                        reload_edges(&ctx).await;
                    }
                    backoff = 1;
                }
                Ok(crate::control::WatchOutcome::Revoked) => {
                    warn!("center enrollment was revoked; disconnecting managed edges");
                    cfg.edges.retain(|edge| !edge.managed);
                    if let Err(error) = common::save_config(&cfg) {
                        warn!("cannot persist center revocation: {error:#}");
                    }
                    reload_edges(&ctx).await;
                    return;
                }
                Err(error) => {
                    warn!("control watch: {error:#}");
                    tokio::time::sleep(Duration::from_secs(backoff)).await;
                    backoff = (backoff * 2).min(60);
                }
            }
        }
    });
}

async fn handle_client(
    stream: crate::local_ipc::Stream,
    ctx: Ctx,
    admin_tx: mpsc::UnboundedSender<DaemonAdmin>,
) -> Result<()> {
    let _active = ActiveGuard::new(&ctx.active);
    let (mut cr, mut cw) = tokio::io::split(stream);
    let Frame { tag, payload } = match io_wire::read_frame(&mut cr).await? {
        Some(f) => f,
        None => return Ok(()),
    };
    anyhow::ensure!(tag == T_START, "expected START from client, got {tag}");
    let request: LocalRequest = serde_json::from_slice(&payload)?;
    if let LocalCommand::Admin(command) = request.command {
        return handle_admin(command, request.version, &ctx, &admin_tx, &mut cw).await;
    }
    anyhow::ensure!(request.version == VERSION, "client/daemon version mismatch");
    let LocalCommand::Work(req) = request.command else {
        unreachable!()
    };
    let edge = {
        let edges = ctx.edges.lock().await;
        edges
            .get(&req.edge)
            .with_context(|| format!("unknown edge '{}'", req.edge))?
            .clone()
    };

    match req.op {
        ClientOp::Exec(params) => relay_exec(&ctx, &edge, params, cr, cw).await,
        ClientOp::Download { remote, local } => {
            let resp = into_resp(do_download(&ctx, &edge, &remote, &local).await);
            io_wire::write_frame(&mut cw, T_RESULT, &serde_json::to_vec(&resp)?).await
        }
        ClientOp::Upload { local, remote } => {
            let resp = into_resp(do_upload(&ctx, &edge, &local, &remote).await);
            io_wire::write_frame(&mut cw, T_RESULT, &serde_json::to_vec(&resp)?).await
        }
        ClientOp::McpList => relay_mcp_control(&ctx, &edge, EdgeReq::McpList, cw).await,
        ClientOp::McpUpsert { name, transport } => {
            relay_mcp_control(&ctx, &edge, EdgeReq::McpUpsert { name, transport }, cw).await
        }
        ClientOp::McpRemove { name } => relay_mcp_control(&ctx, &edge, EdgeReq::McpRemove { name }, cw).await,
        ClientOp::McpConnect { name } => relay_mcp(&ctx, &edge, name, cr, cw).await,
    }
}

async fn handle_admin(
    command: DaemonAdmin,
    client_version: String,
    ctx: &Ctx,
    admin_tx: &mpsc::UnboundedSender<DaemonAdmin>,
    send: &mut crate::local_ipc::WriteHalf,
) -> Result<()> {
    let status = DaemonStatus {
        pid: std::process::id(),
        version: VERSION.into(),
        active_requests: ctx.active.load(Ordering::SeqCst).saturating_sub(1),
        configured_edges: ctx.edges.lock().await.len(),
    };
    let response = if matches!(command, DaemonAdmin::Status | DaemonAdmin::Shutdown) || client_version == VERSION {
        RpcResult::Ok(status)
    } else {
        RpcResult::Error(RemoteError {
            code: "version_mismatch".into(),
            message: format!("daemon is {VERSION}, client is {client_version}"),
        })
    };
    io_wire::write_frame(send, T_RESULT, &serde_json::to_vec(&response)?).await?;
    if matches!(response, RpcResult::Ok(_)) && !matches!(command, DaemonAdmin::Status) {
        let _ = admin_tx.send(command);
    }
    Ok(())
}

async fn relay_mcp_control(
    ctx: &Ctx,
    edge: &EdgeCfg,
    request: EdgeReq,
    mut cw: crate::local_ipc::WriteHalf,
) -> Result<()> {
    let result: Result<Vec<u8>> = async {
        let conn = get_conn(ctx, edge).await?;
        let (mut es, mut er) = conn.open_bi().await.map_err(|e| anyhow::anyhow!("open_bi: {e}"))?;
        iroh_wire::write_frame(&mut es, T_START, &serde_json::to_vec(&request)?).await?;
        let _ = es.finish();
        match iroh_wire::read_frame(&mut er).await? {
            Some(Frame { tag: T_RESULT, payload }) => Ok(payload),
            Some(frame) => anyhow::bail!("unexpected edge frame tag {}", frame.tag),
            None => anyhow::bail!("edge closed without an MCP result"),
        }
    }
    .await;
    let payload = match result {
        Ok(payload) => payload,
        Err(error) => serde_json::to_vec(&RpcResult::<()>::Error(RemoteError::internal(format!("{error:#}"))))?,
    };
    io_wire::write_frame(&mut cw, T_RESULT, &payload).await
}

/// Transparent bidirectional MCP pipe: relay T_DATA frames between the client
/// (local IPC) and the edge's spawned MCP server (iroh).
async fn relay_mcp(
    ctx: &Ctx,
    edge: &EdgeCfg,
    name: String,
    mut cr: crate::local_ipc::ReadHalf,
    mut cw: crate::local_ipc::WriteHalf,
) -> Result<()> {
    let opened = async {
        let conn = get_conn(ctx, edge).await?;
        let (mut es, mut er) = conn.open_bi().await.map_err(|e| anyhow::anyhow!("open_bi: {e}"))?;
        let req = EdgeReq::McpConnect { name };
        iroh_wire::write_frame(&mut es, T_START, &serde_json::to_vec(&req)?).await?;
        let startup = match iroh_wire::read_frame(&mut er).await? {
            Some(Frame { tag: T_RESULT, payload }) => payload,
            Some(frame) => anyhow::bail!("unexpected edge frame tag {} during MCP startup", frame.tag),
            None => anyhow::bail!("edge closed during MCP startup"),
        };
        Ok::<_, anyhow::Error>((es, er, startup))
    }
    .await;
    let (mut es, mut er, startup) = match opened {
        Ok(opened) => opened,
        Err(error) => {
            let response: RpcResult<()> = RpcResult::Error(RemoteError::internal(format!("{error:#}")));
            io_wire::write_frame(&mut cw, T_RESULT, &serde_json::to_vec(&response)?).await?;
            return Ok(());
        }
    };
    io_wire::write_frame(&mut cw, T_RESULT, &startup).await?;
    let response: RpcResult<()> = serde_json::from_slice(&startup)?;
    if matches!(response, RpcResult::Error(_)) {
        return Ok(());
    }

    let mut client_open = true;
    loop {
        tokio::select! {
            f = io_wire::read_frame(&mut cr), if client_open => match f? {
                Some(Frame { tag: T_DATA, payload }) => iroh_wire::write_frame(&mut es, T_DATA, &payload).await?,
                _ => { let _ = es.finish(); client_open = false; } // half-close to edge, keep relaying back
            },
            f = iroh_wire::read_frame(&mut er) => match f? {
                Some(Frame { tag: tag @ (T_DATA | T_STDERR), payload }) => {
                    io_wire::write_frame(&mut cw, tag, &payload).await?
                }
                _ => break, // edge/mcp closed -> done
            },
        }
    }
    Ok(())
}

fn into_resp(result: Result<u64>) -> RpcResult<TransferResult> {
    match result {
        Ok(bytes) => RpcResult::Ok(TransferResult::Stored { bytes }),
        Err(error) => RpcResult::Error(RemoteError::internal(format!("{error:#}"))),
    }
}

async fn relay_exec(
    ctx: &Ctx,
    edge: &EdgeCfg,
    params: ExecParams,
    mut cr: crate::local_ipc::ReadHalf,
    mut cw: crate::local_ipc::WriteHalf,
) -> Result<()> {
    // Dial + open the exec stream. On failure, report it to the client as a
    // STDERR line + nonzero EXIT (both of which `exec()` already renders) rather
    // than dropping the unix stream, which leaves the client hanging silently.
    let setup = async {
        let conn = get_conn(ctx, edge).await?;
        let (mut es, er) = conn.open_bi().await.map_err(|e| anyhow::anyhow!("open_bi: {e}"))?;
        iroh_wire::write_frame(&mut es, T_START, &serde_json::to_vec(&EdgeReq::Exec(params))?).await?;
        Ok::<_, anyhow::Error>((es, er))
    };
    // `_es` is held (not dropped) so the edge's recv side stays open until exit.
    let (_es, mut er) = match setup.await {
        Ok(pair) => pair,
        Err(e) => {
            let msg = format!("agent-scale: edge '{}' unreachable: {e:#}\n", edge.name);
            let _ = io_wire::write_frame(&mut cw, T_STDERR, msg.as_bytes()).await;
            let _ = io_wire::write_frame(&mut cw, T_EXIT, &1i32.to_le_bytes()).await;
            return Ok(());
        }
    };

    let mut cbuf = [0u8; 1];
    loop {
        tokio::select! {
            f = iroh_wire::read_frame(&mut er) => {
                match f? {
                    Some(frame) => {
                        io_wire::write_frame(&mut cw, frame.tag, &frame.payload).await?;
                        if frame.tag == T_EXIT { break; }
                    }
                    None => break,
                }
            }
            n = cr.read(&mut cbuf) => {
                match n {
                    Ok(0) | Err(_) => break, // client gone -> drop es/er resets the edge stream
                    Ok(_) => {}
                }
            }
        }
    }
    Ok(())
}

/// Pull a remote file from the edge into a local path. Returns bytes written.
async fn do_download(ctx: &Ctx, edge: &EdgeCfg, remote: &str, local: &str) -> Result<u64> {
    // 1. Ask the edge to stage the file and report its hash.
    let conn = get_conn(ctx, edge).await?;
    let (mut es, mut er) = conn.open_bi().await.map_err(|e| anyhow::anyhow!("open_bi: {e}"))?;
    let req = EdgeReq::PrepareDownload {
        path: remote.to_string(),
    };
    iroh_wire::write_frame(&mut es, T_START, &serde_json::to_vec(&req)?).await?;
    // Keep `es` open: the edge holds the staged blob until we close it.
    let hash = match read_ctrl(&mut er).await? {
        RpcResult::Ok(TransferResult::DownloadReady { hash }) => hash,
        RpcResult::Ok(TransferResult::Stored { .. }) => anyhow::bail!("edge returned an upload result for download"),
        RpcResult::Error(error) => anyhow::bail!("edge {}: {}", error.code, error.message),
    };
    let hash: iroh_blobs::Hash = hash.parse().map_err(|e| anyhow::anyhow!("bad hash: {e}"))?;

    // 2. Stream the blob from the edge straight to the local file (bounded mem).
    let n = scale_transport::blobs::fetch_to_file(&ctx.endpoint, edge_addr(edge)?, hash, local).await?;
    let _ = es.finish(); // tell the edge it can GC the staged blob
    Ok(n)
}

/// Push a local file to a remote path on the edge. Returns bytes written.
async fn do_upload(ctx: &Ctx, edge: &EdgeCfg, local: &str, remote: &str) -> Result<u64> {
    let abs = std::path::absolute(local).with_context(|| format!("resolve {local}"))?;
    anyhow::ensure!(abs.is_file(), "no such file: {local}");
    // Stage in the disk store with a temp-tag; hold it until the edge has fetched.
    let tt = ctx.store.blobs().add_path(abs).temp_tag().await.context("add_path")?;
    let hash = tt.hash().to_string();

    // The edge fetches from us on the same relay it already uses.
    let conn = get_conn(ctx, edge).await?;
    let (mut es, mut er) = conn.open_bi().await.map_err(|e| anyhow::anyhow!("open_bi: {e}"))?;
    let req = EdgeReq::ReceiveUpload {
        hash,
        center_id: ctx.center_id.to_string(),
        // Tell the edge to dial the center back on a relay both share (the
        // center joined every edge relay into its endpoint).
        center_relay: edge.relays.first().cloned().unwrap_or_default(),
        path: remote.to_string(),
    };
    iroh_wire::write_frame(&mut es, T_START, &serde_json::to_vec(&req)?).await?;
    let _ = es.finish();
    let bytes = match read_ctrl(&mut er).await? {
        RpcResult::Ok(TransferResult::Stored { bytes }) => bytes,
        RpcResult::Ok(TransferResult::DownloadReady { .. }) => {
            anyhow::bail!("edge returned a download result for upload")
        }
        RpcResult::Error(error) => anyhow::bail!("edge {}: {}", error.code, error.message),
    };
    drop(tt); // edge has fetched; GC the staged blob
    Ok(bytes)
}

async fn read_ctrl(er: &mut iroh::endpoint::RecvStream) -> Result<RpcResult<TransferResult>> {
    let frame = iroh_wire::read_frame(er).await?.context("no result frame from edge")?;
    anyhow::ensure!(frame.tag == T_RESULT, "expected RESULT, got tag {}", frame.tag);
    Ok(serde_json::from_slice(&frame.payload)?)
}

fn edge_addr(edge: &EdgeCfg) -> Result<EndpointAddr> {
    let id: EndpointId = edge
        .endpoint_id
        .parse()
        .map_err(|e| anyhow::anyhow!("bad endpoint_id for {}: {e}", edge.name))?;
    anyhow::ensure!(!edge.relays.is_empty(), "edge {} has no relay configured", edge.name);
    let mut addr = EndpointAddr::from(id);
    for r in &edge.relays {
        let url: iroh::RelayUrl = r
            .parse()
            .map_err(|e| anyhow::anyhow!("bad relay {r} for {}: {e}", edge.name))?;
        addr = addr.with_relay_url(url);
    }
    Ok(addr)
}

pub async fn control(_status: bool, stop: bool) -> Result<()> {
    if stop {
        match crate::client::daemon_admin(DaemonAdmin::Shutdown).await? {
            Some(status) => println!("stopping daemon pid {}", status.pid),
            None => println!("no daemon running"),
        }
        return Ok(());
    }
    match crate::client::daemon_admin(DaemonAdmin::Status).await? {
        Some(status) => println!(
            "daemon pid={} version={} active={} edges={} endpoint={}",
            status.pid,
            status.version,
            status.active_requests,
            status.configured_edges,
            common::local_endpoint()
        ),
        None => println!("no daemon running"),
    }
    Ok(())
}
