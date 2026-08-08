//! Edge-side iroh transport: accept connections from the trusted center and
//! serve, on two ALPNs:
//!   - `scale_transport::ALPN` — streaming `exec` and file-transfer control
//!     (PrepareDownload / ReceiveUpload), one request per QUIC bi-stream
//!   - `iroh_blobs::ALPN` — serve blobs from the local store (download path)

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use iroh::endpoint::{Incoming, RecvStream, SendStream};
use iroh::protocol::ProtocolHandler;
use iroh::{Endpoint, EndpointAddr};
use iroh_blobs::BlobsProtocol;
use iroh_blobs::store::fs::FsStore;
use protocol::{EdgeReq, McpTransport, RemoteError, RpcResult, TransferResult};
use scale_transport::{Frame, T_RESULT, T_START, iroh_wire};
use tracing::{info, warn};

use crate::mcp_registry::RegistryStore;

/// Which center(s) this edge will accept.
#[derive(Clone)]
pub struct CenterPin {
    inner: Arc<Mutex<CenterPinState>>,
}

struct CenterPinState {
    auth: CenterAuth,
    connections: HashMap<iroh::EndpointId, HashMap<usize, iroh::endpoint::Connection>>,
}

enum CenterAuth {
    Single {
        pinned: Option<iroh::EndpointId>,
        store: Option<PathBuf>,
    },
    Managed(HashSet<iroh::EndpointId>),
}

impl CenterPin {
    pub fn strict(id: iroh::EndpointId) -> Self {
        Self {
            inner: Arc::new(Mutex::new(CenterPinState {
                auth: CenterAuth::Single {
                    pinned: Some(id),
                    store: None,
                },
                connections: HashMap::new(),
            })),
        }
    }

    pub fn tofu(existing: Option<iroh::EndpointId>, store: PathBuf) -> Self {
        Self {
            inner: Arc::new(Mutex::new(CenterPinState {
                auth: CenterAuth::Single {
                    pinned: existing,
                    store: Some(store),
                },
                connections: HashMap::new(),
            })),
        }
    }

    pub fn managed(ids: HashSet<iroh::EndpointId>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(CenterPinState {
                auth: CenterAuth::Managed(ids),
                connections: HashMap::new(),
            })),
        }
    }

    fn authorize_and_register(&self, connection: &iroh::endpoint::Connection) -> Result<bool> {
        let remote = connection.remote_id();
        let mut state = self.inner.lock().unwrap();
        let authorized = match &mut state.auth {
            CenterAuth::Single { pinned: Some(id), .. } => *id == remote,
            CenterAuth::Single { pinned, store } => {
                if let Some(path) = store {
                    scale_core::atomic_write(path, format!("{remote}\n").as_bytes())?;
                }
                *pinned = Some(remote);
                info!("pinned center {remote} (trust-on-first-use)");
                true
            }
            CenterAuth::Managed(ids) => ids.contains(&remote),
        };
        if authorized {
            state
                .connections
                .entry(remote)
                .or_default()
                .insert(connection.stable_id(), connection.clone());
        }
        Ok(authorized)
    }

    fn unregister(&self, remote: iroh::EndpointId, stable_id: usize) {
        let mut state = self.inner.lock().unwrap();
        if let Some(connections) = state.connections.get_mut(&remote) {
            connections.remove(&stable_id);
            if connections.is_empty() {
                state.connections.remove(&remote);
            }
        }
    }

    #[cfg(test)]
    fn is_authorized(&self, remote: iroh::EndpointId) -> bool {
        let state = self.inner.lock().unwrap();
        match &state.auth {
            CenterAuth::Single { pinned, .. } => pinned.is_some_and(|id| id == remote),
            CenterAuth::Managed(ids) => ids.contains(&remote),
        }
    }

    #[cfg(test)]
    fn connection_count(&self) -> usize {
        self.inner.lock().unwrap().connections.values().map(HashMap::len).sum()
    }

    pub fn replace_managed(&self, next: HashSet<iroh::EndpointId>) -> Result<()> {
        let mut state = self.inner.lock().unwrap();
        let removed = {
            let CenterAuth::Managed(current) = &mut state.auth else {
                anyhow::bail!("cannot update a standalone center pin");
            };
            let removed: Vec<_> = current.difference(&next).copied().collect();
            *current = next;
            removed
        };
        for endpoint_id in removed {
            if let Some(items) = state.connections.remove(&endpoint_id) {
                for connection in items.into_values() {
                    connection.close(1u32.into(), b"center authorization revoked");
                }
            }
        }
        Ok(())
    }
}

/// Accept loop. `store` backs both the blobs provider and the download path.
pub async fn serve(endpoint: Endpoint, pin: CenterPin, store: FsStore, mcp_registry: RegistryStore) -> Result<()> {
    info!("edge listening");
    while let Some(incoming) = endpoint.accept().await {
        let pin = pin.clone();
        let store = store.clone();
        let mcp_registry = mcp_registry.clone();
        let endpoint = endpoint.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(incoming, pin, store, mcp_registry, endpoint).await {
                warn!("connection error: {e}");
            }
        });
    }
    Ok(())
}

async fn handle_conn(
    incoming: Incoming,
    pin: CenterPin,
    store: FsStore,
    mcp_registry: RegistryStore,
    endpoint: Endpoint,
) -> Result<()> {
    let conn = incoming.await.context("handshake")?;
    let remote = conn.remote_id();
    if !pin.authorize_and_register(&conn)? {
        warn!("rejecting unauthorized center {remote}");
        conn.close(1u32.into(), b"unauthorized");
        return Ok(());
    }
    let stable_id = conn.stable_id();

    let result = if conn.alpn() == iroh_blobs::ALPN {
        // Serve blobs the edge has staged (download direction).
        let blobs = BlobsProtocol::new(&store, None);
        blobs
            .accept(conn)
            .await
            .map_err(|e| anyhow::anyhow!("blobs accept: {e}"))
    } else {
        info!("center {remote} connected");
        while let Ok((send, recv)) = conn.accept_bi().await {
            let store = store.clone();
            let mcp_registry = mcp_registry.clone();
            let endpoint = endpoint.clone();
            tokio::spawn(async move {
                if let Err(e) = serve_request(send, recv, store, mcp_registry, endpoint, remote).await {
                    warn!("request error: {e}");
                }
            });
        }
        Ok(())
    };
    pin.unregister(remote, stable_id);
    result
}

async fn serve_request(
    mut send: SendStream,
    mut recv: RecvStream,
    store: FsStore,
    mcp_registry: RegistryStore,
    endpoint: Endpoint,
    authenticated_center: iroh::EndpointId,
) -> Result<()> {
    let Frame { tag, payload } = match iroh_wire::read_frame(&mut recv).await? {
        Some(f) => f,
        None => return Ok(()),
    };
    anyhow::ensure!(tag == T_START, "expected START, got tag {tag}");
    let req: EdgeReq = serde_json::from_slice(&payload).context("parse EdgeReq")?;

    match req {
        EdgeReq::Exec(params) => crate::runtime::run_exec(send, recv, params).await,
        EdgeReq::McpList => {
            let result = tokio::task::spawn_blocking(move || mcp_registry.list()).await?;
            match result {
                Ok(catalog) => write_json_result(&mut send, &catalog).await,
                Err(error) => write_error_result(&mut send, error).await,
            }
        }
        EdgeReq::McpUpsert { name, transport } => {
            let result = tokio::task::spawn_blocking(move || mcp_registry.upsert(name, transport)).await?;
            match result {
                Ok(_) => write_ok_result(&mut send).await,
                Err(error) => write_error_result(&mut send, error).await,
            }
        }
        EdgeReq::McpRemove { name } => {
            let result = tokio::task::spawn_blocking(move || mcp_registry.remove(&name)).await?;
            match result {
                Ok(()) => write_ok_result(&mut send).await,
                Err(error) => write_error_result(&mut send, error).await,
            }
        }
        EdgeReq::McpConnect { name } => {
            let result = tokio::task::spawn_blocking(move || mcp_registry.get(&name)).await?;
            let transport = match result {
                Ok(transport) => transport,
                Err(error) => return write_error_result(&mut send, error).await,
            };
            match transport {
                McpTransport::Stdio { command, args, cwd } => {
                    crate::runtime::mcp_stdio(send, recv, command, args, cwd).await
                }
                McpTransport::Http { url } => {
                    if let Err(error) = reqwest::Url::parse(&url) {
                        return write_error_result(&mut send, anyhow::anyhow!("invalid MCP URL: {error}")).await;
                    }
                    crate::mcp_http::bridge(send, recv, url, crate::mcp_http::Kind::Streamable).await
                }
                McpTransport::Sse { url } => {
                    if let Err(error) = reqwest::Url::parse(&url) {
                        return write_error_result(&mut send, anyhow::anyhow!("invalid MCP URL: {error}")).await;
                    }
                    crate::mcp_http::bridge(send, recv, url, crate::mcp_http::Kind::LegacySse).await
                }
            }
        }
        EdgeReq::PrepareDownload { path } => {
            // Stage the file in the disk store with a temp-tag (auto-GC), report
            // its hash, then hold the tag until the center finishes fetching
            // (it closes this control stream when done).
            match store.blobs().add_path(PathBuf::from(&path)).temp_tag().await {
                Ok(tt) => {
                    let resp = RpcResult::Ok(TransferResult::DownloadReady {
                        hash: tt.hash().to_string(),
                    });
                    iroh_wire::write_frame(&mut send, T_RESULT, &serde_json::to_vec(&resp)?).await?;
                    let _ = send.finish();
                    let _ = recv.read_to_end(64).await; // wait for the center to close
                    drop(tt); // GC the staged blob
                }
                Err(e) => {
                    let resp: RpcResult<TransferResult> =
                        RpcResult::Error(RemoteError::internal(format!("stage {path}: {e}")));
                    iroh_wire::write_frame(&mut send, T_RESULT, &serde_json::to_vec(&resp)?).await?;
                    let _ = send.finish();
                }
            }
            Ok(())
        }
        EdgeReq::ReceiveUpload {
            hash,
            center_id,
            center_relay,
            path,
        } => {
            anyhow::ensure!(
                center_id == authenticated_center.to_string(),
                "upload center_id does not match authenticated connection"
            );
            let resp = match recv_upload(&endpoint, &hash, &center_id, &center_relay, &path).await {
                Ok(bytes) => RpcResult::Ok(TransferResult::Stored { bytes }),
                Err(error) => RpcResult::Error(RemoteError::internal(format!("{error:#}"))),
            };
            iroh_wire::write_frame(&mut send, T_RESULT, &serde_json::to_vec(&resp)?).await?;
            let _ = send.finish();
            let _ = send.stopped().await;
            Ok(())
        }
    }
}

async fn write_json_result<T: serde::Serialize>(send: &mut SendStream, value: &T) -> Result<()> {
    iroh_wire::write_frame(send, T_RESULT, &serde_json::to_vec(&RpcResult::Ok(value))?).await?;
    let _ = send.finish();
    Ok(())
}

async fn write_ok_result(send: &mut SendStream) -> Result<()> {
    write_json_result(send, &()).await
}

async fn write_error_result(send: &mut SendStream, error: anyhow::Error) -> Result<()> {
    let response: RpcResult<()> = RpcResult::Error(RemoteError::internal(format!("{error:#}")));
    iroh_wire::write_frame(send, T_RESULT, &serde_json::to_vec(&response)?).await?;
    let _ = send.finish();
    Ok(())
}

/// Fetch a blob from the center (streamed to disk) and write it to `path`.
async fn recv_upload(endpoint: &Endpoint, hash: &str, center_id: &str, center_relay: &str, path: &str) -> Result<u64> {
    let id: iroh::EndpointId = center_id.parse().map_err(|e| anyhow::anyhow!("bad center_id: {e}"))?;
    let url: iroh::RelayUrl = center_relay
        .parse()
        .map_err(|e| anyhow::anyhow!("bad center_relay: {e}"))?;
    let hash: iroh_blobs::Hash = hash.parse().map_err(|e| anyhow::anyhow!("bad hash: {e}"))?;
    let addr = EndpointAddr::from(id).with_relay_url(url);
    scale_transport::blobs::fetch_to_file(endpoint, addr, hash, path).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_center_set_replaces_authority() {
        let old = iroh::SecretKey::generate().public();
        let next = iroh::SecretKey::generate().public();
        let pin = CenterPin::managed(HashSet::from([old]));
        assert!(pin.is_authorized(old));
        assert!(!pin.is_authorized(next));

        pin.replace_managed(HashSet::from([next])).unwrap();
        assert!(!pin.is_authorized(old));
        assert!(pin.is_authorized(next));
        assert_eq!(pin.connection_count(), 0);
    }
}
