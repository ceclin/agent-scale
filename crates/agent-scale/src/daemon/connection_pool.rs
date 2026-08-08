//! Warm edge connections with per-edge dial singleflight and revocation checks.

use std::sync::Arc;

use anyhow::Result;
use iroh::EndpointId;
use iroh::endpoint::Connection;
use scale_transport::ALPN;
use tokio::sync::Mutex;
use tracing::info;

use super::{Ctx, dial_timeout, edge_addr};
use crate::common::EdgeCfg;

pub(super) async fn get_conn(ctx: &Ctx, edge: &EdgeCfg) -> Result<Connection> {
    {
        let connections = ctx.conns.lock().await;
        if let Some(connection) = connections.get(&edge.name)
            && connection.close_reason().is_none()
        {
            return Ok(connection.clone());
        }
    }

    let dial_lock = {
        let mut dials = ctx.dials.lock().await;
        dials
            .entry(edge.name.clone())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    };
    let _dial_guard = dial_lock.lock().await;
    {
        let connections = ctx.conns.lock().await;
        if let Some(connection) = connections.get(&edge.name)
            && connection.close_reason().is_none()
        {
            return Ok(connection.clone());
        }
    }

    let address = edge_addr(edge)?;
    let endpoint_id = address.id;
    let connection = tokio::time::timeout(dial_timeout(), ctx.endpoint.connect(address, ALPN))
        .await
        .map_err(|_| anyhow::anyhow!("connect {}: timed out (edge offline?)", edge.name))?
        .map_err(|error| anyhow::anyhow!("connect {}: {error}", edge.name))?;
    anyhow::ensure!(
        connection.remote_id() == endpoint_id,
        "edge {} identity mismatch",
        edge.name
    );

    // Publish the completed dial under the same lock order used by config
    // reload, so a revoked/re-keyed edge cannot be reinserted afterward.
    let edges = ctx.edges.lock().await;
    let still_authorized = edges
        .get(&edge.name)
        .and_then(|current| current.endpoint_id.parse::<EndpointId>().ok())
        .is_some_and(|current_id| current_id == endpoint_id);
    if !still_authorized {
        connection.close(1u32.into(), b"edge authorization changed during dial");
        anyhow::bail!("edge {} authorization changed during dial", edge.name);
    }
    ctx.conns.lock().await.insert(edge.name.clone(), connection.clone());
    drop(edges);
    info!("dialed edge {} ({endpoint_id})", edge.name);

    let connections = ctx.conns.clone();
    let name = edge.name.clone();
    let watched = connection.clone();
    tokio::spawn(async move {
        let _ = watched.closed().await;
        let mut connections = connections.lock().await;
        if connections
            .get(&name)
            .is_some_and(|connection| connection.close_reason().is_some())
        {
            connections.remove(&name);
            info!("evicted dead connection to edge {name}");
        }
    });

    Ok(connection)
}
