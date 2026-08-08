//! Standalone local iroh relay for development/testing. Prints its HTTP relay
//! URL on the first line of stdout, then runs until killed.
//!
//! Usage: `relay-dev [PORT]` (PORT defaults to an ephemeral port).

use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};

use anyhow::{Context, Result};
use iroh_relay::server::{RelayConfig, Server, ServerConfig};

#[tokio::main]
async fn main() -> Result<()> {
    let port: u16 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);

    let mut cfg = ServerConfig::default();
    cfg.relay = Some(RelayConfig::new(SocketAddr::from((Ipv4Addr::LOCALHOST, port))));
    let server = Server::spawn(cfg).await.context("spawn relay")?;
    let addr = server.http_addr().context("relay has no http addr")?;

    let mut out = std::io::stdout();
    writeln!(out, "http://{addr}")?;
    out.flush()?;

    tokio::signal::ctrl_c().await.ok();
    Ok(())
}
