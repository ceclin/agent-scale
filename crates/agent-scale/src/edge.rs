//! Simple-mode registry changes stay local; managed removals use the Center's
//! signed Control API.

use crate::common::{self, EdgeCfg};
use anyhow::Result;

/// Add a new edge, or update an existing one with the same name.
pub async fn add(name: String, endpoint_id: String, relays: Vec<String>) -> Result<()> {
    endpoint_id
        .parse::<iroh::EndpointId>()
        .map_err(|e| anyhow::anyhow!("invalid endpoint_id: {e}"))?;
    let using_official_relays = relays.is_empty();
    let relay_urls = scale_transport::relay_urls_or_default(&relays)?;
    let relays: Vec<String> = relay_urls.into_iter().map(|relay| relay.to_string()).collect();

    let mut cfg = common::config_transaction()?;
    anyhow::ensure!(
        cfg.control.is_none(),
        "manual edges cannot be changed in a control-managed profile"
    );
    let action = if let Some(existing) = cfg.edges.iter_mut().find(|e| e.name == name) {
        existing.endpoint_id = endpoint_id;
        existing.relays = relays;
        "updated"
    } else {
        cfg.edges.push(EdgeCfg {
            name: name.clone(),
            endpoint_id,
            relays,
            managed: false,
        });
        "added"
    };
    cfg.commit()?;
    println!("{action} edge '{name}'");
    if using_official_relays {
        println!("  relays: official iroh network");
    }
    refresh_daemon().await?;
    Ok(())
}

pub fn ls() -> Result<()> {
    let cfg = common::load_config_or_default()?;
    if cfg.edges.is_empty() {
        println!("no edges configured");
        return Ok(());
    }
    for e in &cfg.edges {
        println!("{}", e.name);
        println!("  endpoint_id: {}", e.endpoint_id);
        println!("  relays:      {}", e.relays.join(", "));
    }
    Ok(())
}

pub async fn rm(name: String) -> Result<()> {
    if common::load_config_or_default()?.control.is_some() {
        return crate::control::edge_remove(name).await;
    }
    let mut cfg = common::config_transaction()?;
    anyhow::ensure!(cfg.edges.iter().any(|e| e.name == name), "no edge named '{name}'");
    let before = cfg.edges.len();
    cfg.edges.retain(|e| e.name != name);
    debug_assert!(cfg.edges.len() < before);
    cfg.commit()?;
    println!("removed edge '{name}'");
    refresh_daemon().await?;
    Ok(())
}

/// A running daemon caches the edge set at startup; ask it to reload
/// the updated config in place — keeping warm connections to unchanged edges and
/// avoiding a cold restart. (If no daemon is running, the next `exec` spawns one
/// with the new config anyway.)
async fn refresh_daemon() -> Result<()> {
    if crate::client::daemon_admin(crate::common::DaemonAdmin::Reload)
        .await?
        .is_some()
    {
        println!("(asked running daemon to reload edge config)");
    }
    Ok(())
}
