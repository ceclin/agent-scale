//! `agent-scale edge add/ls/rm` — manage the edge registry in config.json.

use crate::common::{self, EdgeCfg};
use anyhow::{Context, Result};

/// Add a new edge, or update an existing one with the same name.
pub async fn add(name: String, endpoint_id: String, relays: Vec<String>) -> Result<()> {
    // Validate formats up front so typos fail here, not at dial time.
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
    let mut affected_relays = relays.clone();
    let action = if let Some(existing) = cfg.edges.iter_mut().find(|e| e.name == name) {
        affected_relays.extend(existing.relays.iter().cloned());
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
    // Reconcile before committing locally so revocation cannot look complete
    // while an affected private relay still authorizes the old identity.
    crate::relay::sync_urls(&cfg, &affected_relays).await?;
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
    let mut cfg = common::config_transaction()?;
    anyhow::ensure!(
        cfg.control.is_none(),
        "manual edges cannot be changed in a control-managed profile"
    );
    if let Some(edge) = cfg.edges.iter().find(|edge| edge.name == name && edge.managed) {
        anyhow::bail!(
            "edge '{}' is control-managed; remove it with `as-control edge rm <center>/{}` on the Control host",
            edge.name,
            edge.name
        );
    }
    let affected_relays = cfg
        .edges
        .iter()
        .find(|e| e.name == name)
        .map(|e| e.relays.clone())
        .with_context(|| format!("no edge named '{name}'"))?;
    let before = cfg.edges.len();
    cfg.edges.retain(|e| e.name != name);
    debug_assert!(cfg.edges.len() < before);
    crate::relay::sync_urls(&cfg, &affected_relays).await?;
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
