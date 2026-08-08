//! Private relay registry and desired-membership synchronization.

use std::{
    collections::HashSet,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use relay_api::{MembershipSnapshot, RELAY_PROTOCOL_VERSION, RelayMember, RelayStatus, SignedSnapshot};
use reqwest::{Client, StatusCode, Url};

use crate::common::{self, Config, RelayCfg};

pub async fn add(name: String, url: String, admin_url: String, audience: Option<String>) -> Result<()> {
    anyhow::ensure!(!name.trim().is_empty(), "relay name must not be empty");
    let url = url
        .parse::<iroh::RelayUrl>()
        .map_err(|error| anyhow::anyhow!("invalid relay URL: {error}"))?
        .to_string();
    let admin_url = normalize_admin_url(&admin_url)?;
    let audience = audience.unwrap_or_else(|| name.clone());
    anyhow::ensure!(!audience.trim().is_empty(), "relay audience must not be empty");

    let mut config = common::config_transaction()?;
    anyhow::ensure!(
        config.control.is_none(),
        "manual relays cannot be changed in a control-managed profile"
    );
    anyhow::ensure!(
        !config.relays.iter().any(|relay| relay.name != name && relay.url == url),
        "relay URL is already managed under another name"
    );
    let action = if let Some(existing) = config.relays.iter_mut().find(|relay| relay.name == name) {
        anyhow::ensure!(
            existing.url == url && existing.audience == audience,
            "cannot change a managed relay's URL or audience in place; remove it first so old memberships are revoked"
        );
        existing.admin_url = admin_url;
        "updated"
    } else {
        config.relays.push(RelayCfg {
            name: name.clone(),
            url,
            admin_url,
            audience,
        });
        "added"
    };
    sync_configured(&config, &name).await?;
    config.commit()?;
    println!("{action} managed relay '{name}'");
    Ok(())
}

pub fn ls() -> Result<()> {
    let config = common::load_config_or_default()?;
    if config.relays.is_empty() {
        println!("no managed relays configured");
        return Ok(());
    }
    for relay in &config.relays {
        println!("{}", relay.name);
        println!("  url:        {}", relay.url);
        println!("  admin_url:  {}", relay.admin_url);
        println!("  audience:   {}", relay.audience);
    }
    Ok(())
}

pub async fn status(name: &str) -> Result<()> {
    let config = common::load_config_or_default()?;
    let relay = find_relay(&config, name)?;
    let status = fetch_status(&client(), relay).await?;
    verify_remote_identity(relay, &status)?;
    println!("{}", relay.name);
    println!("  version:    {}", status.version);
    println!("  members:    {}", status.members);
    println!("  center_id:  {}", status.center_id);
    println!("  audience:   {}", status.audience);
    Ok(())
}

pub async fn sync(name: &str) -> Result<()> {
    let config = common::load_config_or_default()?;
    sync_configured(&config, name).await
}

pub async fn rm(name: &str) -> Result<()> {
    let mut config = common::config_transaction()?;
    anyhow::ensure!(
        config.control.is_none(),
        "manual relays cannot be changed in a control-managed profile"
    );
    let relay = find_relay(&config, name)?.clone();
    anyhow::ensure!(
        !config.edges.iter().any(|edge| edge.relays.contains(&relay.url)),
        "relay '{}' is still used by configured edges; remove or move them first",
        relay.name
    );
    sync_one(&config, &relay).await?;
    config.relays.retain(|item| item.name != name);
    config.commit()?;
    println!("removed managed relay '{name}'");
    Ok(())
}

pub async fn sync_urls(config: &Config, urls: &[String]) -> Result<()> {
    let affected: HashSet<&str> = urls.iter().map(String::as_str).collect();
    let relays: Vec<_> = config
        .relays
        .iter()
        .filter(|relay| affected.contains(relay.url.as_str()))
        .collect();
    let mut errors = Vec::new();
    for relay in relays {
        if let Err(error) = sync_one(config, relay).await {
            errors.push(format!("{}: {error:#}", relay.name));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        bail!("relay sync failed: {}", errors.join("; "))
    }
}

async fn sync_configured(config: &Config, name: &str) -> Result<()> {
    let relay = find_relay(config, name)?;
    sync_one(config, relay).await
}

async fn sync_one(config: &Config, relay: &RelayCfg) -> Result<()> {
    let client = client();
    let remote = fetch_status(&client, relay).await?;
    verify_remote_identity(relay, &remote)?;
    let key = common::load_or_create_key()?;

    let mut members = vec![RelayMember {
        name: "center".into(),
        endpoint_id: key.public().to_string(),
    }];
    members.extend(
        config
            .edges
            .iter()
            .filter(|edge| edge.relays.contains(&relay.url))
            .map(|edge| RelayMember {
                name: edge.name.clone(),
                endpoint_id: edge.endpoint_id.clone(),
            }),
    );
    members.sort_by(|left, right| left.endpoint_id.cmp(&right.endpoint_id));
    let snapshot = MembershipSnapshot {
        protocol_version: RELAY_PROTOCOL_VERSION,
        audience: relay.audience.clone(),
        version: remote.version.checked_add(1).context("relay version overflow")?,
        issued_at: unix_timestamp(),
        members,
    };
    let signed = SignedSnapshot::sign(snapshot, &key)?;
    let url = admin_endpoint(relay, "v1/snapshot")?;
    let response = client
        .post(url)
        .json(&signed)
        .send()
        .await
        .context("send relay snapshot")?;
    let status = response.status();
    let body = response.bytes().await.context("read relay response")?;
    if !status.is_success() {
        bail!("relay rejected snapshot ({status}): {}", String::from_utf8_lossy(&body));
    }
    let applied: RelayStatus = serde_json::from_slice(&body).context("decode relay response")?;
    println!(
        "synced relay '{}' (version {}, {} members)",
        relay.name, applied.version, applied.members
    );
    Ok(())
}

fn client() -> Client {
    let _ = rustls::crypto::ring::default_provider().install_default();
    Client::new()
}

async fn fetch_status(client: &Client, relay: &RelayCfg) -> Result<RelayStatus> {
    let url = admin_endpoint(relay, "v1/status")?;
    let response = client.get(url).send().await.context("query relay status")?;
    let status = response.status();
    if status != StatusCode::OK {
        let body = response.text().await.unwrap_or_default();
        bail!("relay status failed ({status}): {body}");
    }
    response.json().await.context("decode relay status")
}

fn verify_remote_identity(relay: &RelayCfg, status: &RelayStatus) -> Result<()> {
    anyhow::ensure!(status.audience == relay.audience, "relay audience mismatch");
    let expected = common::load_or_create_key()?.public().to_string();
    anyhow::ensure!(status.center_id == expected, "relay is pinned to a different center");
    Ok(())
}

fn find_relay<'a>(config: &'a Config, name: &str) -> Result<&'a RelayCfg> {
    config
        .relays
        .iter()
        .find(|relay| relay.name == name)
        .with_context(|| format!("unknown managed relay '{name}'"))
}

fn normalize_admin_url(value: &str) -> Result<String> {
    let mut url = Url::parse(value).context("invalid admin URL")?;
    anyhow::ensure!(
        url.scheme() == "https" || is_loopback_http(&url),
        "admin URL must use HTTPS unless it targets localhost"
    );
    anyhow::ensure!(
        url.query().is_none() && url.fragment().is_none(),
        "admin URL must not contain a query or fragment"
    );
    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path());
        url.set_path(&path);
    }
    Ok(url.to_string())
}

fn is_loopback_http(url: &Url) -> bool {
    url.scheme() == "http" && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"))
}

fn admin_endpoint(relay: &RelayCfg, path: &str) -> Result<Url> {
    Url::parse(&relay.admin_url)?
        .join(path)
        .context("build relay admin URL")
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_url_requires_tls_off_host() {
        assert!(normalize_admin_url("http://relay.example/admin").is_err());
        assert_eq!(
            normalize_admin_url("http://127.0.0.1:3341").unwrap(),
            "http://127.0.0.1:3341/"
        );
        assert_eq!(
            normalize_admin_url("https://relay.example/admin").unwrap(),
            "https://relay.example/admin/"
        );
    }
}
