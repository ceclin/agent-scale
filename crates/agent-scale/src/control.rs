//! Keeps Control-signed topology separate from user-edited simple-mode config.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use base64::Engine;
use control_api::{
    ClaimRequest, ControlStatus, EdgeInviteRequest, EdgeRemoveRequest, InviteKind, InviteResult, JoinResult, JoinToken,
    SignedNodeMap, StatusRequest, WatchRequest,
};
use rand::Rng;
use reqwest::{Client, Url};
use serde::de::DeserializeOwned;

use crate::common::{self, Config, ControlCfg, EdgeCfg};

const CONTROL_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const CONTROL_WATCH_TIMEOUT: Duration = Duration::from_secs(90);

pub async fn join(join_url: String) -> Result<()> {
    let mut config = common::config_transaction()?;
    anyhow::ensure!(config.control.is_none(), "this client is already enrolled in control");
    anyhow::ensure!(
        config.edges.is_empty(),
        "remove standalone edges before joining control"
    );
    let parsed = Url::parse(&join_url).context("invalid join URL")?;
    let token = JoinToken::decode(parsed.fragment().context("join URL is missing its token fragment")?)?;
    let control_id = token.verify()?;
    let (name, audience, control_url) = match &token.invite.kind {
        InviteKind::Client => (
            token.invite.name.clone(),
            token.invite.audience.clone(),
            token.invite.control_url.clone(),
        ),
        _ => bail!("this invitation is not for a client"),
    };
    let key = common::load_or_create_key()?;
    let request = ClaimRequest::sign(token, &key, unix_timestamp(), random_token(16))?;
    let response = send(
        client()?.post(api_url(&control_url, "v1/claim")?).json(&request),
        CONTROL_REQUEST_TIMEOUT,
    )
    .await
    .context("claim client invitation")?;
    let status = response.status();
    let body = response.bytes().await?;
    anyhow::ensure!(
        status.is_success(),
        "control rejected client claim ({status}): {}",
        String::from_utf8_lossy(&body)
    );
    let joined: JoinResult = serde_json::from_slice(&body).context("decode client join response")?;
    joined.map.verify(control_id, key.public())?;
    config.control = Some(ControlCfg {
        name: name.clone(),
        url: control_url,
        control_id: control_id.to_string(),
        audience,
        map: joined.map.clone(),
    });
    apply_map(&mut config, joined.map)?;
    config.commit()?;
    signal_daemon().await?;
    println!("joined control as client '{name}' ({})", key.public());
    Ok(())
}

pub async fn status() -> Result<()> {
    let config = common::load_config_or_default()?;
    let control = config.control.as_ref().context("client is not enrolled in control")?;
    let key = common::load_or_create_key()?;
    let request = StatusRequest::sign(&key, control.audience.clone(), unix_timestamp(), random_token(16))?;
    let response = send(
        client()?.post(api_url(&control.url, "v1/status")?).json(&request),
        CONTROL_REQUEST_TIMEOUT,
    )
    .await
    .context("query control status")?;
    let status: ControlStatus = decode_response(response).await?;
    anyhow::ensure!(status.control_id == control.control_id, "control identity mismatch");
    anyhow::ensure!(status.audience == control.audience, "control audience mismatch");
    println!("{}", control.name);
    println!("  control:  {}", control.url);
    println!("  revision: {}", status.revision);
    println!("  clients:  {}", status.clients);
    println!("  edges:    {}", status.edges);
    println!("  relays:   {}", status.relays);
    Ok(())
}

pub async fn edge_invite(name: String, ttl_secs: u64) -> Result<()> {
    let config = common::load_config_or_default()?;
    let control = config.control.context("client is not enrolled in control")?;
    let request = EdgeInviteRequest::sign(
        &common::load_or_create_key()?,
        control.audience,
        random_token(16),
        unix_timestamp(),
        name,
        ttl_secs,
    )?;
    let response = send(
        client()?.post(api_url(&control.url, "v1/edge/invite")?).json(&request),
        CONTROL_REQUEST_TIMEOUT,
    )
    .await
    .context("create edge invitation")?;
    let result: InviteResult = decode_response(response).await?;
    println!("{}", result.join_url);
    Ok(())
}

pub async fn edge_remove(name: String) -> Result<()> {
    let mut config = common::config_transaction()?;
    let control = config.control.clone().context("client is not enrolled in control")?;
    let edge = config
        .edges
        .iter()
        .find(|edge| edge.managed && edge.name == name)
        .cloned()
        .with_context(|| format!("no managed edge named '{name}'"))?;
    let key = common::load_or_create_key()?;
    let request = EdgeRemoveRequest::sign(
        &key,
        control.audience.clone(),
        random_token(16),
        unix_timestamp(),
        name.clone(),
        edge.endpoint_id,
    )?;
    let response = send(
        client()?.post(api_url(&control.url, "v1/edge/remove")?).json(&request),
        CONTROL_REQUEST_TIMEOUT,
    )
    .await
    .context("remove managed edge")?;
    let map: SignedNodeMap = decode_response(response).await?;
    let control_id = control.control_id.parse().context("invalid cached control id")?;
    map.verify(control_id, key.public())?;
    anyhow::ensure!(
        map.map.audience == control.audience && map.map.control_url == control.url,
        "control map binding mismatch"
    );
    anyhow::ensure!(
        map.map.revision > control.map.map.revision,
        "control revision did not advance"
    );
    apply_map(&mut config, map)?;
    config.commit()?;
    signal_daemon().await?;
    println!("removed edge '{name}'");
    Ok(())
}

pub async fn sync() -> Result<()> {
    let mut config = common::config_transaction()?;
    sync_config(&mut config).await?;
    let revision = config.control.as_ref().unwrap().map.map.revision;
    config.commit()?;
    signal_daemon().await?;
    println!("control map synchronized at revision {revision}");
    Ok(())
}

pub async fn sync_config(config: &mut Config) -> Result<()> {
    sync_config_at(config, 0).await
}

pub enum WatchOutcome {
    Updated,
    Unchanged,
    Revoked,
}

pub async fn watch_config(config: &mut Config) -> Result<WatchOutcome> {
    let revision = config
        .control
        .as_ref()
        .context("client is not enrolled in control")?
        .map
        .map
        .revision;
    let control = config.control.clone().context("client is not enrolled in control")?;
    let key = common::load_or_create_key()?;
    let request = WatchRequest::sign(&key, revision, unix_timestamp(), random_token(16))?;
    let response = send(
        client()?.post(api_url(&control.url, "v1/watch")?).json(&request),
        CONTROL_WATCH_TIMEOUT,
    )
    .await
    .context("watch control map")?;
    if response.status() == reqwest::StatusCode::NO_CONTENT {
        return Ok(WatchOutcome::Unchanged);
    }
    if matches!(
        response.status(),
        reqwest::StatusCode::FORBIDDEN | reqwest::StatusCode::GONE
    ) {
        return Ok(WatchOutcome::Revoked);
    }
    let map: SignedNodeMap = decode_response(response).await?;
    let control_id = control.control_id.parse().context("invalid cached control id")?;
    map.verify(control_id, key.public())?;
    anyhow::ensure!(
        map.map.audience == control.audience && map.map.control_url == control.url,
        "control map binding mismatch"
    );
    anyhow::ensure!(map.map.revision >= control.map.map.revision, "control map rolled back");
    apply_map(config, map)?;
    Ok(WatchOutcome::Updated)
}

async fn sync_config_at(config: &mut Config, known_revision: u64) -> Result<()> {
    let control = config.control.clone().context("client is not enrolled in control")?;
    let key = common::load_or_create_key()?;
    let request = WatchRequest::sign(&key, known_revision, unix_timestamp(), random_token(16))?;
    let response = send(
        client()?.post(api_url(&control.url, "v1/watch")?).json(&request),
        CONTROL_WATCH_TIMEOUT,
    )
    .await
    .context("watch control map")?;
    let map: SignedNodeMap = decode_response(response).await?;
    let control_id = control.control_id.parse().context("invalid cached control id")?;
    map.verify(control_id, key.public())?;
    anyhow::ensure!(
        map.map.audience == control.audience && map.map.control_url == control.url,
        "control map binding mismatch"
    );
    anyhow::ensure!(map.map.revision >= control.map.map.revision, "control map rolled back");
    apply_map(config, map)
}

pub async fn refresh_cache() -> Result<()> {
    let mut config = common::config_transaction()?;
    if config.control.is_none() {
        return Ok(());
    }
    sync_config(&mut config).await?;
    config.commit()?;
    signal_daemon().await?;
    Ok(())
}

fn apply_map(config: &mut Config, map: SignedNodeMap) -> Result<()> {
    let relay_urls: Vec<String> = map.map.relays.iter().map(|relay| relay.url.clone()).collect();
    let manual_names: Vec<_> = config
        .edges
        .iter()
        .filter(|edge| !edge.managed)
        .map(|edge| edge.name.as_str())
        .collect();
    for edge in &map.map.edges {
        anyhow::ensure!(
            !manual_names.contains(&edge.name.as_str()),
            "control edge '{}' conflicts with a manual edge",
            edge.name
        );
    }
    config.edges.retain(|edge| !edge.managed);
    for edge in &map.map.edges {
        config.edges.push(EdgeCfg {
            name: edge.name.clone(),
            endpoint_id: edge.endpoint_id.clone(),
            relays: relay_urls.clone(),
            managed: true,
        });
    }
    let control = config.control.as_mut().context("missing control profile")?;
    control.map = map;
    Ok(())
}

async fn decode_response<T: DeserializeOwned>(response: reqwest::Response) -> Result<T> {
    let status = response.status();
    let body = response.bytes().await?;
    if !status.is_success() {
        bail!("control request failed ({status}): {}", String::from_utf8_lossy(&body));
    }
    serde_json::from_slice(&body).context("decode control response")
}

fn api_url(base: &str, path: &str) -> Result<Url> {
    Url::parse(&format!("{}/", base.trim_end_matches('/')))?
        .join(path)
        .context("build control API URL")
}
fn client() -> Result<Client> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .build()
        .context("build Control HTTP client")
}

async fn send(request: reqwest::RequestBuilder, timeout: Duration) -> Result<reqwest::Response> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        anyhow::ensure!(!remaining.is_zero(), "Control request timed out after {timeout:?}");
        let attempt = request.try_clone().context("Control request body cannot be retried")?;
        let response = tokio::time::timeout(remaining, attempt.send())
            .await
            .with_context(|| format!("Control request timed out after {timeout:?}"))??;
        if !matches!(
            response.status(),
            reqwest::StatusCode::TOO_MANY_REQUESTS | reqwest::StatusCode::SERVICE_UNAVAILABLE
        ) {
            return Ok(response);
        }
        let Some(seconds) = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
        else {
            return Ok(response);
        };
        let jitter = u64::from(rand::random::<u16>()) % 1001;
        let delay = Duration::from_secs(seconds).saturating_add(Duration::from_millis(jitter));
        anyhow::ensure!(
            delay < deadline.saturating_duration_since(tokio::time::Instant::now()),
            "Control is busy"
        );
        tokio::time::sleep(delay).await;
    }
}
fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
fn random_token(len: usize) -> String {
    let mut bytes = vec![0; len];
    rand::rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
async fn signal_daemon() -> Result<()> {
    crate::client::daemon_admin(crate::common::DaemonAdmin::Reload).await?;
    Ok(())
}
