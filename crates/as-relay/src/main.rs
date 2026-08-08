//! Private iroh relay with a center-managed dynamic EndpointId allowlist.

use std::{
    collections::HashSet,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use clap::{Parser, Subcommand};
use control_api::{ClaimRequest, InviteKind, JoinResult, JoinToken, WatchRequest};
use iroh_base::{EndpointId, SecretKey};
use iroh_relay::server::{Access, AccessControl, ClientRequest, RelayConfig, Server, ServerConfig, clients::Clients};
use relay_api::{MembershipSnapshot, RELAY_PROTOCOL_VERSION, RelayStatus, SignedSnapshot};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

const MAX_CLOCK_SKEW_SECS: i64 = 300;

#[derive(Parser)]
#[command(name = "as-relay", about = "Dynamically managed private iroh relay")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Enroll this relay with an as-control invitation.
    Join {
        join_url: String,
        /// Connect to Control through this URL while retaining the signed public URL.
        #[arg(long)]
        control_url: Option<String>,
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
    /// Run the relay and its signed management API.
    Run {
        /// Relay data-plane listen address. Put TLS in front for production.
        #[arg(long, default_value = "[::]:3340")]
        relay_bind: SocketAddr,
        /// Management API listen address. Expose only behind HTTPS in production.
        #[arg(long, default_value = "127.0.0.1:3341")]
        admin_bind: SocketAddr,
        /// Directory containing the durable membership snapshot.
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Enroll from this invitation file when no Control profile exists.
        #[arg(long)]
        join_if_needed: Option<PathBuf>,
        /// Connect to Control through this URL during first-run enrollment.
        #[arg(long, requires = "join_if_needed")]
        control_url: Option<String>,
    },
}

#[derive(Debug, Clone)]
struct DynamicAccess {
    allowed: Arc<ArcSwap<HashSet<EndpointId>>>,
}

impl AccessControl for DynamicAccess {
    async fn on_connect(&self, request: &ClientRequest) -> Access {
        if self.allowed.load().contains(&request.endpoint_id()) {
            Access::Allow
        } else {
            warn!(endpoint_id = %request.endpoint_id(), "denied relay access");
            Access::Deny {
                reason: Some("endpoint is not authorized".into()),
            }
        }
    }
}

#[derive(Clone)]
struct AdminState {
    audience: Arc<str>,
    authority_id: EndpointId,
    state_path: Arc<PathBuf>,
    current: Arc<Mutex<MembershipSnapshot>>,
    allowed: Arc<ArcSwap<HashSet<EndpointId>>>,
    clients: Clients,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(error: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: error.to_string(),
        }
    }

    fn conflict(error: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: error.to_string(),
        }
    }

    fn unauthorized(error: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: error.to_string(),
        }
    }

    fn internal(error: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: error.to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, self.message).into_response()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    match Cli::parse().command {
        Command::Join {
            join_url,
            control_url,
            state_dir,
        } => join_control(join_url, control_url, state_dir).await,
        Command::Run {
            relay_bind,
            admin_bind,
            state_dir,
            join_if_needed,
            control_url,
        } => run(relay_bind, admin_bind, state_dir, join_if_needed, control_url).await,
    }
}

async fn run(
    relay_bind: SocketAddr,
    admin_bind: SocketAddr,
    state_dir: Option<PathBuf>,
    join_if_needed: Option<PathBuf>,
    control_url: Option<String>,
) -> Result<()> {
    let state_dir = state_dir.unwrap_or_else(default_state_dir);
    tokio::fs::create_dir_all(&state_dir)
        .await
        .with_context(|| format!("create {}", state_dir.display()))?;
    if !profile_path(&state_dir).exists()
        && let Some(join_file) = join_if_needed
    {
        join_from_file(join_file, control_url, state_dir.clone()).await?;
    }
    let profile = load_profile(&state_dir)?;
    let authority_id = profile.control_id.parse().context("invalid profile control id")?;
    let audience = profile.audience.clone();
    anyhow::ensure!(!audience.trim().is_empty(), "audience must not be empty");
    let state_path = state_dir.join("membership.json");
    let snapshot = load_or_initialize(&state_path, &audience).await?;
    let ids = validate_snapshot(&snapshot, &audience)?;
    let allowed = Arc::new(ArcSwap::from_pointee(ids));
    let access = DynamicAccess {
        allowed: allowed.clone(),
    };

    let mut relay_config = RelayConfig::new(relay_bind);
    relay_config.access = Arc::new(access);
    let mut server_config = ServerConfig::default();
    server_config.relay = Some(relay_config);
    let mut relay = Server::spawn(server_config).await.context("start relay")?;
    let clients = relay
        .relay_service()
        .context("relay service missing")?
        .clients()
        .clone();

    let admin_state = AdminState {
        audience: audience.clone().into(),
        authority_id,
        state_path: Arc::new(state_path),
        current: Arc::new(Mutex::new(snapshot)),
        allowed,
        clients,
    };
    let app = Router::new()
        .route("/healthz", get(health))
        .route("/v1/status", get(status))
        .with_state(admin_state.clone());
    let listener = tokio::net::TcpListener::bind(admin_bind)
        .await
        .with_context(|| format!("bind admin API to {admin_bind}"))?;
    let actual_relay = relay.http_addr().unwrap_or(relay_bind);
    let actual_admin = listener.local_addr()?;
    println!("relay=http://{actual_relay}");
    println!("admin=http://{actual_admin}");
    println!("audience={audience}");
    use std::io::Write;
    std::io::stdout().flush().context("flush startup metadata")?;
    info!(relay = %actual_relay, admin = %actual_admin, "private relay started");

    let admin = tokio::spawn(async move { axum::serve(listener, app).await });
    let state = admin_state.clone();
    let poll_state_dir = state_dir.clone();
    let control_poll = tokio::spawn(async move { poll_control(profile, poll_state_dir, state).await });
    tokio::select! {
        result = relay.join() => {
            admin.abort();
            result.context("relay supervisor task")?.context("relay supervisor")?;
        }
        _ = tokio::signal::ctrl_c() => {
            admin.abort();
            relay.shutdown().await.context("stop relay")?;
        }
    }
    control_poll.abort();
    Ok(())
}

async fn join_from_file(join_file: PathBuf, control_url: Option<String>, state_dir: PathBuf) -> Result<()> {
    let join_url = tokio::fs::read_to_string(&join_file).await.with_context(|| {
        format!(
            "read {} (restore relay state or provide a fresh Relay invitation)",
            join_file.display()
        )
    })?;
    let join_url = join_url.trim().to_owned();
    anyhow::ensure!(!join_url.is_empty(), "Relay invitation file is empty");
    let mut backoff = 1u64;
    loop {
        match join_control(join_url.clone(), control_url.clone(), Some(state_dir.clone())).await {
            Ok(()) => return Ok(()),
            Err(error) if error.chain().any(|cause| cause.is::<reqwest::Error>()) => {
                warn!(%error, "Control unavailable during Relay enrollment; retrying");
            }
            Err(error) => return Err(error),
        }
        tokio::time::sleep(Duration::from_secs(backoff)).await;
        backoff = (backoff * 2).min(30);
    }
}

fn default_state_dir() -> PathBuf {
    std::env::var_os("AGENT_SCALE_RELAY_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::home_dir().map(|home| home.join(".agent-scale-relay")))
        .unwrap_or_else(|| PathBuf::from(".agent-scale-relay"))
}

async fn load_or_initialize(path: &Path, audience: &str) -> Result<MembershipSnapshot> {
    match tokio::fs::read(path).await {
        Ok(data) => serde_json::from_slice(&data).with_context(|| format!("parse {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let snapshot = MembershipSnapshot {
                protocol_version: RELAY_PROTOCOL_VERSION,
                audience: audience.into(),
                version: 0,
                issued_at: unix_timestamp(),
                members: Vec::new(),
            };
            persist_snapshot(path, &snapshot).await?;
            Ok(snapshot)
        }
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

fn validate_snapshot(snapshot: &MembershipSnapshot, audience: &str) -> Result<HashSet<EndpointId>> {
    anyhow::ensure!(snapshot.audience == audience, "snapshot audience mismatch");
    let ids: HashSet<_> = snapshot.endpoint_ids()?.into_iter().collect();
    anyhow::ensure!(
        ids.len() == snapshot.members.len(),
        "snapshot contains duplicate endpoint ids"
    );
    Ok(ids)
}

async fn persist_snapshot(path: &Path, snapshot: &MembershipSnapshot) -> Result<()> {
    let data = serde_json::to_vec_pretty(snapshot)?;
    let tmp = path.with_extension("json.tmp");
    let mut file = tokio::fs::File::create(&tmp)
        .await
        .with_context(|| format!("create {}", tmp.display()))?;
    use tokio::io::AsyncWriteExt;
    file.write_all(&data).await?;
    file.sync_all().await?;
    drop(file);
    tokio::fs::rename(&tmp, path)
        .await
        .with_context(|| format!("replace {}", path.display()))?;
    Ok(())
}

async fn health() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn status(State(state): State<AdminState>) -> Json<RelayStatus> {
    let snapshot = state.current.lock().await;
    Json(RelayStatus {
        audience: state.audience.to_string(),
        center_id: state.authority_id.to_string(),
        version: snapshot.version,
        members: snapshot.members.len(),
    })
}

async fn update_snapshot(
    State(state): State<AdminState>,
    Json(signed): Json<SignedSnapshot>,
) -> Result<Json<RelayStatus>, ApiError> {
    signed.verify(state.authority_id).map_err(ApiError::unauthorized)?;
    let next_ids = validate_snapshot(&signed.snapshot, &state.audience).map_err(ApiError::bad_request)?;
    let mut current = state.current.lock().await;

    if signed.snapshot.version < current.version {
        return Err(ApiError::conflict(format!(
            "snapshot version {} is older than current version {}",
            signed.snapshot.version, current.version
        )));
    }
    if signed.snapshot.version == current.version {
        if signed.snapshot == *current {
            return Ok(Json(relay_status(&state, &current)));
        }
        return Err(ApiError::conflict("snapshot version already has different content"));
    }
    let age = unix_timestamp().saturating_sub(signed.snapshot.issued_at).abs();
    if age > MAX_CLOCK_SKEW_SECS {
        return Err(ApiError::unauthorized(
            "snapshot timestamp is outside the 5 minute window",
        ));
    }

    persist_snapshot(&state.state_path, &signed.snapshot)
        .await
        .map_err(ApiError::internal)?;
    let old_ids = state.allowed.load_full();
    state.allowed.store(Arc::new(next_ids.clone()));
    for removed in old_ids.difference(&next_ids) {
        if state.clients.disconnect(*removed, None) {
            info!(endpoint_id = %removed, "disconnected revoked relay client");
        }
    }
    *current = signed.snapshot;
    Ok(Json(relay_status(&state, &current)))
}

fn relay_status(state: &AdminState, snapshot: &MembershipSnapshot) -> RelayStatus {
    RelayStatus {
        audience: state.audience.to_string(),
        center_id: state.authority_id.to_string(),
        version: snapshot.version,
        members: snapshot.members.len(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ControlProfile {
    schema_version: u32,
    name: String,
    control_url: String,
    control_id: String,
    audience: String,
    endpoint_id: String,
}

async fn join_control(join_url: String, control_url: Option<String>, state_dir: Option<PathBuf>) -> Result<()> {
    let state_dir = state_dir.unwrap_or_else(default_state_dir);
    tokio::fs::create_dir_all(&state_dir).await?;
    anyhow::ensure!(
        !profile_path(&state_dir).exists(),
        "relay is already enrolled in control"
    );
    let parsed = reqwest::Url::parse(&join_url).context("invalid join URL")?;
    let fragment = parsed.fragment().context("join URL is missing its token fragment")?;
    let token = JoinToken::decode(fragment)?;
    let control_id = token.verify()?;
    let (name, audience, public_control_url) = match &token.invite.kind {
        InviteKind::Relay { .. } => (
            token.invite.name.clone(),
            token.invite.audience.clone(),
            token.invite.control_url.clone(),
        ),
        _ => anyhow::bail!("this invitation is not for a relay"),
    };
    let control_url = control_url.unwrap_or(public_control_url);
    reqwest::Url::parse(&control_url).context("invalid Control connection URL")?;
    let key = load_or_create_relay_key(&state_dir)?;
    let request = ClaimRequest::sign(token, &key, unix_timestamp(), random_nonce())?;
    let url = api_url(&control_url, "v1/claim")?;
    let response = http_client()
        .post(url)
        .json(&request)
        .send()
        .await
        .context("claim relay invitation")?;
    let status = response.status();
    let body = response.bytes().await?;
    anyhow::ensure!(
        status.is_success(),
        "control rejected relay claim ({status}): {}",
        String::from_utf8_lossy(&body)
    );
    let joined: JoinResult = serde_json::from_slice(&body).context("decode join response")?;
    joined.map.verify(control_id, key.public())?;
    let profile = ControlProfile {
        schema_version: 1,
        name,
        control_url,
        control_id: control_id.to_string(),
        audience,
        endpoint_id: key.public().to_string(),
    };
    persist_json(&profile_path(&state_dir), &profile).await?;
    println!("enrolled relay '{}' ({})", profile.name, profile.endpoint_id);
    println!("next: as-relay run --state-dir {}", state_dir.display());
    Ok(())
}

async fn poll_control(profile: ControlProfile, state_dir: PathBuf, state: AdminState) {
    let key = match load_or_create_relay_key(&state_dir) {
        Ok(key) => key,
        Err(error) => {
            warn!("cannot load relay control identity: {error:#}");
            return;
        }
    };
    if key.public().to_string() != profile.endpoint_id {
        warn!("relay key does not match control profile");
        return;
    }
    let control_id: EndpointId = match profile.control_id.parse() {
        Ok(id) => id,
        Err(error) => {
            warn!("invalid control identity in relay profile: {error}");
            return;
        }
    };
    let url = match api_url(&profile.control_url, "v1/relay/watch") {
        Ok(url) => url,
        Err(error) => {
            warn!("invalid relay control URL: {error:#}");
            return;
        }
    };
    let client = http_client();
    let mut backoff = 1u64;
    loop {
        let known_revision = state.current.lock().await.version;
        let request = match WatchRequest::sign(&key, known_revision, unix_timestamp(), random_nonce()) {
            Ok(request) => request,
            Err(error) => {
                warn!("cannot sign relay watch: {error:#}");
                return;
            }
        };
        match client.post(url.clone()).json(&request).send().await {
            Ok(response) if response.status().is_success() => match response.json::<SignedSnapshot>().await {
                Ok(signed) => {
                    let valid = signed
                        .verify(control_id)
                        .and_then(|()| validate_snapshot(&signed.snapshot, &profile.audience).map(|_| ()));
                    if let Err(error) = valid {
                        warn!("control returned invalid relay membership: {error:#}");
                    } else if let Err(error) = update_snapshot(State(state.clone()), Json(signed)).await {
                        warn!("cannot apply control membership: {}", error.message);
                    } else {
                        backoff = 1;
                        continue;
                    }
                }
                Err(error) => warn!("cannot decode relay membership: {error}"),
            },
            Ok(response) if response.status() == StatusCode::FORBIDDEN || response.status() == StatusCode::GONE => {
                warn!("relay enrollment was revoked; disconnecting all clients");
                revoke_all(&state).await;
                return;
            }
            Ok(response) => warn!(status = %response.status(), "relay control watch failed"),
            Err(error) => warn!("relay control unavailable: {error}"),
        }
        tokio::time::sleep(Duration::from_secs(backoff)).await;
        backoff = (backoff * 2).min(60);
    }
}

async fn revoke_all(state: &AdminState) {
    let old = state.allowed.load_full();
    state.allowed.store(Arc::new(HashSet::new()));
    for endpoint_id in old.iter() {
        state.clients.disconnect(*endpoint_id, None);
    }
}

fn load_profile(state_dir: &Path) -> Result<ControlProfile> {
    let path = profile_path(state_dir);
    let profile: ControlProfile = serde_json::from_slice(
        &std::fs::read(&path).with_context(|| format!("read {} (run `as-relay join` first)", path.display()))?,
    )
    .with_context(|| format!("parse {}", path.display()))?;
    anyhow::ensure!(profile.schema_version == 1, "unsupported relay profile schema");
    Ok(profile)
}

fn load_or_create_relay_key(state_dir: &Path) -> Result<SecretKey> {
    scale_core::load_or_create_secret(&state_dir.join("relay.key"))
}

async fn persist_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let path = path.to_owned();
    let mut data = serde_json::to_vec_pretty(value)?;
    data.push(b'\n');
    tokio::task::spawn_blocking(move || scale_core::atomic_write(&path, &data))
        .await
        .context("join relay state writer")??;
    Ok(())
}

fn profile_path(state_dir: &Path) -> PathBuf {
    state_dir.join("control.json")
}

fn api_url(base: &str, path: &str) -> Result<reqwest::Url> {
    reqwest::Url::parse(&format!("{}/", base.trim_end_matches('/')))?
        .join(path)
        .context("build control API URL")
}

fn http_client() -> reqwest::Client {
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::new()
}

fn random_nonce() -> String {
    use base64::Engine;
    use rand::Rng;
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
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
    fn run_accepts_first_start_enrollment_file() {
        let cli = Cli::try_parse_from([
            "as-relay",
            "run",
            "--join-if-needed",
            "/bootstrap/relay.join",
            "--control-url",
            "http://control:3350",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Run {
                join_if_needed: Some(_),
                ..
            }
        ));
    }

    #[test]
    fn validation_requires_unique_members() {
        let center = iroh_base::SecretKey::generate().public();
        let edge = iroh_base::SecretKey::generate().public();
        let mut snapshot = MembershipSnapshot {
            protocol_version: RELAY_PROTOCOL_VERSION,
            audience: "test".into(),
            version: 1,
            issued_at: unix_timestamp(),
            members: vec![relay_api::RelayMember {
                name: "edge".into(),
                endpoint_id: edge.to_string(),
            }],
        };
        assert!(validate_snapshot(&snapshot, "test").is_ok());
        snapshot.members.push(relay_api::RelayMember {
            name: "center".into(),
            endpoint_id: center.to_string(),
        });
        assert!(validate_snapshot(&snapshot, "test").is_ok());
        snapshot.members.push(relay_api::RelayMember {
            name: "duplicate".into(),
            endpoint_id: edge.to_string(),
        });
        assert!(validate_snapshot(&snapshot, "test").is_err());
    }

    #[tokio::test]
    async fn signed_updates_are_monotonic_and_durable() {
        let center_key = iroh_base::SecretKey::generate();
        let center_id = center_key.public();
        let initial = MembershipSnapshot {
            protocol_version: RELAY_PROTOCOL_VERSION,
            audience: "test".into(),
            version: 0,
            issued_at: unix_timestamp(),
            members: vec![relay_api::RelayMember {
                name: "center".into(),
                endpoint_id: center_id.to_string(),
            }],
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("membership.json");
        persist_snapshot(&path, &initial).await.unwrap();
        let allowed = Arc::new(ArcSwap::from_pointee(validate_snapshot(&initial, "test").unwrap()));
        let state = AdminState {
            audience: Arc::from("test"),
            authority_id: center_id,
            state_path: Arc::new(path.clone()),
            current: Arc::new(Mutex::new(initial)),
            allowed,
            clients: Clients::default(),
        };
        let edge_id = iroh_base::SecretKey::generate().public();
        let next = MembershipSnapshot {
            protocol_version: RELAY_PROTOCOL_VERSION,
            audience: "test".into(),
            version: 1,
            issued_at: unix_timestamp(),
            members: vec![
                relay_api::RelayMember {
                    name: "center".into(),
                    endpoint_id: center_id.to_string(),
                },
                relay_api::RelayMember {
                    name: "edge".into(),
                    endpoint_id: edge_id.to_string(),
                },
            ],
        };
        let signed = SignedSnapshot::sign(next.clone(), &center_key).unwrap();
        let applied = update_snapshot(State(state.clone()), Json(signed.clone()))
            .await
            .unwrap();
        assert_eq!(applied.0.version, 1);
        assert!(state.allowed.load().contains(&edge_id));
        let persisted: MembershipSnapshot = serde_json::from_slice(&tokio::fs::read(path).await.unwrap()).unwrap();
        assert_eq!(persisted, next);

        // Exact retries are idempotent, but a different payload at the same
        // version cannot overwrite durable state.
        let _ = update_snapshot(State(state.clone()), Json(signed)).await.unwrap();
        let mut conflicting = next;
        conflicting.members.pop();
        let conflict = SignedSnapshot::sign(conflicting, &center_key).unwrap();
        let error = update_snapshot(State(state), Json(conflict)).await.unwrap_err();
        assert_eq!(error.status, StatusCode::CONFLICT);
    }
}
