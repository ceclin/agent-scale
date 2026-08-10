//! Verifies Control-signed admission credentials locally and pulls only revocations.

use std::{
    collections::HashMap,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
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
use iroh_relay::server::{
    Access, AccessControl, ClientRequest, QuicConfig, RelayConfig, Server, ServerConfig, clients::Clients,
};
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose};
use relay_api::{RELAY_PROTOCOL_VERSION, RelayStatus, RevocationUpdate, SignedRelayCredential, SignedRevocationUpdate};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

const MAX_CLOCK_SKEW_SECS: i64 = 300;
const DEFAULT_QAD_PORT: u16 = 7842;
const CONTROL_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const CONTROL_WATCH_TIMEOUT: Duration = Duration::from_secs(90);
type RevocationIndex = HashMap<EndpointId, (u64, i64)>;

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
        /// Public QAD UDP port to advertise through Control (default: 7842).
        #[arg(long)]
        qad_port: Option<u16>,
        /// Enroll this Relay without QAD.
        #[arg(long)]
        no_qad: bool,
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
        /// Local UDP bind address for QAD.
        #[arg(long, default_value = "[::]:7842")]
        qad_bind: SocketAddr,
        /// Public QAD UDP port to advertise during enrollment (default: --qad-bind's port).
        #[arg(long)]
        qad_port: Option<u16>,
        /// Enroll without QAD, or require an existing QAD-disabled profile.
        #[arg(long)]
        no_qad: bool,
        /// Directory containing durable Relay state.
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

struct RunOptions {
    relay_bind: SocketAddr,
    admin_bind: SocketAddr,
    qad_bind: SocketAddr,
    qad_port: Option<u16>,
    no_qad: bool,
    state_dir: Option<PathBuf>,
    join_if_needed: Option<PathBuf>,
    control_url: Option<String>,
}

#[derive(Debug, Clone)]
struct DynamicAccess {
    audience: Arc<str>,
    authority_id: EndpointId,
    revoked: Arc<ArcSwap<RevocationIndex>>,
    enrollment_revoked: Arc<AtomicBool>,
}

impl AccessControl for DynamicAccess {
    async fn on_connect(&self, request: &ClientRequest) -> Access {
        let endpoint_id = request.endpoint_id();
        if self.enrollment_revoked.load(Ordering::Acquire) {
            return Access::Deny {
                reason: Some("Relay enrollment is revoked".into()),
            };
        }
        match validate_credential(
            request.auth_token().as_deref(),
            endpoint_id,
            self.authority_id,
            &self.audience,
            &self.revoked.load(),
            unix_timestamp(),
        ) {
            Ok(()) => Access::Allow,
            Err(error) => {
                warn!(%endpoint_id, %error, "denied relay access");
                Access::Deny {
                    reason: Some("endpoint is not authorized".into()),
                }
            }
        }
    }
}

fn validate_credential(
    token: Option<&str>,
    endpoint_id: EndpointId,
    authority_id: EndpointId,
    audience: &str,
    revoked: &RevocationIndex,
    now: i64,
) -> Result<()> {
    let token = token.context("missing Relay credential")?;
    let signed = SignedRelayCredential::decode(token)?;
    signed.verify(authority_id)?;
    signed.credential.validate()?;
    anyhow::ensure!(signed.credential.audience == audience, "credential audience mismatch");
    anyhow::ensure!(
        signed.credential.endpoint_id()? == endpoint_id,
        "credential endpoint mismatch"
    );
    anyhow::ensure!(
        signed.credential.issued_at <= now.saturating_add(MAX_CLOCK_SKEW_SECS),
        "credential is not valid yet"
    );
    anyhow::ensure!(signed.credential.expires_at > now, "credential expired");
    let revoked_through = revoked
        .get(&endpoint_id)
        .filter(|(_, expires_at)| *expires_at > now)
        .map(|(generation, _)| *generation)
        .unwrap_or(0);
    anyhow::ensure!(signed.credential.generation > revoked_through, "credential was revoked");
    Ok(())
}

#[derive(Clone)]
struct AdminState {
    audience: Arc<str>,
    authority_id: EndpointId,
    state_path: Arc<PathBuf>,
    current: Arc<Mutex<RevocationUpdate>>,
    revoked: Arc<ArcSwap<RevocationIndex>>,
    clients: Clients,
    enrollment_revoked: Arc<AtomicBool>,
    enrollment_revoked_path: Arc<PathBuf>,
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
            qad_port,
            no_qad,
            state_dir,
        } => {
            join_control(
                join_url,
                control_url,
                state_dir,
                requested_qad_port(qad_port, no_qad, DEFAULT_QAD_PORT)?,
            )
            .await
        }
        Command::Run {
            relay_bind,
            admin_bind,
            qad_bind,
            qad_port,
            no_qad,
            state_dir,
            join_if_needed,
            control_url,
        } => {
            run(RunOptions {
                relay_bind,
                admin_bind,
                qad_bind,
                qad_port,
                no_qad,
                state_dir,
                join_if_needed,
                control_url,
            })
            .await
        }
    }
}

async fn run(options: RunOptions) -> Result<()> {
    let RunOptions {
        relay_bind,
        admin_bind,
        qad_bind,
        qad_port,
        no_qad,
        state_dir,
        join_if_needed,
        control_url,
    } = options;
    let state_dir = state_dir.unwrap_or_else(default_state_dir);
    tokio::fs::create_dir_all(&state_dir)
        .await
        .with_context(|| format!("create {}", state_dir.display()))?;
    if !profile_path(&state_dir).exists()
        && let Some(join_file) = join_if_needed
    {
        join_from_file(
            join_file,
            control_url,
            state_dir.clone(),
            requested_qad_port(qad_port, no_qad, qad_bind.port())?,
        )
        .await?;
    }
    let mut profile = load_profile(&state_dir)?;
    if no_qad {
        anyhow::ensure!(
            profile.qad_port.is_none(),
            "--no-qad cannot disable QAD after enrollment"
        );
    }
    if let Some(qad_port) = qad_port {
        let requested = requested_qad_port(Some(qad_port), false, qad_bind.port())?;
        anyhow::ensure!(
            profile.qad_port.is_some(),
            "--qad-port cannot enable QAD after a QAD-disabled enrollment"
        );
        if profile.qad_port != requested {
            profile.qad_port = requested;
            persist_json(&profile_path(&state_dir), &profile).await?;
            info!(
                public_port = qad_port,
                "updated public QAD port; reporting it to Control"
            );
        }
    }
    let authority_id = profile.control_id.parse().context("invalid profile control id")?;
    let audience = profile.audience.clone();
    anyhow::ensure!(!audience.trim().is_empty(), "audience must not be empty");
    let state_path = state_dir.join("revocations.json");
    let enrollment_revoked_path = state_dir.join("enrollment-revoked");
    anyhow::ensure!(
        !enrollment_revoked_path.exists(),
        "Relay enrollment was revoked; remove this state directory and enroll a new Relay identity"
    );
    let revocation_state = load_or_initialize(&state_path, &audience).await?;
    let revocations = validate_revocations(&revocation_state, &audience)?;
    let revoked = Arc::new(ArcSwap::from_pointee(revocations));
    let enrollment_revoked = Arc::new(AtomicBool::new(false));
    let access = DynamicAccess {
        audience: audience.clone().into(),
        authority_id,
        revoked: revoked.clone(),
        enrollment_revoked: enrollment_revoked.clone(),
    };

    let mut relay_config = RelayConfig::new(relay_bind);
    relay_config.access = Arc::new(access);
    let mut server_config = ServerConfig::default();
    server_config.relay = Some(relay_config);
    server_config.quic = managed_qad_config(&profile, &state_dir, qad_bind)?;
    if let Some(public_port) = profile.qad_port {
        info!(bind = %qad_bind, public_port, "QAD enabled");
    }
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
        current: Arc::new(Mutex::new(revocation_state)),
        revoked,
        clients,
        enrollment_revoked,
        enrollment_revoked_path: Arc::new(enrollment_revoked_path),
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
    if let Some(public_port) = profile.qad_port {
        println!("qad=udp://{qad_bind} (public port {public_port})");
    }
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

fn managed_qad_config(profile: &ControlProfile, state_dir: &Path, qad_bind: SocketAddr) -> Result<Option<QuicConfig>> {
    let Some(_public_port) = profile.qad_port else {
        return Ok(None);
    };
    anyhow::ensure!(
        !profile.qad_certificate_der.is_empty(),
        "managed QAD TLS certificate is empty"
    );
    anyhow::ensure!(
        !profile.relay_ca_der.is_empty(),
        "managed Relay CA certificate is empty"
    );
    let key_der = std::fs::read(qad_key_path(state_dir)).context("read managed QAD TLS key")?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(
            vec![
                rustls::pki_types::CertificateDer::from(profile.qad_certificate_der.clone()),
                rustls::pki_types::CertificateDer::from(profile.relay_ca_der.clone()),
            ],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key_der).into(),
        )
        .context("configure managed QAD TLS certificate")?;
    let mut quic = QuicConfig::new(qad_bind);
    quic.server_config = Some(tls);
    Ok(Some(quic))
}

async fn join_from_file(
    join_file: PathBuf,
    control_url: Option<String>,
    state_dir: PathBuf,
    qad_port: Option<u16>,
) -> Result<()> {
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
        match join_control(join_url.clone(), control_url.clone(), Some(state_dir.clone()), qad_port).await {
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

fn requested_qad_port(port: Option<u16>, disabled: bool, default_port: u16) -> Result<Option<u16>> {
    anyhow::ensure!(
        !(disabled && port.is_some()),
        "--no-qad cannot be combined with --qad-port"
    );
    if disabled {
        return Ok(None);
    }
    let port = port.unwrap_or(default_port);
    anyhow::ensure!(port != 0, "--qad-port must be between 1 and 65535");
    Ok(Some(port))
}

async fn load_or_initialize(path: &Path, audience: &str) -> Result<RevocationUpdate> {
    match tokio::fs::read(path).await {
        Ok(data) => serde_json::from_slice(&data).with_context(|| format!("parse {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let state = RevocationUpdate {
                protocol_version: RELAY_PROTOCOL_VERSION,
                audience: audience.into(),
                version: 0,
                issued_at: unix_timestamp(),
                revocations: Vec::new(),
            };
            persist_revocation_state(path, &state).await?;
            Ok(state)
        }
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

fn validate_revocations(update: &RevocationUpdate, audience: &str) -> Result<RevocationIndex> {
    update.validate()?;
    anyhow::ensure!(update.audience == audience, "revocation audience mismatch");
    let entries = update.entries()?;
    let ids: RevocationIndex = update
        .revocations
        .iter()
        .zip(entries)
        .map(|(revocation, (endpoint_id, generation))| (endpoint_id, (generation, revocation.expires_at)))
        .collect();
    anyhow::ensure!(
        ids.len() == update.revocations.len(),
        "revocation update contains duplicate endpoint ids"
    );
    Ok(ids)
}

async fn persist_revocation_state(path: &Path, state: &RevocationUpdate) -> Result<()> {
    let data = serde_json::to_vec_pretty(state)?;
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
    let current = state.current.lock().await;
    Json(RelayStatus {
        audience: state.audience.to_string(),
        control_id: state.authority_id.to_string(),
        version: current.version,
        revocations: current.revocations.len(),
    })
}

async fn apply_revocation_update(
    State(state): State<AdminState>,
    Json(signed): Json<SignedRevocationUpdate>,
) -> Result<Json<RelayStatus>, ApiError> {
    signed.verify(state.authority_id).map_err(ApiError::unauthorized)?;
    let delta = validate_revocations(&signed.update, &state.audience).map_err(ApiError::bad_request)?;
    let mut current = state.current.lock().await;

    if signed.update.version < current.version {
        return Err(ApiError::conflict(format!(
            "revocation version {} is older than current version {}",
            signed.update.version, current.version
        )));
    }
    if signed.update.version == current.version {
        let already_applied = signed
            .update
            .revocations
            .iter()
            .all(|revocation| current.revocations.iter().any(|existing| existing == revocation));
        if already_applied {
            let now = unix_timestamp();
            if current
                .revocations
                .iter()
                .any(|revocation| revocation.expires_at <= now)
            {
                let mut pruned = current.clone();
                pruned.revocations.retain(|revocation| revocation.expires_at > now);
                let active = validate_revocations(&pruned, &state.audience).map_err(ApiError::bad_request)?;
                persist_revocation_state(&state.state_path, &pruned)
                    .await
                    .map_err(ApiError::internal)?;
                state.revoked.store(Arc::new(active));
                *current = pruned;
            }
            return Ok(Json(relay_status(&state, &current)));
        }
        return Err(ApiError::conflict("revocation version already has different content"));
    }
    let age = unix_timestamp().saturating_sub(signed.update.issued_at).abs();
    if age > MAX_CLOCK_SKEW_SECS {
        return Err(ApiError::unauthorized(
            "revocation timestamp is outside the 5 minute window",
        ));
    }

    if signed
        .update
        .revocations
        .iter()
        .any(|revocation| revocation.revision <= current.version)
    {
        return Err(ApiError::conflict("revocation update overlaps the applied revision"));
    }

    let now = unix_timestamp();
    let mut merged: HashMap<EndpointId, relay_api::Revocation> = current
        .revocations
        .iter()
        .filter(|revocation| revocation.expires_at > now)
        .filter_map(|revocation| revocation.endpoint_id.parse().ok().map(|id| (id, revocation.clone())))
        .collect();
    for revocation in &signed.update.revocations {
        let endpoint_id = revocation.endpoint_id.parse().map_err(ApiError::bad_request)?;
        if let Some(existing) = merged.get(&endpoint_id)
            && revocation.revoked_through_generation < existing.revoked_through_generation
        {
            return Err(ApiError::conflict("revocation generation moved backwards"));
        }
        merged.insert(endpoint_id, revocation.clone());
    }
    let mut revocations: Vec<_> = merged.into_values().collect();
    revocations.sort_by(|a, b| a.endpoint_id.cmp(&b.endpoint_id));
    let accumulated = RevocationUpdate {
        protocol_version: RELAY_PROTOCOL_VERSION,
        audience: signed.update.audience.clone(),
        version: signed.update.version,
        issued_at: signed.update.issued_at,
        revocations,
    };
    let next_revocations = validate_revocations(&accumulated, &state.audience).map_err(ApiError::bad_request)?;
    persist_revocation_state(&state.state_path, &accumulated)
        .await
        .map_err(ApiError::internal)?;
    let old_revocations = state.revoked.load_full();
    state.revoked.store(Arc::new(next_revocations.clone()));
    for (endpoint_id, (generation, expires_at)) in delta {
        let old_generation = old_revocations
            .get(&endpoint_id)
            .filter(|(_, old_expires_at)| *old_expires_at > now)
            .map(|(generation, _)| *generation)
            .unwrap_or(0);
        if expires_at > now && old_generation < generation && state.clients.disconnect(endpoint_id, None) {
            info!(%endpoint_id, "disconnected revoked relay client");
        }
    }
    *current = accumulated;
    Ok(Json(relay_status(&state, &current)))
}

fn relay_status(state: &AdminState, current: &RevocationUpdate) -> RelayStatus {
    RelayStatus {
        audience: state.audience.to_string(),
        control_id: state.authority_id.to_string(),
        version: current.version,
        revocations: current.revocations.len(),
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
    relay_url: String,
    qad_port: Option<u16>,
    relay_ca_der: Vec<u8>,
    qad_certificate_der: Vec<u8>,
}

async fn join_control(
    join_url: String,
    control_url: Option<String>,
    state_dir: Option<PathBuf>,
    qad_port: Option<u16>,
) -> Result<()> {
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
    let (name, audience, public_control_url, relay_url) = match &token.invite.kind {
        InviteKind::Relay { url } => (
            token.invite.name.clone(),
            token.invite.audience.clone(),
            token.invite.control_url.clone(),
            url.clone(),
        ),
        _ => anyhow::bail!("this invitation is not for a relay"),
    };
    let control_url = control_url.unwrap_or(public_control_url);
    reqwest::Url::parse(&control_url).context("invalid Control connection URL")?;
    let key = load_or_create_relay_key(&state_dir)?;
    let (qad_key, csr_der) = if qad_port.is_some() {
        let host = reqwest::Url::parse(&relay_url)?
            .host_str()
            .context("Relay URL has no host")?
            .to_owned();
        let qad_key = KeyPair::generate().context("generate QAD TLS key")?;
        let mut params = CertificateParams::new(vec![host])?;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let csr = params.serialize_request(&qad_key).context("create QAD TLS CSR")?;
        (Some(qad_key), Some(csr.der().to_vec()))
    } else {
        (None, None)
    };
    let request = ClaimRequest::sign_with_relay_qad(token, &key, unix_timestamp(), random_nonce(), qad_port, csr_der)?;
    let url = api_url(&control_url, "v1/claim")?;
    let response = send_control(http_client()?.post(url).json(&request), CONTROL_REQUEST_TIMEOUT)
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
    let qad_certificate_der = match qad_port {
        Some(_) => joined
            .relay_tls_certificate_der
            .context("Control omitted the managed QAD TLS certificate")?,
        None => Vec::new(),
    };
    if let Some(qad_key) = qad_key {
        let key_der = qad_key.serialize_der();
        tokio::task::spawn_blocking({
            let path = qad_key_path(&state_dir);
            move || scale_core::atomic_write(&path, &key_der)
        })
        .await
        .context("join QAD key writer")??;
    }
    let profile = ControlProfile {
        schema_version: 2,
        name,
        control_url,
        control_id: control_id.to_string(),
        audience,
        endpoint_id: key.public().to_string(),
        relay_url,
        qad_port,
        relay_ca_der: joined.map.map.relay_ca_der,
        qad_certificate_der,
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
    let client = match http_client() {
        Ok(client) => client,
        Err(error) => {
            warn!("cannot build Control HTTP client: {error:#}");
            return;
        }
    };
    let mut backoff = 1u64;
    loop {
        let known_revision = state.current.lock().await.version;
        let request =
            match WatchRequest::sign_relay(&key, known_revision, unix_timestamp(), random_nonce(), profile.qad_port) {
                Ok(request) => request,
                Err(error) => {
                    warn!("cannot sign relay watch: {error:#}");
                    return;
                }
            };
        match send_control(client.post(url.clone()).json(&request), CONTROL_WATCH_TIMEOUT).await {
            Ok(response) if response.status() == StatusCode::NO_CONTENT => {
                backoff = 1;
                continue;
            }
            Ok(response) if response.status().is_success() => match response.json::<SignedRevocationUpdate>().await {
                Ok(signed) => {
                    let valid = signed
                        .verify(control_id)
                        .and_then(|()| validate_revocations(&signed.update, &profile.audience).map(|_| ()));
                    if let Err(error) = valid {
                        warn!("control returned invalid Relay revocations: {error:#}");
                    } else if let Err(error) = apply_revocation_update(State(state.clone()), Json(signed)).await {
                        warn!("cannot apply Control revocations: {}", error.message);
                    } else {
                        backoff = 1;
                        continue;
                    }
                }
                Err(error) => warn!("cannot decode Relay revocations: {error}"),
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
    state.enrollment_revoked.store(true, Ordering::Release);
    let path = state.enrollment_revoked_path.clone();
    if let Err(error) = tokio::task::spawn_blocking(move || scale_core::atomic_write(path.as_path(), b"revoked\n"))
        .await
        .context("join Relay revocation marker writer")
        .and_then(|result| result)
    {
        warn!(%error, "cannot persist Relay enrollment revocation");
    }
    state.clients.shutdown().await;
}

fn load_profile(state_dir: &Path) -> Result<ControlProfile> {
    let path = profile_path(state_dir);
    let profile: ControlProfile = serde_json::from_slice(
        &std::fs::read(&path).with_context(|| format!("read {} (run `as-relay join` first)", path.display()))?,
    )
    .with_context(|| format!("parse {}", path.display()))?;
    anyhow::ensure!(profile.schema_version == 2, "unsupported relay profile schema");
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

fn qad_key_path(state_dir: &Path) -> PathBuf {
    state_dir.join("qad.key")
}

fn api_url(base: &str, path: &str) -> Result<reqwest::Url> {
    reqwest::Url::parse(&format!("{}/", base.trim_end_matches('/')))?
        .join(path)
        .context("build control API URL")
}

fn http_client() -> Result<reqwest::Client> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .build()
        .context("build Control HTTP client")
}

async fn send_control(request: reqwest::RequestBuilder, timeout: Duration) -> Result<reqwest::Response> {
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
    use rcgen::{BasicConstraints, IsCa, Issuer};

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
    fn run_accepts_non_default_qad_bind_port() {
        let cli = Cli::try_parse_from(["as-relay", "run", "--qad-bind", "0.0.0.0:49152"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Run { qad_bind, .. } if qad_bind.port() == 49152
        ));
    }

    #[test]
    fn qad_is_enabled_by_default_and_can_be_overridden_or_disabled() {
        assert_eq!(
            requested_qad_port(None, false, DEFAULT_QAD_PORT).unwrap(),
            Some(DEFAULT_QAD_PORT)
        );
        assert_eq!(requested_qad_port(None, false, 49152).unwrap(), Some(49152));
        assert_eq!(requested_qad_port(Some(4433), false, 49152).unwrap(), Some(4433));
        assert_eq!(requested_qad_port(None, true, 49152).unwrap(), None);
        assert!(requested_qad_port(Some(4433), true, 49152).is_err());
        assert!(requested_qad_port(Some(0), false, 49152).is_err());
        assert!(requested_qad_port(None, false, 0).is_err());
    }

    #[tokio::test]
    async fn managed_qad_listener_starts_with_control_issued_chain() {
        let dir = tempfile::tempdir().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(ca_params, ca_key);

        let leaf_key = KeyPair::generate().unwrap();
        let mut leaf_params = CertificateParams::new(vec!["localhost".into()]).unwrap();
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf_cert = leaf_params.signed_by(&leaf_key, &issuer).unwrap();
        scale_core::atomic_write(&qad_key_path(dir.path()), &leaf_key.serialize_der()).unwrap();
        let profile = ControlProfile {
            schema_version: 2,
            name: "relay-a".into(),
            control_url: "http://127.0.0.1:3350".into(),
            control_id: SecretKey::generate().public().to_string(),
            audience: "test".into(),
            endpoint_id: SecretKey::generate().public().to_string(),
            relay_url: "http://localhost:3340/".into(),
            qad_port: Some(4433),
            relay_ca_der: ca_cert.der().to_vec(),
            qad_certificate_der: leaf_cert.der().to_vec(),
        };
        let mut config = ServerConfig::default();
        config.relay = Some(RelayConfig::new("127.0.0.1:0".parse::<SocketAddr>().unwrap()));
        config.quic = managed_qad_config(&profile, dir.path(), "127.0.0.1:0".parse::<SocketAddr>().unwrap()).unwrap();
        let server = Server::spawn(config).await.unwrap();
        assert_ne!(server.quic_addr().unwrap().port(), 0);
        server.shutdown().await.unwrap();
    }

    fn credential_token(control: &SecretKey, endpoint_id: EndpointId, generation: u64, expires_at: i64) -> String {
        SignedRelayCredential::sign(
            relay_api::RelayCredential {
                protocol_version: RELAY_PROTOCOL_VERSION,
                audience: "test".into(),
                control_id: control.public().to_string(),
                endpoint_id: endpoint_id.to_string(),
                kind: relay_api::RelaySubjectKind::Edge,
                generation,
                issued_at: 100,
                expires_at,
            },
            control,
        )
        .unwrap()
        .encode()
        .unwrap()
    }

    #[test]
    fn credentials_are_endpoint_bound_and_revocable() {
        let control = SecretKey::generate();
        let endpoint = SecretKey::generate().public();
        let other = SecretKey::generate().public();
        let token = credential_token(&control, endpoint, 3, 1_000);

        validate_credential(Some(&token), endpoint, control.public(), "test", &HashMap::new(), 200).unwrap();
        assert!(validate_credential(Some(&token), other, control.public(), "test", &HashMap::new(), 200,).is_err());
        assert!(
            validate_credential(
                Some(&token),
                endpoint,
                control.public(),
                "test",
                &HashMap::from([(endpoint, (3, 1_000))]),
                200,
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn signed_updates_are_monotonic_and_durable() {
        let control_key = iroh_base::SecretKey::generate();
        let control_id = control_key.public();
        let initial = RevocationUpdate {
            protocol_version: RELAY_PROTOCOL_VERSION,
            audience: "test".into(),
            version: 0,
            issued_at: unix_timestamp(),
            revocations: vec![],
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("revocations.json");
        persist_revocation_state(&path, &initial).await.unwrap();
        let revoked = Arc::new(ArcSwap::from_pointee(HashMap::new()));
        let state = AdminState {
            audience: Arc::from("test"),
            authority_id: control_id,
            state_path: Arc::new(path.clone()),
            current: Arc::new(Mutex::new(initial)),
            revoked,
            clients: Clients::default(),
            enrollment_revoked: Arc::new(AtomicBool::new(false)),
            enrollment_revoked_path: Arc::new(dir.path().join("enrollment-revoked")),
        };
        let edge_id = iroh_base::SecretKey::generate().public();
        let next = RevocationUpdate {
            protocol_version: RELAY_PROTOCOL_VERSION,
            audience: "test".into(),
            version: 1,
            issued_at: unix_timestamp(),
            revocations: vec![relay_api::Revocation {
                endpoint_id: edge_id.to_string(),
                revoked_through_generation: 4,
                expires_at: unix_timestamp() + 60,
                revision: 1,
            }],
        };
        let signed = SignedRevocationUpdate::sign(next.clone(), &control_key).unwrap();
        let applied = apply_revocation_update(State(state.clone()), Json(signed.clone()))
            .await
            .unwrap();
        assert_eq!(applied.0.version, 1);
        assert_eq!(state.revoked.load().get(&edge_id).map(|value| value.0), Some(4));
        let persisted: RevocationUpdate = serde_json::from_slice(&tokio::fs::read(path).await.unwrap()).unwrap();
        assert_eq!(persisted, next);

        let _ = apply_revocation_update(State(state.clone()), Json(signed))
            .await
            .unwrap();
        let mut conflicting = next;
        conflicting.revocations[0].revoked_through_generation = 5;
        let conflict = SignedRevocationUpdate::sign(conflicting, &control_key).unwrap();
        let error = apply_revocation_update(State(state.clone()), Json(conflict))
            .await
            .unwrap_err();
        assert_eq!(error.status, StatusCode::CONFLICT);

        let other_id = SecretKey::generate().public();
        let delta = RevocationUpdate {
            protocol_version: RELAY_PROTOCOL_VERSION,
            audience: "test".into(),
            version: 2,
            issued_at: unix_timestamp(),
            revocations: vec![relay_api::Revocation {
                endpoint_id: other_id.to_string(),
                revoked_through_generation: 1,
                expires_at: unix_timestamp() + 60,
                revision: 2,
            }],
        };
        let signed = SignedRevocationUpdate::sign(delta, &control_key).unwrap();
        let _ = apply_revocation_update(State(state.clone()), Json(signed))
            .await
            .unwrap();
        assert_eq!(state.current.lock().await.revocations.len(), 2);
    }
}
