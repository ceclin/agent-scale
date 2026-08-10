//! Serializes authorization changes through one signed revision stream; the
//! single-instance lock keeps SQLite state and in-memory snapshots coherent.

mod db;

use std::{
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Parser, Subcommand};
use control_api::{
    CONTROL_PROTOCOL_VERSION, ClaimRequest, ClientInfo, ControlStatus, EdgeInfo, EdgeInviteRequest, EdgeRemoveRequest,
    Invite, InviteInfo, InviteKind, InviteResult, JoinResult, JoinToken, ManagedClientInfo, ManagedEdgeInfo, NodeMap,
    Overview, ProvisionerAction, ProvisionerRequest, ProvisionerResponse, ProvisionerTopology, RelayInfo,
    RelayNodeInfo, SignedNodeMap, WatchRequest, action_hash, hash_secret, verify_provisioner_authorization,
};
use iroh_base::{EndpointId, SecretKey};
use rand::Rng;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use relay_api::{
    RELAY_PROTOCOL_VERSION, RelayCredential, RelaySubjectKind, Revocation, RevocationUpdate, SignedRelayCredential,
    SignedRevocationUpdate,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, Notify};
use tracing::info;
use tracing_subscriber::EnvFilter;
use url::Url;

const STATE_SCHEMA: u32 = 6;
const CLOCK_SKEW_SECS: i64 = 300;
const DEFAULT_TTL_SECS: u64 = 15 * 60;
const RELAY_CREDENTIAL_LIFETIME_SECS: i64 = 30 * 24 * 60 * 60;
const RELAY_CREDENTIAL_RENEW_BEFORE_SECS: i64 = 7 * 24 * 60 * 60;

#[derive(Parser)]
#[command(
    name = "as-control",
    about = "agent-scale multi-client control plane",
    after_help = "AS_CONTROL_STATE_DIR defaults to ~/.agent-scale-control; the administration \
                  socket is always $AS_CONTROL_STATE_DIR/admin.sock."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Initialize a new control identity and durable state.
    Init {
        #[arg(long)]
        public_url: String,
        #[arg(long)]
        audience: String,
    },
    /// Idempotently initialize a deployment and write its Relay enrollment invitation.
    Bootstrap {
        #[arg(long)]
        public_url: String,
        #[arg(long)]
        audience: String,
        #[arg(long)]
        relay_name: String,
        #[arg(long)]
        relay_url: String,
        #[arg(long, default_value_t = DEFAULT_TTL_SECS)]
        relay_ttl_secs: u64,
        #[arg(long)]
        relay_invite_out: PathBuf,
    },
    /// Run the public control API.
    Run {
        #[arg(long, default_value = "127.0.0.1:3350")]
        bind: SocketAddr,
    },
    /// Show all registered nodes and the current revision.
    Status,
    /// Manage clients through the local administration socket.
    Client {
        #[command(subcommand)]
        command: ClientCommand,
    },
    /// Manage edges through the local administration socket.
    Edge {
        #[command(subcommand)]
        command: EdgeCommand,
    },
    /// Manage relays through the local administration socket.
    Relay {
        #[command(subcommand)]
        command: RelayCommand,
    },
    /// Manage external topology reconcilers through the local administration socket.
    Provisioner {
        #[command(subcommand)]
        command: ProvisionerCommand,
    },
    /// Inspect or revoke enrollment invitations.
    Invite {
        #[command(subcommand)]
        command: InviteCommand,
    },
}

#[derive(Subcommand)]
enum ClientCommand {
    Invite {
        name: String,
        #[arg(long, default_value_t = DEFAULT_TTL_SECS)]
        ttl_secs: u64,
    },
    Ls,
    Rm {
        name: String,
    },
}

#[derive(Subcommand)]
enum EdgeCommand {
    Invite {
        name: String,
        #[arg(long)]
        owner: String,
        #[arg(long, default_value_t = DEFAULT_TTL_SECS)]
        ttl_secs: u64,
    },
    Ls,
    Transfer {
        edge: String,
        new_client: String,
    },
    Rm {
        edge: String,
    },
}

#[derive(Subcommand)]
enum RelayCommand {
    Invite {
        name: String,
        url: String,
        #[arg(long, default_value_t = DEFAULT_TTL_SECS)]
        ttl_secs: u64,
    },
    Ls,
    Rm {
        name: String,
    },
}

#[derive(Subcommand)]
enum ProvisionerCommand {
    Add { name: String, endpoint_id: String },
    Ls,
    Rm { name: String },
}

#[derive(Subcommand)]
enum InviteCommand {
    Ls,
    Revoke { invite_id: String },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
enum LocalAdminRequest {
    Overview,
    ListClients,
    ListEdges,
    ListRelays,
    ListInvites,
    ListProvisioners,
    InviteClient { name: String, ttl_secs: u64 },
    InviteEdge { name: String, owner: String, ttl_secs: u64 },
    InviteRelay { name: String, url: String, ttl_secs: u64 },
    RevokeInvite { invite_id: String },
    RemoveClient { name: String },
    TransferEdge { edge: String, new_client: String },
    RemoveEdge { edge: String },
    RemoveRelay { name: String },
    AddProvisioner { name: String, endpoint_id: String },
    RemoveProvisioner { name: String },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "result", content = "data", rename_all = "snake_case")]
enum LocalAdminResponse {
    Overview(Overview),
    Clients(Vec<ClientInfo>),
    Edges(Vec<EdgeInfo>),
    Relays(Vec<RelayNodeInfo>),
    Invites(Vec<InviteInfo>),
    Provisioners(Vec<ProvisionerInfo>),
    Invite(InviteResult),
    Ok,
    Error(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClientRecord {
    name: String,
    endpoint_id: String,
    managed_by: Option<String>,
    credential_generation: u64,
    credential_issued_at: i64,
    credential_expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EdgeRecord {
    name: String,
    endpoint_id: String,
    owner_id: String,
    credential_generation: u64,
    credential_issued_at: i64,
    credential_expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RelayRecord {
    name: String,
    endpoint_id: String,
    url: String,
    qad_port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RevocationRecord {
    endpoint_id: String,
    revoked_through_generation: u64,
    expires_at: i64,
    revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProvisionerRecord {
    name: String,
    endpoint_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProvisionerInfo {
    name: String,
    endpoint_id: String,
    clients: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InviteState {
    Pending,
    Claimed,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InviteRecord {
    invite: Invite,
    state: InviteState,
    claimed_by: Option<String>,
    request_id: Option<String>,
    managed_by: Option<String>,
    request_hash: Option<String>,
    terminal_at: Option<i64>,
}

#[derive(Debug, Clone)]
struct ControlState {
    schema: u32,
    audience: String,
    public_url: String,
    relay_ca_der: Vec<u8>,
    revision: u64,
    relay_revision: u64,
    clients: Vec<ClientRecord>,
    edges: Vec<EdgeRecord>,
    relays: Vec<RelayRecord>,
    invites: Vec<InviteRecord>,
    provisioners: Vec<ProvisionerRecord>,
    revocations: Vec<RevocationRecord>,
}

struct Store {
    database: db::Database,
    key: SecretKey,
    relay_ca: Issuer<'static, KeyPair>,
    state: Mutex<ControlState>,
    changed: Notify,
    relay_changed: Notify,
    _lock: scale_core::FileLock,
}

#[derive(Clone)]
struct AppState(Arc<Store>);

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, error: impl std::fmt::Display) -> Self {
        Self {
            status,
            message: error.to_string(),
        }
    }
    fn bad(error: impl std::fmt::Display) -> Self {
        Self::new(StatusCode::BAD_REQUEST, error)
    }
    fn unauthorized(error: impl std::fmt::Display) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, error)
    }
    fn forbidden(error: impl std::fmt::Display) -> Self {
        Self::new(StatusCode::FORBIDDEN, error)
    }
    fn conflict(error: impl std::fmt::Display) -> Self {
        Self::new(StatusCode::CONFLICT, error)
    }
    fn gone(error: impl std::fmt::Display) -> Self {
        Self::new(StatusCode::GONE, error)
    }
    fn internal(error: impl std::fmt::Display) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, error)
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
    let cli = Cli::parse();
    let state_dir = control_state_dir();
    let admin_socket = state_dir.join("admin.sock");
    match cli.command {
        Command::Init { public_url, audience } => init(state_dir, public_url, audience),
        Command::Bootstrap {
            public_url,
            audience,
            relay_name,
            relay_url,
            relay_ttl_secs,
            relay_invite_out,
        } => bootstrap(
            state_dir,
            public_url,
            audience,
            relay_name,
            relay_url,
            relay_ttl_secs,
            relay_invite_out,
        ),
        Command::Run { bind } => run(state_dir, bind, admin_socket).await,
        Command::Status => print_admin_response(admin_call(&admin_socket, LocalAdminRequest::Overview).await?),
        Command::Client { command } => {
            let request = match command {
                ClientCommand::Invite { name, ttl_secs } => LocalAdminRequest::InviteClient { name, ttl_secs },
                ClientCommand::Ls => LocalAdminRequest::ListClients,
                ClientCommand::Rm { name } => LocalAdminRequest::RemoveClient { name },
            };
            print_admin_response(admin_call(&admin_socket, request).await?)
        }
        Command::Edge { command } => {
            let request = match command {
                EdgeCommand::Invite { name, owner, ttl_secs } => {
                    LocalAdminRequest::InviteEdge { name, owner, ttl_secs }
                }
                EdgeCommand::Ls => LocalAdminRequest::ListEdges,
                EdgeCommand::Transfer { edge, new_client } => LocalAdminRequest::TransferEdge { edge, new_client },
                EdgeCommand::Rm { edge } => LocalAdminRequest::RemoveEdge { edge },
            };
            print_admin_response(admin_call(&admin_socket, request).await?)
        }
        Command::Relay { command } => {
            let request = match command {
                RelayCommand::Invite { name, url, ttl_secs } => LocalAdminRequest::InviteRelay { name, url, ttl_secs },
                RelayCommand::Ls => LocalAdminRequest::ListRelays,
                RelayCommand::Rm { name } => LocalAdminRequest::RemoveRelay { name },
            };
            print_admin_response(admin_call(&admin_socket, request).await?)
        }
        Command::Provisioner { command } => {
            let request = match command {
                ProvisionerCommand::Add { name, endpoint_id } => {
                    LocalAdminRequest::AddProvisioner { name, endpoint_id }
                }
                ProvisionerCommand::Ls => LocalAdminRequest::ListProvisioners,
                ProvisionerCommand::Rm { name } => LocalAdminRequest::RemoveProvisioner { name },
            };
            print_admin_response(admin_call(&admin_socket, request).await?)
        }
        Command::Invite { command } => {
            let request = match command {
                InviteCommand::Ls => LocalAdminRequest::ListInvites,
                InviteCommand::Revoke { invite_id } => LocalAdminRequest::RevokeInvite { invite_id },
            };
            print_admin_response(admin_call(&admin_socket, request).await?)
        }
    }
}

fn control_state_dir() -> PathBuf {
    std::env::var_os("AS_CONTROL_STATE_DIR")
        .map(PathBuf::from)
        .or_else(|| std::env::home_dir().map(|home| home.join(".agent-scale-control")))
        .unwrap_or_else(|| PathBuf::from(".agent-scale-control"))
}

fn init(dir: PathBuf, public_url: String, audience: String) -> Result<()> {
    anyhow::ensure!(!audience.trim().is_empty(), "--audience must not be empty");
    let public_url = normalize_public_url(&public_url)?;
    scale_core::ensure_private_dir(&dir)?;
    anyhow::ensure!(
        !key_path(&dir).exists() && !database_path(&dir).exists(),
        "control state already exists"
    );
    let key = scale_core::load_or_create_secret(&key_path(&dir))?;
    let (relay_ca_der, _) = load_or_create_relay_ca(&dir)?;
    let state = ControlState {
        schema: STATE_SCHEMA,
        audience,
        public_url,
        relay_ca_der,
        revision: 0,
        relay_revision: 1,
        clients: vec![],
        edges: vec![],
        relays: vec![],
        invites: vec![],
        provisioners: vec![],
        revocations: vec![],
    };
    db::Database::create(&database_path(&dir), &state)?;
    println!("initialized control {}", key.public());
    println!("next: as-control run, then as-control client invite <name>");
    Ok(())
}

fn bootstrap(
    dir: PathBuf,
    public_url: String,
    audience: String,
    relay_name: String,
    relay_url: String,
    relay_ttl_secs: u64,
    relay_invite_out: PathBuf,
) -> Result<()> {
    validate_name(&relay_name)?;
    anyhow::ensure!(!audience.trim().is_empty(), "--audience must not be empty");
    let public_url = normalize_public_url(&public_url)?;
    let relay_url = normalize_relay_url(&relay_url)?;
    scale_core::ensure_private_dir(&dir)?;
    if key_path(&dir).exists()
        && database_path(&dir).exists()
        && relay_ca_key_path(&dir).exists()
        && relay_ca_cert_path(&dir).exists()
        && relay_invite_out.exists()
    {
        let key = scale_core::read_secret(&key_path(&dir))?;
        validate_prepared_invitation(
            &relay_invite_out,
            key.public(),
            &audience,
            &public_url,
            &relay_name,
            &InviteKind::Relay { url: relay_url.clone() },
        )?;
        println!("control {} is already prepared", key.public());
        return Ok(());
    }
    let _lock = scale_core::FileLock::try_acquire(&lock_path(&dir))
        .context("control state is already in use; bootstrap must run before as-control run")?;

    let key_exists = key_path(&dir).exists();
    let database_exists = database_path(&dir).exists();
    let ca_exists = relay_ca_key_path(&dir).exists() && relay_ca_cert_path(&dir).exists();
    anyhow::ensure!(
        key_exists == database_exists && database_exists == ca_exists,
        "incomplete control state: control.key, control.db, relay-ca.key, and relay-ca.der must all exist or all be absent"
    );
    let (key, database, mut state) = if database_exists {
        let key = scale_core::read_secret(&key_path(&dir))?;
        let database = db::Database::open(&database_path(&dir))?;
        let state = database.load()?;
        (key, database, state)
    } else {
        let key = scale_core::load_or_create_secret(&key_path(&dir))?;
        let (relay_ca_der, _) = load_or_create_relay_ca(&dir)?;
        let state = ControlState {
            schema: STATE_SCHEMA,
            audience: audience.clone(),
            public_url: public_url.clone(),
            relay_ca_der,
            revision: 0,
            relay_revision: 1,
            clients: vec![],
            edges: vec![],
            relays: vec![],
            invites: vec![],
            provisioners: vec![],
            revocations: vec![],
        };
        let database = db::Database::create(&database_path(&dir), &state)?;
        (key, database, state)
    };
    anyhow::ensure!(
        state.audience == audience,
        "configured Control audience does not match durable state"
    );
    anyhow::ensure!(
        state.public_url == public_url,
        "configured Control public URL does not match durable state"
    );

    let previous = state.clone();
    let relay_invite = if state.relays.is_empty() {
        state.invites.retain(|invite| {
            !matches!(invite.invite.kind, InviteKind::Relay { .. }) || invite.state != InviteState::Pending
        });
        Some(create_invite(
            &key,
            &mut state,
            relay_name,
            InviteKind::Relay { url: relay_url },
            relay_ttl_secs,
        )?)
    } else {
        anyhow::ensure!(
            state
                .relays
                .iter()
                .any(|relay| relay.name == relay_name && relay.url == relay_url),
            "configured Relay name or URL does not match durable state"
        );
        None
    };
    database.apply_sync(&previous, &state)?;
    if let Some(invite) = relay_invite {
        write_invitation(&relay_invite_out, &invite.join_url)?;
    }
    println!("prepared control {}", key.public());
    Ok(())
}

fn validate_prepared_invitation(
    path: &Path,
    control_id: EndpointId,
    audience: &str,
    public_url: &str,
    name: &str,
    kind: &InviteKind,
) -> Result<()> {
    let join_url = std::fs::read_to_string(path).with_context(|| format!("read invitation {}", path.display()))?;
    let parsed = Url::parse(join_url.trim()).with_context(|| format!("parse invitation {}", path.display()))?;
    let fragment = parsed
        .fragment()
        .with_context(|| format!("invitation {} has no token", path.display()))?;
    let token = JoinToken::decode(fragment).with_context(|| format!("decode invitation {}", path.display()))?;
    anyhow::ensure!(
        token.verify()? == control_id,
        "invitation {} belongs to another Control",
        path.display()
    );
    anyhow::ensure!(
        token.invite.audience == audience
            && token.invite.control_url == public_url
            && token.invite.name == name
            && token.invite.kind == *kind,
        "invitation {} does not match configured deployment",
        path.display()
    );
    Ok(())
}

fn write_invitation(path: &Path, join_url: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        scale_core::ensure_private_dir(parent)?;
    }
    let mut contents = join_url.as_bytes().to_vec();
    contents.push(b'\n');
    scale_core::atomic_write(path, &contents).with_context(|| format!("write invitation {}", path.display()))
}

async fn run(dir: PathBuf, bind: SocketAddr, admin_socket: PathBuf) -> Result<()> {
    let (lock, key, database, mut state) = open_exclusive(&dir)?;
    let (relay_ca_der, relay_ca) = load_relay_ca(&dir)?;
    anyhow::ensure!(
        state.relay_ca_der == relay_ca_der,
        "Relay CA files do not match control.db"
    );
    anyhow::ensure!(
        state.schema == STATE_SCHEMA,
        "unsupported state schema {}",
        state.schema
    );
    let previous = state.clone();
    let now = unix_timestamp();
    cleanup_invitations(&mut state, now);
    cleanup_revocations(&mut state, now);
    database.apply_sync(&previous, &state)?;
    let store = Arc::new(Store {
        database,
        key,
        relay_ca,
        state: Mutex::new(state),
        changed: Notify::new(),
        relay_changed: Notify::new(),
        _lock: lock,
    });
    let app = public_router(store.clone());
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("bind {bind}"))?;
    let actual = listener.local_addr()?;
    let state = store.state.lock().await;
    println!("control=http://{actual}");
    println!("control_id={}", store.key.public());
    println!("audience={}", state.audience);
    drop(state);
    std::io::stdout().flush()?;
    info!(bind = %actual, socket = %admin_socket.display(), control_id = %store.key.public(), "control started");
    let cleanup_store = store.clone();
    let cleanup = tokio::spawn(async move { invitation_cleanup_loop(cleanup_store).await });
    let admin = tokio::spawn(serve_local_admin(admin_socket, store));
    tokio::select! {
        result = axum::serve(listener, app) => result.context("control server"),
        result = admin => result.context("local administration task")?,
    }?;
    cleanup.abort();
    Ok(())
}

fn public_router(store: Arc<Store>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { StatusCode::NO_CONTENT }))
        .route("/v1/status", get(status))
        .route("/v1/claim", post(claim))
        .route("/v1/edge/invite", post(client_edge_invite))
        .route("/v1/edge/remove", post(client_edge_remove))
        .route("/v1/provisioner", post(provisioner_request))
        .route("/v1/watch", post(watch))
        .route("/v1/relay/watch", post(relay_watch))
        .with_state(AppState(store))
}

async fn status(State(AppState(store)): State<AppState>) -> Json<ControlStatus> {
    let state = store.state.lock().await;
    Json(ControlStatus {
        audience: state.audience.clone(),
        control_url: state.public_url.clone(),
        control_id: store.key.public().to_string(),
        revision: state.revision,
        clients: state.clients.len(),
        edges: state.edges.len(),
        relays: state.relays.len(),
    })
}

async fn claim(
    State(AppState(store)): State<AppState>,
    Json(request): Json<ClaimRequest>,
) -> Result<Json<JoinResult>, ApiError> {
    let now = unix_timestamp();
    request.token.verify().map_err(ApiError::unauthorized)?;
    let endpoint_id = request.verify().map_err(ApiError::unauthorized)?;
    check_time(request.claim.issued_at, now).map_err(ApiError::unauthorized)?;
    let mut state = store.state.lock().await;
    validate_token_for_state(&request.token, &state, store.key.public(), now)?;
    let index = state
        .invites
        .iter()
        .position(|record| record.invite.invite_id == request.claim.invite_id)
        .ok_or_else(|| ApiError::gone("unknown invite"))?;
    let relay_qad_port = validate_relay_claim(
        &state.invites[index].invite.kind,
        request.claim.relay_qad_port,
        request.claim.relay_tls_csr.as_deref(),
    )?;
    let relay_tls_certificate_der = issue_relay_tls_certificate(
        &request.claim.relay_tls_csr,
        &state.invites[index].invite.kind,
        relay_qad_port,
        &store.relay_ca,
    )?;
    match state.invites[index].state {
        InviteState::Pending => {}
        InviteState::Claimed if state.invites[index].claimed_by.as_deref() == Some(&request.claim.endpoint_id) => {
            if let Some(relay) = state
                .relays
                .iter()
                .find(|relay| relay.endpoint_id == request.claim.endpoint_id)
                && relay.qad_port != relay_qad_port
            {
                return Err(ApiError::conflict("Relay QAD port differs from its enrolled value"));
            }
            let map = signed_map(&state, &store.key, endpoint_id).map_err(ApiError::internal)?;
            return Ok(Json(JoinResult {
                name: state.invites[index].invite.name.clone(),
                kind: state.invites[index].invite.kind.clone(),
                map,
                relay_tls_certificate_der,
            }));
        }
        InviteState::Claimed => return Err(ApiError::conflict("invite was already claimed")),
        InviteState::Revoked => return Err(ApiError::gone("invite was revoked")),
    }
    let mut next = state.clone();
    let invite = next.invites[index].invite.clone();
    let managed_by = next.invites[index].managed_by.clone();
    let credential_generation = next
        .revision
        .checked_add(1)
        .ok_or_else(|| ApiError::internal("revision overflow"))?;
    add_claimed_node(
        &mut next,
        &invite,
        endpoint_id,
        managed_by.as_deref(),
        relay_qad_port,
        credential_generation,
        now,
    )?;
    next.invites[index].state = InviteState::Claimed;
    next.invites[index].claimed_by = Some(endpoint_id.to_string());
    next.invites[index].terminal_at = Some(now);
    next.revision = next
        .revision
        .checked_add(1)
        .ok_or_else(|| ApiError::internal("revision overflow"))?;
    let map = signed_map(&next, &store.key, endpoint_id).map_err(ApiError::internal)?;
    persist_candidate(&store, &mut state, next, true).await?;
    Ok(Json(JoinResult {
        name: invite.name,
        kind: invite.kind,
        map,
        relay_tls_certificate_der,
    }))
}

fn issue_relay_tls_certificate(
    csr_der: &Option<Vec<u8>>,
    kind: &InviteKind,
    qad_port: Option<u16>,
    issuer: &Issuer<'static, KeyPair>,
) -> Result<Option<Vec<u8>>, ApiError> {
    let InviteKind::Relay { url } = kind else {
        if csr_der.is_some() {
            return Err(ApiError::bad("only Relay claims may include a TLS CSR"));
        }
        return Ok(None);
    };
    let Some(_port) = qad_port else {
        if csr_der.is_some() {
            return Err(ApiError::bad("QAD is disabled for this Relay enrollment"));
        }
        return Ok(None);
    };
    let csr_der = csr_der
        .as_deref()
        .ok_or_else(|| ApiError::bad("QAD-enabled Relay claim is missing its TLS CSR"))?;
    if csr_der.len() > 16 * 1024 {
        return Err(ApiError::bad("Relay TLS CSR is too large"));
    }
    let host = Url::parse(url)
        .map_err(ApiError::bad)?
        .host_str()
        .ok_or_else(|| ApiError::bad("Relay URL has no host"))?
        .to_owned();
    let mut csr = CertificateSigningRequestParams::from_der(&csr_der.into()).map_err(ApiError::bad)?;
    let expected = CertificateParams::new(vec![host.clone()]).map_err(ApiError::bad)?;
    if csr.params.subject_alt_names != expected.subject_alt_names {
        return Err(ApiError::bad("Relay TLS CSR SAN does not match its Relay URL host"));
    }
    csr.params.is_ca = IsCa::ExplicitNoCa;
    csr.params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    csr.params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    csr.params.use_authority_key_identifier_extension = true;
    csr.params.distinguished_name = expected.distinguished_name;
    csr.params.distinguished_name.push(DnType::CommonName, host);
    let now = time::OffsetDateTime::now_utc();
    csr.params.not_before = now - time::Duration::days(1);
    csr.params.not_after = now + time::Duration::days(825);
    let certificate = csr.signed_by(issuer).map_err(ApiError::internal)?;
    Ok(Some(certificate.der().to_vec()))
}

fn validate_relay_claim(
    kind: &InviteKind,
    qad_port: Option<u16>,
    csr_der: Option<&[u8]>,
) -> Result<Option<u16>, ApiError> {
    if !matches!(kind, InviteKind::Relay { .. }) {
        if qad_port.is_some() || csr_der.is_some() {
            return Err(ApiError::bad("only Relay claims may advertise QAD"));
        }
        return Ok(None);
    }
    validate_qad_port(qad_port).map_err(ApiError::bad)?;
    if qad_port.is_some() != csr_der.is_some() {
        return Err(ApiError::bad("Relay QAD port and TLS CSR must be provided together"));
    }
    Ok(qad_port)
}

async fn client_edge_invite(
    State(AppState(store)): State<AppState>,
    Json(request): Json<EdgeInviteRequest>,
) -> Result<Json<InviteResult>, ApiError> {
    let client_id = request.verify().map_err(ApiError::unauthorized)?;
    check_time(request.issued_at, unix_timestamp()).map_err(ApiError::unauthorized)?;
    validate_name(&request.name).map_err(ApiError::bad)?;
    if request.request_id.is_empty() || request.request_id.len() > 128 {
        return Err(ApiError::bad("request id must contain 1-128 characters"));
    }
    let mut state = store.state.lock().await;
    if request.audience != state.audience {
        return Err(ApiError::unauthorized("control audience mismatch"));
    }
    let managed_by = state
        .clients
        .iter()
        .find(|client| client.endpoint_id == client_id.to_string())
        .map(|client| client.managed_by.clone())
        .ok_or_else(|| ApiError::forbidden("client is not registered"))?;
    if state
        .invites
        .iter()
        .any(|invite| invite.request_id.as_deref() == Some(&request.request_id))
    {
        return Err(ApiError::conflict("edge invitation request was already used"));
    }
    let kind = InviteKind::Edge {
        owner_id: client_id.to_string(),
    };
    validate_invite_name(&state, &request.name, &kind)?;
    let mut next = state.clone();
    let result = create_invite(&store.key, &mut next, request.name, kind, request.ttl_secs).map_err(ApiError::bad)?;
    next.invites
        .last_mut()
        .expect("create_invite always appends an invitation")
        .request_id = Some(request.request_id);
    next.invites
        .last_mut()
        .expect("create_invite always appends an invitation")
        .managed_by = managed_by;
    commit_candidate(&store, &mut state, next).await?;
    Ok(Json(result))
}

async fn client_edge_remove(
    State(AppState(store)): State<AppState>,
    Json(request): Json<EdgeRemoveRequest>,
) -> Result<Json<SignedNodeMap>, ApiError> {
    let client_endpoint = request.verify().map_err(ApiError::unauthorized)?;
    check_time(request.issued_at, unix_timestamp()).map_err(ApiError::unauthorized)?;
    validate_name(&request.name).map_err(ApiError::bad)?;
    if request.nonce.is_empty() || request.nonce.len() > 128 {
        return Err(ApiError::bad("nonce must contain 1-128 characters"));
    }
    let client_id = client_endpoint.to_string();
    let mut state = store.state.lock().await;
    if request.audience != state.audience {
        return Err(ApiError::unauthorized("control audience mismatch"));
    }
    if !state.clients.iter().any(|client| client.endpoint_id == client_id) {
        return Err(ApiError::forbidden("client is not registered"));
    }
    let mut next = state.clone();
    let removed = next
        .edges
        .iter()
        .find(|edge| edge.owner_id == client_id && edge.name == request.name && edge.endpoint_id == request.endpoint_id)
        .cloned();
    let before = next.edges.len();
    next.edges.retain(|edge| {
        !(edge.owner_id == client_id && edge.name == request.name && edge.endpoint_id == request.endpoint_id)
    });
    if next.edges.len() == before {
        return Err(ApiError::bad(format!(
            "unknown edge '{}' with the expected identity",
            request.name
        )));
    }
    let removed = removed.expect("the length check proves an Edge was removed");
    add_revocation(
        &mut next,
        &removed.endpoint_id,
        removed.credential_generation,
        removed.credential_expires_at,
    );
    commit_revocation_candidate(&store, &mut state, next).await?;
    let map = signed_map(&state, &store.key, client_endpoint).map_err(ApiError::internal)?;
    Ok(Json(map))
}

async fn provisioner_request(
    State(AppState(store)): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<ProvisionerResponse>, ApiError> {
    if body.len() > 64 * 1024 {
        return Err(ApiError::bad("provisioner request body exceeds 64 KiB"));
    }
    let authorization = headers
        .get(AUTHORIZATION)
        .ok_or_else(|| ApiError::unauthorized("missing provisioner authorization"))?
        .to_str()
        .map_err(ApiError::unauthorized)?;
    let provisioner_id = verify_provisioner_authorization(authorization, &body)
        .map_err(ApiError::unauthorized)?
        .to_string();
    let request: ProvisionerRequest = serde_json::from_slice(&body).map_err(ApiError::bad)?;
    request.verify_protocol().map_err(ApiError::bad)?;
    check_time(request.issued_at, unix_timestamp()).map_err(ApiError::unauthorized)?;
    validate_request_id(&request.request_id).map_err(ApiError::bad)?;

    let mut state = store.state.lock().await;
    if request.audience != state.audience {
        return Err(ApiError::unauthorized("control audience mismatch"));
    }
    if !state.provisioners.iter().any(|item| item.endpoint_id == provisioner_id) {
        return Err(ApiError::forbidden("provisioner is not registered"));
    }

    if matches!(request.action, ProvisionerAction::GetTopology) {
        return Ok(Json(ProvisionerResponse::Topology(provisioner_topology(
            &state,
            &provisioner_id,
        ))));
    }

    let response = dispatch_provisioner_mutation(&store, &mut state, &provisioner_id, &request).await?;
    Ok(Json(response))
}

async fn dispatch_provisioner_mutation(
    store: &Store,
    state: &mut ControlState,
    provisioner_id: &str,
    request: &ProvisionerRequest,
) -> Result<ProvisionerResponse, ApiError> {
    match &request.action {
        ProvisionerAction::GetTopology => unreachable!("queries are handled before mutation dispatch"),
        ProvisionerAction::InviteClient { name, ttl_secs, secret } => {
            provisioner_invite(
                store,
                state,
                provisioner_id,
                request,
                name,
                InviteKind::Client,
                *ttl_secs,
                secret,
            )
            .await
        }
        ProvisionerAction::InviteEdge {
            owner,
            name,
            ttl_secs,
            secret,
        } => {
            let owner_id = managed_client_id(state, owner, provisioner_id)?;
            provisioner_invite(
                store,
                state,
                provisioner_id,
                request,
                name,
                InviteKind::Edge { owner_id },
                *ttl_secs,
                secret,
            )
            .await
        }
        ProvisionerAction::RevokeInvite { invite_id } => {
            let Some(index) = state.invites.iter().position(|item| {
                item.invite.invite_id == *invite_id && item.managed_by.as_deref() == Some(provisioner_id)
            }) else {
                return Err(ApiError::bad("unknown managed invite"));
            };
            match state.invites[index].state {
                InviteState::Revoked => return provisioner_ok(state),
                InviteState::Claimed => return Err(ApiError::conflict("claimed invites cannot be revoked")),
                InviteState::Pending => {}
            }
            check_expected_revision(state, request.expected_revision)?;
            let mut next = state.clone();
            next.invites[index].state = InviteState::Revoked;
            next.invites[index].terminal_at = Some(unix_timestamp());
            commit_candidate(store, state, next).await?;
            provisioner_ok(state)
        }
        ProvisionerAction::RemoveClient { name } => {
            let Some(client) = state
                .clients
                .iter()
                .find(|item| item.name == *name && item.managed_by.as_deref() == Some(provisioner_id))
                .cloned()
            else {
                if state.clients.iter().any(|item| item.name == *name) {
                    return Err(ApiError::forbidden("client is managed by another authority"));
                }
                return provisioner_ok(state);
            };
            if state.edges.iter().any(|edge| edge.owner_id == client.endpoint_id) {
                return Err(ApiError::conflict("client still owns edges"));
            }
            if state.invites.iter().any(|invite| {
                invite_is_active_pending(invite)
                    && matches!(&invite.invite.kind, InviteKind::Edge { owner_id } if owner_id == &client.endpoint_id)
            }) {
                return Err(ApiError::conflict("client still has pending edge invites"));
            }
            check_expected_revision(state, request.expected_revision)?;
            let mut next = state.clone();
            next.clients.retain(|item| item.endpoint_id != client.endpoint_id);
            add_revocation(
                &mut next,
                &client.endpoint_id,
                client.credential_generation,
                client.credential_expires_at,
            );
            commit_revocation_candidate(store, state, next).await?;
            provisioner_ok(state)
        }
        ProvisionerAction::RemoveEdge { owner, name } => {
            let owner_id = managed_client_id(state, owner, provisioner_id)?;
            let edge = state
                .edges
                .iter()
                .find(|item| item.owner_id == owner_id && item.name == *name)
                .cloned();
            let Some(edge) = edge else {
                return provisioner_ok(state);
            };
            check_expected_revision(state, request.expected_revision)?;
            let mut next = state.clone();
            next.edges
                .retain(|item| !(item.owner_id == owner_id && item.name == *name));
            add_revocation(
                &mut next,
                &edge.endpoint_id,
                edge.credential_generation,
                edge.credential_expires_at,
            );
            commit_revocation_candidate(store, state, next).await?;
            provisioner_ok(state)
        }
        ProvisionerAction::TransferEdge {
            owner,
            name,
            endpoint_id,
            new_owner,
        } => {
            let endpoint_id = endpoint_id
                .parse::<EndpointId>()
                .map_err(|error| ApiError::bad(format!("invalid edge endpoint id: {error}")))?
                .to_string();
            let owner_id = managed_client_id(state, owner, provisioner_id)?;
            let new_owner_id = managed_client_id(state, new_owner, provisioner_id)?;
            if !state
                .edges
                .iter()
                .any(|item| item.owner_id == owner_id && item.name == *name && item.endpoint_id == endpoint_id)
            {
                if state
                    .edges
                    .iter()
                    .any(|item| item.owner_id == new_owner_id && item.name == *name && item.endpoint_id == endpoint_id)
                {
                    return provisioner_ok(state);
                }
                return Err(ApiError::bad("unknown managed edge"));
            }
            if state
                .edges
                .iter()
                .any(|item| item.owner_id == new_owner_id && item.name == *name)
            {
                return Err(ApiError::conflict("target client already has an edge with this name"));
            }
            check_expected_revision(state, request.expected_revision)?;
            let mut next = state.clone();
            next.edges
                .iter_mut()
                .find(|item| item.owner_id == owner_id && item.name == *name && item.endpoint_id == endpoint_id)
                .expect("managed edge was checked above")
                .owner_id = new_owner_id;
            commit_candidate(store, state, next).await?;
            provisioner_ok(state)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn provisioner_invite(
    store: &Store,
    state: &mut ControlState,
    provisioner_id: &str,
    request: &ProvisionerRequest,
    name: &str,
    kind: InviteKind,
    ttl_secs: u64,
    secret: &str,
) -> Result<ProvisionerResponse, ApiError> {
    validate_name(name).map_err(ApiError::bad)?;
    validate_join_secret(secret).map_err(ApiError::bad)?;
    let request_hash = action_hash(&request.action).map_err(ApiError::internal)?;
    if let Some(existing) = state.invites.iter().find(|item| {
        item.managed_by.as_deref() == Some(provisioner_id) && item.request_id.as_deref() == Some(&request.request_id)
    }) {
        if existing.request_hash.as_deref() != Some(&request_hash) {
            return Err(ApiError::conflict("request id was already used for another action"));
        }
        let result = invite_result(&store.key, &existing.invite, secret).map_err(ApiError::internal)?;
        return Ok(ProvisionerResponse::Invite(result));
    }

    check_expected_revision(state, request.expected_revision)?;
    validate_invite_name(state, name, &kind)?;
    let mut next = state.clone();
    let result = create_invite_with_secret(
        &store.key,
        &mut next,
        name.to_owned(),
        kind,
        ttl_secs,
        secret.to_owned(),
    )
    .map_err(ApiError::bad)?;
    let record = next
        .invites
        .last_mut()
        .expect("create_invite always appends an invitation");
    record.request_id = Some(request.request_id.clone());
    record.managed_by = Some(provisioner_id.to_owned());
    record.request_hash = Some(request_hash);
    commit_candidate(store, state, next).await?;
    Ok(ProvisionerResponse::Invite(result))
}

fn provisioner_topology(state: &ControlState, provisioner_id: &str) -> ProvisionerTopology {
    let clients = state
        .clients
        .iter()
        .filter(|client| client.managed_by.as_deref() == Some(provisioner_id))
        .map(|client| ManagedClientInfo {
            name: client.name.clone(),
            endpoint_id: client.endpoint_id.clone(),
            edges: state
                .edges
                .iter()
                .filter(|edge| edge.owner_id == client.endpoint_id)
                .map(|edge| ManagedEdgeInfo {
                    name: edge.name.clone(),
                    endpoint_id: edge.endpoint_id.clone(),
                })
                .collect(),
        })
        .collect();
    let invites = state
        .invites
        .iter()
        .filter(|invite| invite.managed_by.as_deref() == Some(provisioner_id))
        .map(invite_info)
        .collect();
    ProvisionerTopology {
        revision: state.revision,
        clients,
        invites,
    }
}

fn provisioner_ok(state: &ControlState) -> Result<ProvisionerResponse, ApiError> {
    Ok(ProvisionerResponse::Ok {
        revision: state.revision,
    })
}

fn managed_client_id(state: &ControlState, name: &str, provisioner_id: &str) -> Result<String, ApiError> {
    state
        .clients
        .iter()
        .find(|client| client.name == name && client.managed_by.as_deref() == Some(provisioner_id))
        .map(|client| client.endpoint_id.clone())
        .ok_or_else(|| ApiError::bad(format!("unknown managed client '{name}'")))
}

fn check_expected_revision(state: &ControlState, expected: Option<u64>) -> Result<(), ApiError> {
    if let Some(expected) = expected
        && expected != state.revision
    {
        return Err(ApiError::conflict(format!(
            "revision mismatch: expected {expected}, current {}",
            state.revision
        )));
    }
    Ok(())
}

async fn watch(
    State(AppState(store)): State<AppState>,
    Json(request): Json<WatchRequest>,
) -> Result<Json<SignedNodeMap>, ApiError> {
    let endpoint_id = request.verify().map_err(ApiError::unauthorized)?;
    check_time(request.issued_at, unix_timestamp()).map_err(ApiError::unauthorized)?;
    if !renew_relay_credential_if_needed(&store, endpoint_id).await? {
        wait_for_revision(&store, endpoint_id, request.known_revision).await?;
    }
    let state = store.state.lock().await;
    Ok(Json(
        signed_map(&state, &store.key, endpoint_id).map_err(ApiError::internal)?,
    ))
}

async fn relay_watch(
    State(AppState(store)): State<AppState>,
    Json(request): Json<WatchRequest>,
) -> Result<Json<SignedRevocationUpdate>, ApiError> {
    let endpoint_id = request.verify().map_err(ApiError::unauthorized)?;
    check_time(request.issued_at, unix_timestamp()).map_err(ApiError::unauthorized)?;
    validate_qad_port(request.relay_qad_port).map_err(ApiError::bad)?;
    {
        let mut state = store.state.lock().await;
        let index = state
            .relays
            .iter()
            .position(|relay| relay.endpoint_id == endpoint_id.to_string())
            .ok_or_else(|| ApiError::forbidden("relay is not registered"))?;
        if state.relays[index].qad_port != request.relay_qad_port {
            let mut next = state.clone();
            next.relays[index].qad_port = request.relay_qad_port;
            commit_candidate(&store, &mut state, next).await?;
        }
    }
    wait_for_relay_revision(&store, endpoint_id, request.known_revision).await?;
    let state = store.state.lock().await;
    anyhow_relay_exists(&state, endpoint_id)?;
    let now = unix_timestamp();
    let update = RevocationUpdate {
        protocol_version: RELAY_PROTOCOL_VERSION,
        audience: state.audience.clone(),
        version: state.relay_revision,
        issued_at: now,
        revocations: state
            .revocations
            .iter()
            .filter(|revocation| revocation.revision > request.known_revision)
            .map(|revocation| Revocation {
                endpoint_id: revocation.endpoint_id.clone(),
                revoked_through_generation: revocation.revoked_through_generation,
                expires_at: revocation.expires_at,
                revision: revocation.revision,
            })
            .collect(),
    };
    Ok(Json(
        SignedRevocationUpdate::sign(update, &store.key).map_err(ApiError::internal)?,
    ))
}

async fn renew_relay_credential_if_needed(store: &Arc<Store>, endpoint_id: EndpointId) -> Result<bool, ApiError> {
    let now = unix_timestamp();
    let renew_at = now.saturating_add(RELAY_CREDENTIAL_RENEW_BEFORE_SECS);
    let endpoint = endpoint_id.to_string();
    let mut state = store.state.lock().await;
    let expires_at = state
        .clients
        .iter()
        .find(|record| record.endpoint_id == endpoint)
        .map(|record| record.credential_expires_at)
        .or_else(|| {
            state
                .edges
                .iter()
                .find(|record| record.endpoint_id == endpoint)
                .map(|record| record.credential_expires_at)
        });
    let Some(expires_at) = expires_at else {
        anyhow_node_exists(&state, endpoint_id)?;
        return Ok(false);
    };
    if expires_at > renew_at {
        return Ok(false);
    }
    let mut next = state.clone();
    if let Some(record) = next.clients.iter_mut().find(|record| record.endpoint_id == endpoint) {
        record.credential_issued_at = now;
        record.credential_expires_at = now.saturating_add(RELAY_CREDENTIAL_LIFETIME_SECS);
    } else if let Some(record) = next.edges.iter_mut().find(|record| record.endpoint_id == endpoint) {
        record.credential_issued_at = now;
        record.credential_expires_at = now.saturating_add(RELAY_CREDENTIAL_LIFETIME_SECS);
    }
    persist_candidate(store, &mut state, next, false).await?;
    Ok(true)
}

async fn wait_for_revision(store: &Arc<Store>, endpoint_id: EndpointId, known: u64) -> Result<(), ApiError> {
    loop {
        let notified = store.changed.notified();
        {
            let state = store.state.lock().await;
            anyhow_node_exists(&state, endpoint_id)?;
            if state.revision > known {
                return Ok(());
            }
        }
        if tokio::time::timeout(Duration::from_secs(30), notified).await.is_err() {
            return Ok(());
        }
    }
}

async fn wait_for_relay_revision(store: &Arc<Store>, endpoint_id: EndpointId, known: u64) -> Result<(), ApiError> {
    loop {
        let notified = store.relay_changed.notified();
        {
            let state = store.state.lock().await;
            anyhow_relay_exists(&state, endpoint_id)?;
            if known > state.relay_revision {
                return Err(ApiError::bad("Relay revision is ahead of Control"));
            }
            if state.relay_revision > known {
                return Ok(());
            }
        }
        if tokio::time::timeout(Duration::from_secs(30), notified).await.is_err() {
            return Ok(());
        }
    }
}

#[cfg(unix)]
async fn serve_local_admin(path: PathBuf, store: Arc<Store>) -> Result<()> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};

    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    if let Ok(metadata) = std::fs::symlink_metadata(&path) {
        anyhow::ensure!(
            metadata.file_type().is_socket(),
            "refusing to replace non-socket {}",
            path.display()
        );
        std::fs::remove_file(&path)?;
    }
    let listener = tokio::net::UnixListener::bind(&path)
        .with_context(|| format!("bind local administration socket {}", path.display()))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    loop {
        let (stream, _) = listener.accept().await?;
        let store = store.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_local_admin(stream, store).await {
                tracing::warn!(%error, "local administration request failed");
            }
        });
    }
}

#[cfg(not(unix))]
async fn serve_local_admin(_path: PathBuf, _store: Arc<Store>) -> Result<()> {
    anyhow::bail!("local administration requires Unix sockets")
}

#[cfg(unix)]
async fn handle_local_admin(mut stream: tokio::net::UnixStream, store: Arc<Store>) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let len = stream.read_u32().await? as usize;
    anyhow::ensure!(len <= 1024 * 1024, "administration request is too large");
    let mut bytes = vec![0; len];
    stream.read_exact(&mut bytes).await?;
    let request: LocalAdminRequest = serde_json::from_slice(&bytes)?;
    let response = match dispatch_local_admin(&store, request).await {
        Ok(response) => response,
        Err(error) => LocalAdminResponse::Error(error.message),
    };
    let bytes = serde_json::to_vec(&response)?;
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(&bytes).await?;
    stream.shutdown().await?;
    Ok(())
}

async fn dispatch_local_admin(store: &Arc<Store>, request: LocalAdminRequest) -> Result<LocalAdminResponse, ApiError> {
    match request {
        LocalAdminRequest::Overview => {
            let state = store.state.lock().await;
            Ok(LocalAdminResponse::Overview(overview(&state)))
        }
        LocalAdminRequest::ListClients => {
            let state = store.state.lock().await;
            Ok(LocalAdminResponse::Clients(overview(&state).clients))
        }
        LocalAdminRequest::ListEdges => {
            let state = store.state.lock().await;
            Ok(LocalAdminResponse::Edges(overview(&state).edges))
        }
        LocalAdminRequest::ListRelays => {
            let state = store.state.lock().await;
            Ok(LocalAdminResponse::Relays(overview(&state).relays))
        }
        LocalAdminRequest::ListInvites => {
            let state = store.state.lock().await;
            Ok(LocalAdminResponse::Invites(overview(&state).invites))
        }
        LocalAdminRequest::ListProvisioners => {
            let state = store.state.lock().await;
            Ok(LocalAdminResponse::Provisioners(
                state
                    .provisioners
                    .iter()
                    .map(|item| ProvisionerInfo {
                        name: item.name.clone(),
                        endpoint_id: item.endpoint_id.clone(),
                        clients: state
                            .clients
                            .iter()
                            .filter(|client| client.managed_by.as_deref() == Some(&item.endpoint_id))
                            .count(),
                    })
                    .collect(),
            ))
        }
        LocalAdminRequest::InviteClient { name, ttl_secs } => {
            local_create_invite(store, name, InviteKind::Client, ttl_secs, None).await
        }
        LocalAdminRequest::InviteEdge { name, owner, ttl_secs } => {
            let (owner_id, managed_by) = {
                let state = store.state.lock().await;
                state
                    .clients
                    .iter()
                    .find(|client| client.name == owner)
                    .map(|client| (client.endpoint_id.clone(), client.managed_by.clone()))
                    .ok_or_else(|| ApiError::bad(format!("unknown client '{owner}'")))?
            };
            local_create_invite(store, name, InviteKind::Edge { owner_id }, ttl_secs, managed_by).await
        }
        LocalAdminRequest::InviteRelay { name, url, ttl_secs } => {
            let url = normalize_relay_url(&url).map_err(ApiError::bad)?;
            local_create_invite(store, name, InviteKind::Relay { url }, ttl_secs, None).await
        }
        LocalAdminRequest::RevokeInvite { invite_id } => {
            let mut state = store.state.lock().await;
            let mut next = state.clone();
            let invite = next
                .invites
                .iter_mut()
                .find(|item| item.invite.invite_id == invite_id)
                .ok_or_else(|| ApiError::bad("unknown invite"))?;
            match invite.state {
                InviteState::Pending => {}
                InviteState::Claimed => return Err(ApiError::conflict("claimed invites cannot be revoked")),
                InviteState::Revoked => return Ok(LocalAdminResponse::Ok),
            }
            invite.state = InviteState::Revoked;
            invite.terminal_at = Some(unix_timestamp());
            commit_candidate(store, &mut state, next).await?;
            Ok(LocalAdminResponse::Ok)
        }
        LocalAdminRequest::RemoveClient { name } => {
            let mut state = store.state.lock().await;
            let client = state
                .clients
                .iter()
                .find(|client| client.name == name)
                .cloned()
                .ok_or_else(|| ApiError::bad(format!("unknown client '{name}'")))?;
            if state.edges.iter().any(|edge| edge.owner_id == client.endpoint_id) {
                return Err(ApiError::conflict("client still owns edges"));
            }
            if state.invites.iter().any(|invite| {
                invite_is_active_pending(invite)
                    && matches!(
                        &invite.invite.kind,
                        InviteKind::Edge { owner_id } if owner_id == &client.endpoint_id
                    )
            }) {
                return Err(ApiError::conflict("client still has pending edge invites"));
            }
            let mut next = state.clone();
            next.clients.retain(|item| item.endpoint_id != client.endpoint_id);
            add_revocation(
                &mut next,
                &client.endpoint_id,
                client.credential_generation,
                client.credential_expires_at,
            );
            commit_revocation_candidate(store, &mut state, next).await?;
            Ok(LocalAdminResponse::Ok)
        }
        LocalAdminRequest::TransferEdge { edge, new_client } => {
            let (owner_name, edge_name) = parse_edge_ref(&edge)?;
            let mut state = store.state.lock().await;
            let old_owner = client_id_by_name(&state, owner_name)?;
            let new_owner = client_id_by_name(&state, &new_client)?;
            if state
                .edges
                .iter()
                .any(|item| item.owner_id == new_owner && item.name == edge_name)
            {
                return Err(ApiError::conflict("target client already has an edge with this name"));
            }
            let mut next = state.clone();
            let record = next
                .edges
                .iter_mut()
                .find(|item| item.owner_id == old_owner && item.name == edge_name)
                .ok_or_else(|| ApiError::bad(format!("unknown edge '{edge}'")))?;
            record.owner_id = new_owner;
            commit_candidate(store, &mut state, next).await?;
            Ok(LocalAdminResponse::Ok)
        }
        LocalAdminRequest::RemoveEdge { edge } => {
            let (owner_name, edge_name) = parse_edge_ref(&edge)?;
            let mut state = store.state.lock().await;
            let owner_id = client_id_by_name(&state, owner_name)?;
            let mut next = state.clone();
            let removed = next
                .edges
                .iter()
                .find(|item| item.owner_id == owner_id && item.name == edge_name)
                .cloned();
            let before = next.edges.len();
            next.edges
                .retain(|item| !(item.owner_id == owner_id && item.name == edge_name));
            if next.edges.len() == before {
                return Err(ApiError::bad(format!("unknown edge '{edge}'")));
            }
            let removed = removed.expect("the length check proves an Edge was removed");
            add_revocation(
                &mut next,
                &removed.endpoint_id,
                removed.credential_generation,
                removed.credential_expires_at,
            );
            commit_revocation_candidate(store, &mut state, next).await?;
            Ok(LocalAdminResponse::Ok)
        }
        LocalAdminRequest::RemoveRelay { name } => {
            let mut state = store.state.lock().await;
            let mut next = state.clone();
            let before = next.relays.len();
            next.relays.retain(|relay| relay.name != name);
            if next.relays.len() == before {
                return Err(ApiError::bad(format!("unknown relay '{name}'")));
            }
            commit_revocation_candidate(store, &mut state, next).await?;
            Ok(LocalAdminResponse::Ok)
        }
        LocalAdminRequest::AddProvisioner { name, endpoint_id } => {
            validate_name(&name).map_err(ApiError::bad)?;
            let endpoint_id = endpoint_id
                .parse::<EndpointId>()
                .map_err(|error| ApiError::bad(format!("invalid provisioner endpoint id: {error}")))?
                .to_string();
            let mut state = store.state.lock().await;
            if state
                .provisioners
                .iter()
                .any(|item| item.name == name || item.endpoint_id == endpoint_id)
            {
                return Err(ApiError::conflict("provisioner name or identity already exists"));
            }
            let mut next = state.clone();
            next.provisioners.push(ProvisionerRecord { name, endpoint_id });
            commit_candidate(store, &mut state, next).await?;
            Ok(LocalAdminResponse::Ok)
        }
        LocalAdminRequest::RemoveProvisioner { name } => {
            let mut state = store.state.lock().await;
            let Some(provisioner) = state.provisioners.iter().find(|item| item.name == name).cloned() else {
                return Err(ApiError::bad(format!("unknown provisioner '{name}'")));
            };
            if state
                .clients
                .iter()
                .any(|client| client.managed_by.as_deref() == Some(&provisioner.endpoint_id))
            {
                return Err(ApiError::conflict("provisioner still manages clients"));
            }
            if state.invites.iter().any(|invite| {
                invite_is_active_pending(invite) && invite.managed_by.as_deref() == Some(&provisioner.endpoint_id)
            }) {
                return Err(ApiError::conflict("provisioner still owns pending invites"));
            }
            let mut next = state.clone();
            next.provisioners
                .retain(|item| item.endpoint_id != provisioner.endpoint_id);
            commit_candidate(store, &mut state, next).await?;
            Ok(LocalAdminResponse::Ok)
        }
    }
}

async fn local_create_invite(
    store: &Arc<Store>,
    name: String,
    kind: InviteKind,
    ttl_secs: u64,
    managed_by: Option<String>,
) -> Result<LocalAdminResponse, ApiError> {
    validate_name(&name).map_err(ApiError::bad)?;
    let mut state = store.state.lock().await;
    validate_invite_name(&state, &name, &kind)?;
    let mut next = state.clone();
    let result = create_invite(&store.key, &mut next, name, kind, ttl_secs).map_err(ApiError::bad)?;
    next.invites
        .last_mut()
        .expect("create_invite always appends an invitation")
        .managed_by = managed_by;
    commit_candidate(store, &mut state, next).await?;
    Ok(LocalAdminResponse::Invite(result))
}

fn overview(state: &ControlState) -> Overview {
    Overview {
        revision: state.revision,
        clients: state
            .clients
            .iter()
            .map(|client| ClientInfo {
                name: client.name.clone(),
                endpoint_id: client.endpoint_id.clone(),
                edges: state
                    .edges
                    .iter()
                    .filter(|edge| edge.owner_id == client.endpoint_id)
                    .count(),
            })
            .collect(),
        edges: state
            .edges
            .iter()
            .map(|edge| EdgeInfo {
                name: edge.name.clone(),
                endpoint_id: edge.endpoint_id.clone(),
                owner_id: edge.owner_id.clone(),
                owner_name: client_name(state, &edge.owner_id).unwrap_or("unknown").into(),
            })
            .collect(),
        relays: state
            .relays
            .iter()
            .map(|relay| RelayNodeInfo {
                name: relay.name.clone(),
                endpoint_id: relay.endpoint_id.clone(),
                url: relay.url.clone(),
                qad_port: relay.qad_port,
            })
            .collect(),
        invites: state.invites.iter().map(invite_info).collect(),
    }
}

fn invite_info(invite: &InviteRecord) -> InviteInfo {
    InviteInfo {
        invite_id: invite.invite.invite_id.clone(),
        name: invite.invite.name.clone(),
        kind: invite.invite.kind.clone(),
        expires_at: invite.invite.expires_at,
        state: if invite.state == InviteState::Pending && invite.invite.expires_at < unix_timestamp() {
            "expired"
        } else {
            match invite.state {
                InviteState::Pending => "pending",
                InviteState::Claimed => "claimed",
                InviteState::Revoked => "revoked",
            }
        }
        .into(),
    }
}

fn parse_edge_ref(value: &str) -> Result<(&str, &str), ApiError> {
    value
        .split_once('/')
        .ok_or_else(|| ApiError::bad("edge must be written as <client>/<edge>"))
}

fn client_id_by_name(state: &ControlState, name: &str) -> Result<String, ApiError> {
    state
        .clients
        .iter()
        .find(|client| client.name == name)
        .map(|client| client.endpoint_id.clone())
        .ok_or_else(|| ApiError::bad(format!("unknown client '{name}'")))
}

#[cfg(unix)]
async fn admin_call(path: &Path, request: LocalAdminRequest) -> Result<LocalAdminResponse> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::UnixStream::connect(path)
        .await
        .with_context(|| format!("connect local administration socket {}", path.display()))?;
    let bytes = serde_json::to_vec(&request)?;
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    let len = stream.read_u32().await? as usize;
    anyhow::ensure!(len <= 1024 * 1024, "administration response is too large");
    let mut bytes = vec![0; len];
    stream.read_exact(&mut bytes).await?;
    serde_json::from_slice(&bytes).context("decode local administration response")
}

#[cfg(not(unix))]
async fn admin_call(_path: &Path, _request: LocalAdminRequest) -> Result<LocalAdminResponse> {
    anyhow::bail!("local administration requires Unix sockets")
}

fn print_admin_response(response: LocalAdminResponse) -> Result<()> {
    match response {
        LocalAdminResponse::Overview(value) => {
            println!("revision: {}", value.revision);
            println!("clients:  {}", value.clients.len());
            println!("edges:    {}", value.edges.len());
            println!("relays:   {}", value.relays.len());
        }
        LocalAdminResponse::Clients(values) => {
            for client in values {
                println!("{}", client.name);
                println!("  endpoint_id: {}", client.endpoint_id);
                println!("  edges:       {}", client.edges);
            }
        }
        LocalAdminResponse::Edges(values) => {
            for edge in values {
                println!("{}/{}", edge.owner_name, edge.name);
                println!("  endpoint_id: {}", edge.endpoint_id);
            }
        }
        LocalAdminResponse::Relays(values) => {
            for relay in values {
                println!("{}", relay.name);
                println!("  endpoint_id: {}", relay.endpoint_id);
                println!("  url:         {}", relay.url);
                match relay.qad_port {
                    Some(port) => println!("  qad:         udp/{port}"),
                    None => println!("  qad:         disabled"),
                }
            }
        }
        LocalAdminResponse::Invites(values) => {
            for invite in values {
                println!("{}", invite.invite_id);
                println!("  name:    {}", invite.name);
                println!("  kind:    {:?}", invite.kind);
                println!("  state:   {}", invite.state);
                println!("  expires: {}", invite.expires_at);
            }
        }
        LocalAdminResponse::Provisioners(values) => {
            for provisioner in values {
                println!("{}", provisioner.name);
                println!("  endpoint_id: {}", provisioner.endpoint_id);
                println!("  clients:    {}", provisioner.clients);
            }
        }
        LocalAdminResponse::Invite(value) => println!("{}", value.join_url),
        LocalAdminResponse::Ok => {}
        LocalAdminResponse::Error(message) => anyhow::bail!(message),
    }
    Ok(())
}

async fn commit_candidate(store: &Store, current: &mut ControlState, mut next: ControlState) -> Result<(), ApiError> {
    next.revision = next
        .revision
        .checked_add(1)
        .ok_or_else(|| ApiError::internal("revision overflow"))?;
    persist_candidate(store, current, next, true).await
}

async fn commit_revocation_candidate(
    store: &Store,
    current: &mut ControlState,
    mut next: ControlState,
) -> Result<(), ApiError> {
    next.revision = next
        .revision
        .checked_add(1)
        .ok_or_else(|| ApiError::internal("revision overflow"))?;
    next.relay_revision = next
        .relay_revision
        .checked_add(1)
        .ok_or_else(|| ApiError::internal("Relay revision overflow"))?;
    persist_candidate_with_notifications(store, current, next, true, true).await
}

async fn persist_candidate(
    store: &Store,
    current: &mut ControlState,
    next: ControlState,
    notify: bool,
) -> Result<(), ApiError> {
    persist_candidate_with_notifications(store, current, next, notify, false).await
}

async fn persist_candidate_with_notifications(
    store: &Store,
    current: &mut ControlState,
    next: ControlState,
    notify_nodes: bool,
    notify_relays: bool,
) -> Result<(), ApiError> {
    store
        .database
        .apply(current.clone(), next.clone())
        .await
        .map_err(ApiError::internal)?;
    *current = next;
    if notify_nodes {
        store.changed.notify_waiters();
    }
    if notify_relays {
        store.relay_changed.notify_waiters();
    }
    Ok(())
}

const INVITATION_RETENTION_SECS: i64 = 7 * 24 * 60 * 60;

fn cleanup_invitations(state: &mut ControlState, now: i64) -> bool {
    let before = state.invites.len();
    state.invites.retain(|invite| {
        let terminal = match invite.state {
            InviteState::Pending => invite.invite.expires_at,
            InviteState::Claimed | InviteState::Revoked => invite.terminal_at.unwrap_or(now),
        };
        now < terminal.saturating_add(INVITATION_RETENTION_SECS)
    });
    state.invites.len() != before
}

fn cleanup_revocations(state: &mut ControlState, now: i64) -> bool {
    let before = state.revocations.len();
    state.revocations.retain(|revocation| revocation.expires_at > now);
    state.revocations.len() != before
}

fn add_revocation(state: &mut ControlState, endpoint_id: &str, generation: u64, expires_at: i64) {
    let revision = state.relay_revision.saturating_add(1);
    if let Some(existing) = state
        .revocations
        .iter_mut()
        .find(|revocation| revocation.endpoint_id == endpoint_id)
    {
        existing.revoked_through_generation = existing.revoked_through_generation.max(generation);
        existing.expires_at = existing.expires_at.max(expires_at);
        existing.revision = revision;
        return;
    }
    state.revocations.push(RevocationRecord {
        endpoint_id: endpoint_id.to_owned(),
        revoked_through_generation: generation,
        expires_at,
        revision,
    });
}

async fn invitation_cleanup_loop(store: Arc<Store>) {
    let mut interval = tokio::time::interval(Duration::from_secs(60 * 60));
    interval.tick().await;
    loop {
        interval.tick().await;
        let mut current = store.state.lock().await;
        let mut next = current.clone();
        let now = unix_timestamp();
        let invitations_changed = cleanup_invitations(&mut next, now);
        let revocations_changed = cleanup_revocations(&mut next, now);
        if (invitations_changed || revocations_changed)
            && let Err(error) = persist_candidate(&store, &mut current, next, false).await
        {
            tracing::warn!(message = %error.message, "Control state cleanup failed");
        }
    }
}

fn add_claimed_node(
    state: &mut ControlState,
    invite: &Invite,
    endpoint_id: EndpointId,
    managed_by: Option<&str>,
    relay_qad_port: Option<u16>,
    credential_generation: u64,
    now: i64,
) -> Result<(), ApiError> {
    match &invite.kind {
        InviteKind::Client => {
            if state
                .clients
                .iter()
                .any(|item| item.name == invite.name || item.endpoint_id == endpoint_id.to_string())
            {
                return Err(ApiError::conflict("client name or identity already exists"));
            }
            state.clients.push(ClientRecord {
                name: invite.name.clone(),
                endpoint_id: endpoint_id.to_string(),
                managed_by: managed_by.map(ToOwned::to_owned),
                credential_generation,
                credential_issued_at: now,
                credential_expires_at: now.saturating_add(RELAY_CREDENTIAL_LIFETIME_SECS),
            });
        }
        InviteKind::Edge { owner_id } => {
            anyhow_client_exists(state, owner_id)?;
            if state.edges.iter().any(|item| {
                item.owner_id == *owner_id && item.name == invite.name || item.endpoint_id == endpoint_id.to_string()
            }) {
                return Err(ApiError::conflict("edge name or identity already exists"));
            }
            state.edges.push(EdgeRecord {
                name: invite.name.clone(),
                endpoint_id: endpoint_id.to_string(),
                owner_id: owner_id.clone(),
                credential_generation,
                credential_issued_at: now,
                credential_expires_at: now.saturating_add(RELAY_CREDENTIAL_LIFETIME_SECS),
            });
        }
        InviteKind::Relay { url } => {
            if state
                .relays
                .iter()
                .any(|item| item.name == invite.name || item.url == *url || item.endpoint_id == endpoint_id.to_string())
            {
                return Err(ApiError::conflict("relay name, URL, or identity already exists"));
            }
            state.relays.push(RelayRecord {
                name: invite.name.clone(),
                endpoint_id: endpoint_id.to_string(),
                url: url.clone(),
                qad_port: relay_qad_port,
            });
        }
    }
    Ok(())
}

fn signed_map(state: &ControlState, key: &SecretKey, recipient: EndpointId) -> Result<SignedNodeMap> {
    let recipient_string = recipient.to_string();
    let relays = state
        .relays
        .iter()
        .map(|relay| RelayInfo {
            name: relay.name.clone(),
            url: relay.url.clone(),
            qad_port: relay.qad_port,
        })
        .collect();
    let (relay_credential, allowed_clients, edges) =
        if let Some(edge) = state.edges.iter().find(|edge| edge.endpoint_id == recipient_string) {
            (
                Some(sign_relay_credential(
                    state,
                    key,
                    recipient,
                    RelaySubjectKind::Edge,
                    edge.credential_generation,
                    edge.credential_issued_at,
                    edge.credential_expires_at,
                )?),
                vec![edge.owner_id.clone()],
                vec![],
            )
        } else if let Some(client) = state
            .clients
            .iter()
            .find(|client| client.endpoint_id == recipient_string)
        {
            let edges = state
                .edges
                .iter()
                .filter(|edge| edge.owner_id == recipient_string)
                .map(|edge| EdgeInfo {
                    name: edge.name.clone(),
                    endpoint_id: edge.endpoint_id.clone(),
                    owner_id: edge.owner_id.clone(),
                    owner_name: client_name(state, &edge.owner_id).unwrap_or("unknown").to_string(),
                })
                .collect();
            (
                Some(sign_relay_credential(
                    state,
                    key,
                    recipient,
                    RelaySubjectKind::Client,
                    client.credential_generation,
                    client.credential_issued_at,
                    client.credential_expires_at,
                )?),
                vec![],
                edges,
            )
        } else if state.relays.iter().any(|relay| relay.endpoint_id == recipient_string) {
            (None, vec![], vec![])
        } else {
            anyhow::bail!("node is not registered")
        };
    SignedNodeMap::sign(
        NodeMap {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            audience: state.audience.clone(),
            control_url: state.public_url.clone(),
            control_id: key.public().to_string(),
            revision: state.revision,
            issued_at: unix_timestamp(),
            recipient_id: recipient_string,
            relays,
            relay_credential,
            relay_ca_der: state.relay_ca_der.clone(),
            allowed_clients,
            edges,
        },
        key,
    )
}

fn sign_relay_credential(
    state: &ControlState,
    key: &SecretKey,
    endpoint_id: EndpointId,
    kind: RelaySubjectKind,
    generation: u64,
    issued_at: i64,
    expires_at: i64,
) -> Result<String> {
    SignedRelayCredential::sign(
        RelayCredential {
            protocol_version: RELAY_PROTOCOL_VERSION,
            audience: state.audience.clone(),
            control_id: key.public().to_string(),
            endpoint_id: endpoint_id.to_string(),
            kind,
            generation,
            issued_at,
            expires_at,
        },
        key,
    )?
    .encode()
}

fn create_invite(
    key: &SecretKey,
    state: &mut ControlState,
    name: String,
    kind: InviteKind,
    ttl_secs: u64,
) -> Result<InviteResult> {
    create_invite_with_secret(key, state, name, kind, ttl_secs, random_token(32))
}

fn create_invite_with_secret(
    key: &SecretKey,
    state: &mut ControlState,
    name: String,
    kind: InviteKind,
    ttl_secs: u64,
    secret: String,
) -> Result<InviteResult> {
    anyhow::ensure!(
        (1..=7 * 24 * 60 * 60).contains(&ttl_secs),
        "TTL must be between 1 second and 7 days"
    );
    let invite_id = random_token(16);
    let expires_at = unix_timestamp()
        .checked_add(ttl_secs as i64)
        .context("invite expiry overflow")?;
    let invite = Invite {
        protocol_version: CONTROL_PROTOCOL_VERSION,
        audience: state.audience.clone(),
        control_url: state.public_url.clone(),
        control_id: key.public().to_string(),
        invite_id: invite_id.clone(),
        name,
        kind,
        secret_hash: hash_secret(&secret),
        expires_at,
    };
    let token = JoinToken::new(invite.clone(), secret, key)?;
    let join_url = token.join_url()?;
    state.invites.push(InviteRecord {
        invite,
        state: InviteState::Pending,
        claimed_by: None,
        request_id: None,
        managed_by: None,
        request_hash: None,
        terminal_at: None,
    });
    Ok(InviteResult {
        invite_id,
        join_url,
        expires_at,
    })
}

fn invite_result(key: &SecretKey, invite: &Invite, secret: &str) -> Result<InviteResult> {
    anyhow::ensure!(
        hash_secret(secret) == invite.secret_hash,
        "join secret does not match existing request"
    );
    let token = JoinToken::new(invite.clone(), secret.to_owned(), key)?;
    Ok(InviteResult {
        invite_id: invite.invite_id.clone(),
        join_url: token.join_url()?,
        expires_at: invite.expires_at,
    })
}

fn validate_token_for_state(
    token: &JoinToken,
    state: &ControlState,
    control_id: EndpointId,
    now: i64,
) -> Result<(), ApiError> {
    if token.invite.control_id != control_id.to_string()
        || token.invite.audience != state.audience
        || token.invite.control_url != state.public_url
    {
        return Err(ApiError::unauthorized("invite belongs to another control"));
    }
    if token.invite.expires_at < now {
        return Err(ApiError::gone("invite expired"));
    }
    let stored = state
        .invites
        .iter()
        .find(|record| record.invite.invite_id == token.invite.invite_id)
        .ok_or_else(|| ApiError::gone("unknown invite"))?;
    if stored.invite != token.invite {
        return Err(ApiError::unauthorized("invite payload mismatch"));
    }
    Ok(())
}

fn validate_invite_name(state: &ControlState, name: &str, kind: &InviteKind) -> Result<(), ApiError> {
    let registered_duplicate = match kind {
        InviteKind::Client => state.clients.iter().any(|item| item.name == name),
        InviteKind::Edge { owner_id } => state
            .edges
            .iter()
            .any(|item| item.owner_id == *owner_id && item.name == name),
        InviteKind::Relay { url } => state.relays.iter().any(|item| item.name == name || item.url == *url),
    };
    let pending_duplicate = state.invites.iter().any(|record| {
        invite_is_active_pending(record)
            && match (&record.invite.kind, kind) {
                (InviteKind::Client, InviteKind::Client) => record.invite.name == name,
                (InviteKind::Edge { owner_id: left }, InviteKind::Edge { owner_id: right }) => {
                    left == right && record.invite.name == name
                }
                (InviteKind::Relay { url: left }, InviteKind::Relay { url: right }) => {
                    record.invite.name == name || left == right
                }
                _ => false,
            }
    });
    if registered_duplicate || pending_duplicate {
        Err(ApiError::conflict("name or relay URL already exists"))
    } else {
        Ok(())
    }
}

fn invite_is_active_pending(record: &InviteRecord) -> bool {
    record.state == InviteState::Pending && record.invite.expires_at >= unix_timestamp()
}

fn validate_request_id(value: &str) -> Result<()> {
    anyhow::ensure!(
        (1..=128).contains(&value.len()),
        "request id must contain 1-128 characters"
    );
    anyhow::ensure!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')),
        "request id contains unsupported characters"
    );
    Ok(())
}

fn validate_join_secret(value: &str) -> Result<()> {
    anyhow::ensure!(
        (32..=128).contains(&value.len()),
        "join secret must contain 32-128 characters"
    );
    anyhow::ensure!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "join secret must use URL-safe base64 characters"
    );
    Ok(())
}

fn client_name<'a>(state: &'a ControlState, id: &str) -> Option<&'a str> {
    state
        .clients
        .iter()
        .find(|item| item.endpoint_id == id)
        .map(|item| item.name.as_str())
}

fn anyhow_client_exists(state: &ControlState, id: &str) -> Result<(), ApiError> {
    if state.clients.iter().any(|item| item.endpoint_id == id) {
        Ok(())
    } else {
        Err(ApiError::bad("unknown client"))
    }
}

fn anyhow_node_exists(state: &ControlState, id: EndpointId) -> Result<(), ApiError> {
    if state.clients.iter().any(|item| item.endpoint_id == id.to_string())
        || state.edges.iter().any(|item| item.endpoint_id == id.to_string())
    {
        Ok(())
    } else {
        Err(ApiError::forbidden("node is not registered"))
    }
}

fn anyhow_relay_exists(state: &ControlState, id: EndpointId) -> Result<(), ApiError> {
    if state.relays.iter().any(|item| item.endpoint_id == id.to_string()) {
        Ok(())
    } else {
        Err(ApiError::forbidden("relay is not registered"))
    }
}

fn validate_name(name: &str) -> Result<()> {
    anyhow::ensure!(
        !name.is_empty() && name.len() <= 64,
        "name must contain 1-64 characters"
    );
    anyhow::ensure!(
        name.bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')),
        "name may contain only ASCII letters, digits, '-', '_', and '.'"
    );
    Ok(())
}

fn check_time(issued_at: i64, now: i64) -> Result<()> {
    anyhow::ensure!(
        issued_at.abs_diff(now) <= CLOCK_SKEW_SECS as u64,
        "request timestamp outside allowed window"
    );
    Ok(())
}

fn normalize_public_url(value: &str) -> Result<String> {
    let mut url = Url::parse(value).context("invalid public URL")?;
    anyhow::ensure!(
        url.query().is_none() && url.fragment().is_none(),
        "public URL cannot contain query or fragment"
    );
    let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
    anyhow::ensure!(
        url.scheme() == "https" || (url.scheme() == "http" && loopback),
        "public URL must use HTTPS unless it targets loopback"
    );
    let path = url.path().trim_end_matches('/').to_string();
    url.set_path(&path);
    Ok(url.to_string().trim_end_matches('/').to_string())
}

fn normalize_relay_url(value: &str) -> Result<String> {
    let mut url = Url::parse(value).context("invalid relay URL")?;
    anyhow::ensure!(
        url.query().is_none() && url.fragment().is_none(),
        "relay URL cannot contain query or fragment"
    );
    let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
    anyhow::ensure!(
        url.scheme() == "https" || (url.scheme() == "http" && loopback),
        "relay URL must use HTTPS unless it targets loopback"
    );
    if url.path().is_empty() {
        url.set_path("/");
    }
    Ok(url.to_string())
}

fn validate_qad_port(port: Option<u16>) -> Result<()> {
    anyhow::ensure!(port != Some(0), "QAD public port must be between 1 and 65535");
    Ok(())
}

fn random_token(bytes: usize) -> String {
    let mut value = vec![0u8; bytes];
    rand::rng().fill_bytes(&mut value);
    URL_SAFE_NO_PAD.encode(value)
}

fn open_exclusive(dir: &Path) -> Result<(scale_core::FileLock, SecretKey, db::Database, ControlState)> {
    let lock = scale_core::FileLock::try_acquire(&lock_path(dir))
        .context("control state is already in use (stop as-control before offline bootstrap)")?;
    let database = db::Database::open(&database_path(dir))?;
    let key = scale_core::read_secret(&key_path(dir))?;
    let state = database.load()?;
    Ok((lock, key, database, state))
}

fn key_path(dir: &Path) -> PathBuf {
    dir.join("control.key")
}
fn database_path(dir: &Path) -> PathBuf {
    dir.join("control.db")
}
fn relay_ca_key_path(dir: &Path) -> PathBuf {
    dir.join("relay-ca.key")
}
fn relay_ca_cert_path(dir: &Path) -> PathBuf {
    dir.join("relay-ca.der")
}
fn lock_path(dir: &Path) -> PathBuf {
    dir.join("control.lock")
}

fn load_or_create_relay_ca(dir: &Path) -> Result<(Vec<u8>, Issuer<'static, KeyPair>)> {
    let key_path = relay_ca_key_path(dir);
    let cert_path = relay_ca_cert_path(dir);
    match (key_path.exists(), cert_path.exists()) {
        (true, true) => load_relay_ca(dir),
        (false, false) => {
            let key = KeyPair::generate().context("generate Relay CA key")?;
            let mut params = CertificateParams::new(Vec::<String>::new())?;
            params
                .distinguished_name
                .push(DnType::CommonName, "agent-scale Control Relay CA");
            params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
            params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            let now = time::OffsetDateTime::now_utc();
            params.not_before = now - time::Duration::days(1);
            params.not_after = now + time::Duration::days(3650);
            let cert = params.self_signed(&key)?;
            let key_der = key.serialize_der();
            let cert_der = cert.der().to_vec();
            scale_core::atomic_write(&key_path, &key_der).with_context(|| format!("write {}", key_path.display()))?;
            scale_core::atomic_write(&cert_path, &cert_der)
                .with_context(|| format!("write {}", cert_path.display()))?;
            load_relay_ca(dir)
        }
        _ => anyhow::bail!("incomplete Relay CA state: relay-ca.key and relay-ca.der must both exist"),
    }
}

fn load_relay_ca(dir: &Path) -> Result<(Vec<u8>, Issuer<'static, KeyPair>)> {
    let key_der = std::fs::read(relay_ca_key_path(dir)).context("read Relay CA key")?;
    let cert_der = std::fs::read(relay_ca_cert_path(dir)).context("read Relay CA certificate")?;
    let key = KeyPair::try_from(key_der).context("parse Relay CA key")?;
    let issuer = Issuer::from_ca_cert_der(&cert_der.as_slice().into(), key).context("parse Relay CA certificate")?;
    Ok((cert_der, issuer))
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
    use axum::http::Request;
    use control_api::ProvisionerHttpRequest;
    use tower::ServiceExt;

    fn persist_test_state(database: &db::Database, state: &ControlState) {
        let previous = database.load().unwrap();
        database.apply_sync(&previous, state).unwrap();
    }

    async fn send_provisioner_request(
        store: Arc<Store>,
        request: ProvisionerHttpRequest,
    ) -> Result<Json<ProvisionerResponse>, ApiError> {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, request.authorization.parse().unwrap());
        provisioner_request(State(AppState(store)), headers, Bytes::from(request.body)).await
    }

    async fn send_provisioner_http(store: Arc<Store>, request: ProvisionerHttpRequest) -> (StatusCode, Vec<u8>) {
        let response = public_router(store)
            .oneshot(
                Request::post("/v1/provisioner")
                    .header(AUTHORIZATION, request.authorization)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(request.body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap()
            .to_vec();
        (status, body)
    }

    #[test]
    fn state_directory_and_admin_socket_are_not_cli_options() {
        assert!(Cli::try_parse_from(["as-control", "--admin-socket", "/tmp/admin.sock", "status"]).is_err());
        assert!(Cli::try_parse_from(["as-control", "--state-dir", "/tmp/control", "status"]).is_err());
    }

    #[test]
    fn bootstrap_is_a_single_top_level_command() {
        assert!(
            Cli::try_parse_from([
                "as-control",
                "bootstrap",
                "--public-url",
                "http://127.0.0.1:3350",
                "--audience",
                "test",
                "--relay-name",
                "primary",
                "--relay-url",
                "http://127.0.0.1:3340",
                "--relay-invite-out",
                "/tmp/relay.join",
            ])
            .is_ok()
        );
        assert!(Cli::try_parse_from(["as-control", "bootstrap", "client", "main"]).is_err());
        assert!(Cli::try_parse_from(["as-control", "prepare"]).is_err());
    }

    #[test]
    fn control_ca_signs_only_the_invited_relay_host() {
        let dir = tempfile::tempdir().unwrap();
        let (ca_der, issuer) = load_or_create_relay_ca(dir.path()).unwrap();
        assert!(!ca_der.is_empty());
        let key = KeyPair::generate().unwrap();
        let params = CertificateParams::new(vec!["relay.example.com".into()]).unwrap();
        let csr = params.serialize_request(&key).unwrap();
        let kind = InviteKind::Relay {
            url: "https://relay.example.com/".into(),
        };
        let certificate = issue_relay_tls_certificate(&Some(csr.der().to_vec()), &kind, Some(4433), &issuer)
            .unwrap()
            .unwrap();
        assert!(!certificate.is_empty());

        let wrong_key = KeyPair::generate().unwrap();
        let wrong = CertificateParams::new(vec!["other.example.com".into()])
            .unwrap()
            .serialize_request(&wrong_key)
            .unwrap();
        assert!(issue_relay_tls_certificate(&Some(wrong.der().to_vec()), &kind, Some(4433), &issuer).is_err());
    }

    #[test]
    fn relay_claim_reports_qad_port_with_its_csr() {
        let relay = InviteKind::Relay {
            url: "https://relay.example.com/".into(),
        };
        assert_eq!(
            validate_relay_claim(&relay, Some(4433), Some(&[1])).unwrap(),
            Some(4433)
        );
        assert!(validate_relay_claim(&relay, Some(4433), None).is_err());
        assert!(validate_relay_claim(&relay, None, Some(&[1])).is_err());
        assert!(validate_relay_claim(&InviteKind::Client, Some(4433), Some(&[1])).is_err());
    }

    #[test]
    fn bootstrap_is_idempotent_and_does_not_require_invitation_artifacts_after_enrollment() {
        let dir = tempfile::tempdir().unwrap();
        let relay_out = dir.path().join("bootstrap/relay.join");
        let run_bootstrap = || {
            bootstrap(
                dir.path().join("control"),
                "http://127.0.0.1:3350".into(),
                "test".into(),
                "relay-a".into(),
                "http://127.0.0.1:3340".into(),
                900,
                relay_out.clone(),
            )
        };
        run_bootstrap().unwrap();
        assert!(
            std::fs::read_to_string(&relay_out)
                .unwrap()
                .starts_with("http://127.0.0.1:3350/join#")
        );

        let control_dir = dir.path().join("control");
        let (lock, _key, database, mut state) = open_exclusive(&control_dir).unwrap();
        assert!(state.clients.is_empty());
        assert!(
            state
                .invites
                .iter()
                .all(|invite| !matches!(invite.invite.kind, InviteKind::Client))
        );
        run_bootstrap().unwrap();
        let relay_id = SecretKey::generate().public().to_string();
        state.relays.push(RelayRecord {
            name: "relay-a".into(),
            endpoint_id: relay_id.clone(),
            url: "http://127.0.0.1:3340/".into(),
            qad_port: None,
        });
        for invite in &mut state.invites {
            invite.state = InviteState::Claimed;
            invite.terminal_at = Some(unix_timestamp());
            invite.claimed_by = Some(relay_id.clone());
        }
        persist_test_state(&database, &state);
        drop(database);
        drop(lock);
        std::fs::remove_file(&relay_out).unwrap();

        run_bootstrap().unwrap();
        assert!(!relay_out.exists());
        assert!(
            bootstrap(
                control_dir,
                "http://127.0.0.1:9999".into(),
                "test".into(),
                "relay-a".into(),
                "http://127.0.0.1:3340".into(),
                900,
                relay_out,
            )
            .is_err()
        );
    }

    #[test]
    fn map_enforces_edge_ownership() {
        let key = SecretKey::generate();
        let a = SecretKey::generate();
        let b = SecretKey::generate();
        let edge = SecretKey::generate();
        let state = ControlState {
            schema: STATE_SCHEMA,
            audience: "test".into(),
            public_url: "http://127.0.0.1:1".into(),
            relay_ca_der: vec![1, 2, 3],
            revision: 3,
            relay_revision: 1,
            clients: vec![
                ClientRecord {
                    name: "a".into(),
                    endpoint_id: a.public().to_string(),
                    managed_by: None,
                    credential_generation: 1,
                    credential_issued_at: 0,
                    credential_expires_at: i64::MAX,
                },
                ClientRecord {
                    name: "b".into(),
                    endpoint_id: b.public().to_string(),
                    managed_by: None,
                    credential_generation: 1,
                    credential_issued_at: 0,
                    credential_expires_at: i64::MAX,
                },
            ],
            edges: vec![EdgeRecord {
                name: "box".into(),
                endpoint_id: edge.public().to_string(),
                owner_id: b.public().to_string(),
                credential_generation: 1,
                credential_issued_at: 0,
                credential_expires_at: i64::MAX,
            }],
            relays: vec![],
            invites: vec![],
            provisioners: vec![],
            revocations: vec![],
        };
        let edge_map = signed_map(&state, &key, edge.public()).unwrap();
        assert_eq!(edge_map.map.allowed_clients, vec![b.public().to_string()]);
        assert!(signed_map(&state, &key, a.public()).unwrap().map.edges.is_empty());
        assert_eq!(signed_map(&state, &key, b.public()).unwrap().map.edges.len(), 1);
    }

    #[tokio::test]
    async fn failed_persistence_does_not_publish_candidate_state() {
        let dir = tempfile::tempdir().unwrap();
        init(dir.path().into(), "http://127.0.0.1:3350".into(), "test".into()).unwrap();
        let (lock, _control_key, database, mut current) = open_exclusive(dir.path()).unwrap();
        let key = SecretKey::generate();
        let mut next = current.clone();
        next.clients = vec![
            ClientRecord {
                name: "duplicate".into(),
                endpoint_id: key.public().to_string(),
                managed_by: None,
                credential_generation: 1,
                credential_issued_at: 0,
                credential_expires_at: i64::MAX,
            },
            ClientRecord {
                name: "duplicate".into(),
                endpoint_id: SecretKey::generate().public().to_string(),
                managed_by: None,
                credential_generation: 1,
                credential_issued_at: 0,
                credential_expires_at: i64::MAX,
            },
        ];
        let store = Store {
            database,
            key,
            relay_ca: load_relay_ca(dir.path()).unwrap().1,
            state: Mutex::new(current.clone()),
            changed: Notify::new(),
            relay_changed: Notify::new(),
            _lock: lock,
        };

        assert!(persist_candidate(&store, &mut current, next, true).await.is_err());
        assert_eq!(current.revision, 0);
    }

    #[tokio::test]
    async fn client_edge_invites_are_self_owned_and_replay_protected() {
        let dir = tempfile::tempdir().unwrap();
        init(dir.path().into(), "http://127.0.0.1:3350".into(), "test".into()).unwrap();
        let (lock, control_key, database, mut state) = open_exclusive(dir.path()).unwrap();
        let client = SecretKey::generate();
        state.clients.push(ClientRecord {
            name: "main".into(),
            endpoint_id: client.public().to_string(),
            managed_by: None,
            credential_generation: 1,
            credential_issued_at: 0,
            credential_expires_at: i64::MAX,
        });
        persist_test_state(&database, &state);
        let store = Arc::new(Store {
            database,
            key: control_key,
            relay_ca: load_relay_ca(dir.path()).unwrap().1,
            state: Mutex::new(state),
            changed: Notify::new(),
            relay_changed: Notify::new(),
            _lock: lock,
        });

        let stranger = SecretKey::generate();
        let unauthorized = EdgeInviteRequest::sign(
            &stranger,
            "test".into(),
            "stranger-request".into(),
            unix_timestamp(),
            "box".into(),
            900,
        )
        .unwrap();
        let error = client_edge_invite(State(AppState(store.clone())), Json(unauthorized))
            .await
            .unwrap_err();
        assert_eq!(error.status, StatusCode::FORBIDDEN);

        let request = EdgeInviteRequest::sign(
            &client,
            "test".into(),
            "client-request".into(),
            unix_timestamp(),
            "box".into(),
            900,
        )
        .unwrap();
        let response = client_edge_invite(State(AppState(store.clone())), Json(request.clone()))
            .await
            .unwrap();
        assert!(response.0.join_url.contains("/join#"));
        let state = store.state.lock().await;
        assert_eq!(
            state.invites.last().unwrap().invite.kind,
            InviteKind::Edge {
                owner_id: client.public().to_string()
            }
        );
        drop(state);

        let error = client_edge_invite(State(AppState(store)), Json(request))
            .await
            .unwrap_err();
        assert_eq!(error.status, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn clients_can_remove_only_their_current_edge_identity() {
        let dir = tempfile::tempdir().unwrap();
        init(dir.path().into(), "http://127.0.0.1:3350".into(), "test".into()).unwrap();
        let (lock, control_key, database, mut state) = open_exclusive(dir.path()).unwrap();
        let client = SecretKey::generate();
        let other_client = SecretKey::generate();
        let edge = SecretKey::generate();
        state.clients = vec![
            ClientRecord {
                name: "main".into(),
                endpoint_id: client.public().to_string(),
                managed_by: None,
                credential_generation: 1,
                credential_issued_at: 0,
                credential_expires_at: i64::MAX,
            },
            ClientRecord {
                name: "other".into(),
                endpoint_id: other_client.public().to_string(),
                managed_by: None,
                credential_generation: 1,
                credential_issued_at: 0,
                credential_expires_at: i64::MAX,
            },
        ];
        state.edges.push(EdgeRecord {
            name: "box".into(),
            endpoint_id: edge.public().to_string(),
            owner_id: client.public().to_string(),
            credential_generation: 1,
            credential_issued_at: 0,
            credential_expires_at: i64::MAX,
        });
        persist_test_state(&database, &state);
        let revision = state.revision;
        let store = Arc::new(Store {
            database,
            key: control_key,
            relay_ca: load_relay_ca(dir.path()).unwrap().1,
            state: Mutex::new(state),
            changed: Notify::new(),
            relay_changed: Notify::new(),
            _lock: lock,
        });

        let unauthorized = EdgeRemoveRequest::sign(
            &other_client,
            "test".into(),
            "other-request".into(),
            unix_timestamp(),
            "box".into(),
            edge.public().to_string(),
        )
        .unwrap();
        assert!(
            client_edge_remove(State(AppState(store.clone())), Json(unauthorized))
                .await
                .is_err()
        );

        let request = EdgeRemoveRequest::sign(
            &client,
            "test".into(),
            "remove-request".into(),
            unix_timestamp(),
            "box".into(),
            edge.public().to_string(),
        )
        .unwrap();
        let map = client_edge_remove(State(AppState(store.clone())), Json(request))
            .await
            .unwrap()
            .0;
        assert_eq!(map.map.revision, revision + 1);
        assert!(map.map.edges.is_empty());
        assert!(store.state.lock().await.edges.is_empty());
    }

    #[tokio::test]
    async fn provisioner_requests_are_scoped_authenticated_and_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        init(dir.path().into(), "http://127.0.0.1:3350".into(), "test".into()).unwrap();
        let (lock, control_key, database, mut state) = open_exclusive(dir.path()).unwrap();
        let provisioner = SecretKey::generate();
        let other_provisioner = SecretKey::generate();
        let client = SecretKey::generate();
        let other_client = SecretKey::generate();
        state.provisioners = vec![
            ProvisionerRecord {
                name: "controller-a".into(),
                endpoint_id: provisioner.public().to_string(),
            },
            ProvisionerRecord {
                name: "controller-b".into(),
                endpoint_id: other_provisioner.public().to_string(),
            },
        ];
        state.clients = vec![
            ClientRecord {
                name: "job-a".into(),
                endpoint_id: client.public().to_string(),
                managed_by: Some(provisioner.public().to_string()),
                credential_generation: 1,
                credential_issued_at: 0,
                credential_expires_at: i64::MAX,
            },
            ClientRecord {
                name: "job-b".into(),
                endpoint_id: other_client.public().to_string(),
                managed_by: Some(other_provisioner.public().to_string()),
                credential_generation: 1,
                credential_issued_at: 0,
                credential_expires_at: i64::MAX,
            },
        ];
        persist_test_state(&database, &state);
        let store = Arc::new(Store {
            database,
            key: control_key,
            relay_ca: load_relay_ca(dir.path()).unwrap().1,
            state: Mutex::new(state),
            changed: Notify::new(),
            relay_changed: Notify::new(),
            _lock: lock,
        });

        let topology_request = ProvisionerRequest::sign(
            &provisioner,
            "test".into(),
            "topology-1".into(),
            unix_timestamp(),
            None,
            ProvisionerAction::GetTopology,
        )
        .unwrap();
        let response = send_provisioner_request(store.clone(), topology_request)
            .await
            .unwrap()
            .0;
        let ProvisionerResponse::Topology(topology) = response else {
            panic!("expected topology response");
        };
        assert_eq!(topology.clients.len(), 1);
        assert_eq!(topology.clients[0].name, "job-a");

        let stranger = SecretKey::generate();
        let unauthorized = ProvisionerRequest::sign(
            &stranger,
            "test".into(),
            "topology-2".into(),
            unix_timestamp(),
            None,
            ProvisionerAction::GetTopology,
        )
        .unwrap();
        let error = send_provisioner_request(store.clone(), unauthorized).await.unwrap_err();
        assert_eq!(error.status, StatusCode::FORBIDDEN);

        let revision = store.state.lock().await.revision;
        let invite_action = ProvisionerAction::InviteClient {
            name: "job-new".into(),
            ttl_secs: 900,
            secret: "a".repeat(43),
        };
        let invite_request = ProvisionerRequest::sign(
            &provisioner,
            "test".into(),
            "invite-client-1".into(),
            unix_timestamp(),
            Some(revision),
            invite_action.clone(),
        )
        .unwrap();
        let first = send_provisioner_request(store.clone(), invite_request.clone())
            .await
            .unwrap()
            .0;
        let revision_after_first = store.state.lock().await.revision;
        assert_eq!(revision_after_first, revision + 1);
        let retry = send_provisioner_request(store.clone(), invite_request).await.unwrap().0;
        assert_eq!(first, retry);
        assert_eq!(store.state.lock().await.revision, revision_after_first);

        let reused_request_id = ProvisionerRequest::sign(
            &provisioner,
            "test".into(),
            "invite-client-1".into(),
            unix_timestamp(),
            Some(revision_after_first),
            ProvisionerAction::InviteClient {
                name: "different".into(),
                ttl_secs: 900,
                secret: "b".repeat(43),
            },
        )
        .unwrap();
        let error = send_provisioner_request(store.clone(), reused_request_id)
            .await
            .unwrap_err();
        assert_eq!(error.status, StatusCode::CONFLICT);

        let stale = ProvisionerRequest::sign(
            &provisioner,
            "test".into(),
            "invite-client-stale".into(),
            unix_timestamp(),
            Some(revision),
            ProvisionerAction::InviteClient {
                name: "stale".into(),
                ttl_secs: 900,
                secret: "c".repeat(43),
            },
        )
        .unwrap();
        let error = send_provisioner_request(store, stale).await.unwrap_err();
        assert_eq!(error.status, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn provisioner_enrollment_persists_client_edge_grouping() {
        let dir = tempfile::tempdir().unwrap();
        init(dir.path().into(), "http://127.0.0.1:3350".into(), "test".into()).unwrap();
        let (lock, control_key, database, mut state) = open_exclusive(dir.path()).unwrap();
        let provisioner = SecretKey::generate();
        state.provisioners.push(ProvisionerRecord {
            name: "controller".into(),
            endpoint_id: provisioner.public().to_string(),
        });
        persist_test_state(&database, &state);
        let store = Arc::new(Store {
            database,
            key: control_key,
            relay_ca: load_relay_ca(dir.path()).unwrap().1,
            state: Mutex::new(state),
            changed: Notify::new(),
            relay_changed: Notify::new(),
            _lock: lock,
        });

        let client_secret = "c".repeat(43);
        let client_invite = ProvisionerRequest::sign(
            &provisioner,
            "test".into(),
            "client-invite".into(),
            unix_timestamp(),
            Some(store.state.lock().await.revision),
            ProvisionerAction::InviteClient {
                name: "job".into(),
                ttl_secs: 900,
                secret: client_secret,
            },
        )
        .unwrap();
        let ProvisionerResponse::Invite(client_result) =
            send_provisioner_request(store.clone(), client_invite).await.unwrap().0
        else {
            panic!("expected client invite");
        };
        let client_token = JoinToken::decode(client_result.join_url.split_once('#').unwrap().1).unwrap();
        let client_key = SecretKey::generate();
        let client_claim =
            ClaimRequest::sign(client_token, &client_key, unix_timestamp(), "client-claim".into()).unwrap();
        let _ = claim(State(AppState(store.clone())), Json(client_claim)).await.unwrap();

        let edge_invite = ProvisionerRequest::sign(
            &provisioner,
            "test".into(),
            "edge-invite".into(),
            unix_timestamp(),
            Some(store.state.lock().await.revision),
            ProvisionerAction::InviteEdge {
                owner: "job".into(),
                name: "lab".into(),
                ttl_secs: 900,
                secret: "e".repeat(43),
            },
        )
        .unwrap();
        let ProvisionerResponse::Invite(edge_result) =
            send_provisioner_request(store.clone(), edge_invite).await.unwrap().0
        else {
            panic!("expected edge invite");
        };
        let edge_token = JoinToken::decode(edge_result.join_url.split_once('#').unwrap().1).unwrap();
        let edge_key = SecretKey::generate();
        let edge_claim = ClaimRequest::sign(edge_token, &edge_key, unix_timestamp(), "edge-claim".into()).unwrap();
        let _ = claim(State(AppState(store.clone())), Json(edge_claim)).await.unwrap();

        let topology = provisioner_topology(&*store.state.lock().await, &provisioner.public().to_string());
        assert_eq!(topology.clients.len(), 1);
        assert_eq!(topology.clients[0].name, "job");
        assert_eq!(topology.clients[0].endpoint_id, client_key.public().to_string());
        assert_eq!(topology.clients[0].edges.len(), 1);
        assert_eq!(topology.clients[0].edges[0].name, "lab");
        assert_eq!(topology.clients[0].edges[0].endpoint_id, edge_key.public().to_string());
    }

    #[test]
    fn expired_invites_do_not_reserve_names() {
        let key = SecretKey::generate();
        let mut state = ControlState {
            schema: STATE_SCHEMA,
            audience: "test".into(),
            public_url: "http://127.0.0.1:1".into(),
            relay_ca_der: vec![1, 2, 3],
            revision: 1,
            relay_revision: 1,
            clients: vec![],
            edges: vec![],
            relays: vec![],
            invites: vec![],
            provisioners: vec![],
            revocations: vec![],
        };
        create_invite(&key, &mut state, "job".into(), InviteKind::Client, 1).unwrap();
        state.invites[0].invite.expires_at = unix_timestamp() - 1;
        assert!(validate_invite_name(&state, "job", &InviteKind::Client).is_ok());
    }

    #[test]
    fn invitation_cleanup_retains_terminal_history_for_seven_days_without_revision_change() {
        let key = SecretKey::generate();
        let now = unix_timestamp();
        let mut state = ControlState {
            schema: STATE_SCHEMA,
            audience: "test".into(),
            public_url: "http://127.0.0.1:1".into(),
            relay_ca_der: vec![1, 2, 3],
            revision: 9,
            relay_revision: 1,
            clients: vec![],
            edges: vec![],
            relays: vec![],
            invites: vec![],
            provisioners: vec![],
            revocations: vec![],
        };
        for name in ["recent-expired", "old-expired", "recent-claimed", "old-revoked"] {
            create_invite(&key, &mut state, name.into(), InviteKind::Client, 60).unwrap();
        }
        state.invites[0].invite.expires_at = now - 60;
        state.invites[1].invite.expires_at = now - INVITATION_RETENTION_SECS - 1;
        state.invites[2].state = InviteState::Claimed;
        state.invites[2].terminal_at = Some(now - 60);
        state.invites[3].state = InviteState::Revoked;
        state.invites[3].terminal_at = Some(now - INVITATION_RETENTION_SECS - 1);
        assert!(cleanup_invitations(&mut state, now));
        assert_eq!(
            state
                .invites
                .iter()
                .map(|item| item.invite.name.as_str())
                .collect::<Vec<_>>(),
            vec!["recent-expired", "recent-claimed"]
        );
        assert_eq!(state.revision, 9);
    }

    #[tokio::test]
    async fn provisioner_http_is_idempotent_and_recovers_topology_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        init(dir.path().into(), "http://127.0.0.1:3350".into(), "test".into()).unwrap();
        let (lock, key, database, mut state) = open_exclusive(dir.path()).unwrap();
        let provisioner = SecretKey::generate();
        state.provisioners.push(ProvisionerRecord {
            name: "controller".into(),
            endpoint_id: provisioner.public().to_string(),
        });
        persist_test_state(&database, &state);
        let store = Arc::new(Store {
            database,
            key,
            relay_ca: load_relay_ca(dir.path()).unwrap().1,
            state: Mutex::new(state),
            changed: Notify::new(),
            relay_changed: Notify::new(),
            _lock: lock,
        });
        let invite = ProvisionerRequest::sign(
            &provisioner,
            "test".into(),
            "http-idempotency".into(),
            unix_timestamp(),
            Some(0),
            ProvisionerAction::InviteClient {
                name: "job".into(),
                ttl_secs: 900,
                secret: "s".repeat(43),
            },
        )
        .unwrap();
        let first = send_provisioner_http(store.clone(), invite.clone()).await;
        let retry = send_provisioner_http(store.clone(), invite).await;
        assert_eq!(first.0, StatusCode::OK);
        assert_eq!(first, retry);
        drop(store);

        let (lock, key, database, state) = open_exclusive(dir.path()).unwrap();
        let store = Arc::new(Store {
            database,
            key,
            relay_ca: load_relay_ca(dir.path()).unwrap().1,
            state: Mutex::new(state),
            changed: Notify::new(),
            relay_changed: Notify::new(),
            _lock: lock,
        });
        let topology = ProvisionerRequest::sign(
            &provisioner,
            "test".into(),
            "topology-after-restart".into(),
            unix_timestamp(),
            None,
            ProvisionerAction::GetTopology,
        )
        .unwrap();
        let (status, body) = send_provisioner_http(store, topology).await;
        assert_eq!(status, StatusCode::OK);
        let response: ProvisionerResponse = serde_json::from_slice(&body).unwrap();
        let ProvisionerResponse::Topology(topology) = response else {
            panic!("expected topology")
        };
        assert_eq!(topology.revision, 1);
        assert_eq!(topology.invites.len(), 1);
    }
}
