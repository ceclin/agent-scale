//! Single-instance coordination server for centers, edges, and private relays.

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
    CONTROL_PROTOCOL_VERSION, CenterInfo, ClaimRequest, ControlStatus, EdgeInfo, EdgeInviteRequest, Invite, InviteInfo,
    InviteKind, InviteResult, JoinResult, JoinToken, ManagedCenterInfo, ManagedEdgeInfo, NodeMap, Overview,
    ProvisionerAction, ProvisionerRequest, ProvisionerResponse, ProvisionerTopology, RelayInfo, RelayNodeInfo,
    SignedNodeMap, WatchRequest, action_hash, hash_secret, verify_provisioner_authorization,
};
use iroh_base::{EndpointId, SecretKey};
use rand::Rng;
use relay_api::{MembershipSnapshot, RELAY_PROTOCOL_VERSION, RelayMember, SignedSnapshot};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, Notify};
use tracing::info;
use tracing_subscriber::EnvFilter;
use url::Url;

const STATE_SCHEMA: u32 = 3;
const CLOCK_SKEW_SECS: i64 = 300;
const DEFAULT_TTL_SECS: u64 = 15 * 60;

#[derive(Parser)]
#[command(name = "as-control", about = "agent-scale multi-center control plane")]
struct Cli {
    /// Local administration socket. It is never exposed over HTTP.
    #[arg(long, global = true, env = "AGENT_SCALE_CONTROL_ADMIN_SOCKET")]
    admin_socket: Option<PathBuf>,
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
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
    /// Create initial invitations before the first server start.
    Bootstrap {
        #[command(subcommand)]
        command: BootstrapCommand,
    },
    /// Run the public control API.
    Run {
        #[arg(long, default_value = "127.0.0.1:3350")]
        bind: SocketAddr,
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
    /// Show all registered nodes and the current revision.
    Status,
    /// Manage centers through the local administration socket.
    Center {
        #[command(subcommand)]
        command: CenterCommand,
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
enum BootstrapCommand {
    Center {
        name: String,
        #[arg(long, default_value_t = DEFAULT_TTL_SECS)]
        ttl_secs: u64,
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
    /// Create the initial relay invitation. The server must be stopped.
    Relay {
        name: String,
        url: String,
        #[arg(long, default_value_t = DEFAULT_TTL_SECS)]
        ttl_secs: u64,
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum CenterCommand {
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
        new_center: String,
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
    ListCenters,
    ListEdges,
    ListRelays,
    ListInvites,
    ListProvisioners,
    InviteCenter { name: String, ttl_secs: u64 },
    InviteEdge { name: String, owner: String, ttl_secs: u64 },
    InviteRelay { name: String, url: String, ttl_secs: u64 },
    RevokeInvite { invite_id: String },
    RemoveCenter { name: String },
    TransferEdge { edge: String, new_center: String },
    RemoveEdge { edge: String },
    RemoveRelay { name: String },
    AddProvisioner { name: String, endpoint_id: String },
    RemoveProvisioner { name: String },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "result", content = "data", rename_all = "snake_case")]
enum LocalAdminResponse {
    Overview(Overview),
    Centers(Vec<CenterInfo>),
    Edges(Vec<EdgeInfo>),
    Relays(Vec<RelayNodeInfo>),
    Invites(Vec<InviteInfo>),
    Provisioners(Vec<ProvisionerInfo>),
    Invite(InviteResult),
    Ok,
    Error(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CenterRecord {
    name: String,
    endpoint_id: String,
    #[serde(default)]
    managed_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EdgeRecord {
    name: String,
    endpoint_id: String,
    owner_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RelayRecord {
    name: String,
    endpoint_id: String,
    url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProvisionerRecord {
    name: String,
    endpoint_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProvisionerInfo {
    name: String,
    endpoint_id: String,
    centers: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum InviteState {
    Pending,
    Claimed,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InviteRecord {
    invite: Invite,
    state: InviteState,
    claimed_by: Option<String>,
    #[serde(default)]
    request_id: Option<String>,
    #[serde(default)]
    managed_by: Option<String>,
    #[serde(default)]
    request_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ControlState {
    schema: u32,
    audience: String,
    public_url: String,
    revision: u64,
    #[serde(default)]
    centers: Vec<CenterRecord>,
    #[serde(default)]
    edges: Vec<EdgeRecord>,
    #[serde(default)]
    relays: Vec<RelayRecord>,
    #[serde(default)]
    invites: Vec<InviteRecord>,
    #[serde(default)]
    provisioners: Vec<ProvisionerRecord>,
}

struct Store {
    dir: PathBuf,
    key: SecretKey,
    state: Mutex<ControlState>,
    changed: Notify,
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
    let admin_socket = cli.admin_socket.unwrap_or_else(default_admin_socket);
    match cli.command {
        Command::Init {
            public_url,
            audience,
            state_dir,
        } => init(state_dir, public_url, audience),
        Command::Bootstrap { command } => match command {
            BootstrapCommand::Center {
                name,
                ttl_secs,
                state_dir,
            } => bootstrap_center(state_dir, name, ttl_secs),
            BootstrapCommand::Relay {
                name,
                url,
                ttl_secs,
                state_dir,
            } => bootstrap_relay(state_dir, name, url, ttl_secs),
        },
        Command::Run { bind, state_dir } => run(state_dir, bind, admin_socket).await,
        Command::Status => print_admin_response(admin_call(&admin_socket, LocalAdminRequest::Overview).await?),
        Command::Center { command } => {
            let request = match command {
                CenterCommand::Invite { name, ttl_secs } => LocalAdminRequest::InviteCenter { name, ttl_secs },
                CenterCommand::Ls => LocalAdminRequest::ListCenters,
                CenterCommand::Rm { name } => LocalAdminRequest::RemoveCenter { name },
            };
            print_admin_response(admin_call(&admin_socket, request).await?)
        }
        Command::Edge { command } => {
            let request = match command {
                EdgeCommand::Invite { name, owner, ttl_secs } => {
                    LocalAdminRequest::InviteEdge { name, owner, ttl_secs }
                }
                EdgeCommand::Ls => LocalAdminRequest::ListEdges,
                EdgeCommand::Transfer { edge, new_center } => LocalAdminRequest::TransferEdge { edge, new_center },
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

fn default_state_dir() -> PathBuf {
    std::env::var_os("AGENT_SCALE_CONTROL_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::home_dir().map(|home| home.join(".agent-scale-control")))
        .unwrap_or_else(|| PathBuf::from(".agent-scale-control"))
}

fn default_admin_socket() -> PathBuf {
    default_state_dir().join("admin.sock")
}

fn init(state_dir: Option<PathBuf>, public_url: String, audience: String) -> Result<()> {
    let dir = state_dir.unwrap_or_else(default_state_dir);
    anyhow::ensure!(!audience.trim().is_empty(), "--audience must not be empty");
    let public_url = normalize_public_url(&public_url)?;
    scale_core::ensure_private_dir(&dir)?;
    anyhow::ensure!(
        !key_path(&dir).exists() && !state_path(&dir).exists(),
        "control state already exists"
    );
    let key = scale_core::load_or_create_secret(&key_path(&dir))?;
    let state = ControlState {
        schema: STATE_SCHEMA,
        audience,
        public_url,
        revision: 0,
        centers: vec![],
        edges: vec![],
        relays: vec![],
        invites: vec![],
        provisioners: vec![],
    };
    persist_state(&dir, &state)?;
    println!("initialized control {}", key.public());
    println!("next: as-control bootstrap center <name> --state-dir {}", dir.display());
    Ok(())
}

fn bootstrap_center(state_dir: Option<PathBuf>, name: String, ttl_secs: u64) -> Result<()> {
    validate_name(&name)?;
    let dir = state_dir.unwrap_or_else(default_state_dir);
    let (_lock, key, mut state) = open_exclusive(&dir)?;
    anyhow::ensure!(
        state.centers.is_empty(),
        "a Center already exists; use `as-control center invite`"
    );
    state
        .invites
        .retain(|invite| !matches!(invite.invite.kind, InviteKind::Center));
    let result = create_invite(&key, &mut state, name, InviteKind::Center, ttl_secs)?;
    persist_state(&dir, &state)?;
    println!("{}", result.join_url);
    Ok(())
}

fn bootstrap_relay(state_dir: Option<PathBuf>, name: String, url: String, ttl_secs: u64) -> Result<()> {
    validate_name(&name)?;
    let url = normalize_relay_url(&url)?;
    let dir = state_dir.unwrap_or_else(default_state_dir);
    let (_lock, key, mut state) = open_exclusive(&dir)?;
    anyhow::ensure!(
        state.relays.is_empty(),
        "a Relay already exists; use `as-control relay invite`"
    );
    state.invites.retain(|invite| {
        !matches!(invite.invite.kind, InviteKind::Relay { .. }) || invite.state == InviteState::Claimed
    });
    let result = create_invite(&key, &mut state, name, InviteKind::Relay { url }, ttl_secs)?;
    persist_state(&dir, &state)?;
    println!("{}", result.join_url);
    Ok(())
}

async fn run(state_dir: Option<PathBuf>, bind: SocketAddr, admin_socket: PathBuf) -> Result<()> {
    let dir = state_dir.unwrap_or_else(default_state_dir);
    let (lock, key, state) = open_exclusive(&dir)?;
    anyhow::ensure!(
        state.schema == STATE_SCHEMA,
        "unsupported state schema {}",
        state.schema
    );
    let store = Arc::new(Store {
        dir,
        key,
        state: Mutex::new(state),
        changed: Notify::new(),
        _lock: lock,
    });
    let app_state = AppState(store.clone());
    let app = Router::new()
        .route("/healthz", get(|| async { StatusCode::NO_CONTENT }))
        .route("/v1/status", get(status))
        .route("/v1/claim", post(claim))
        .route("/v1/edge/invite", post(center_edge_invite))
        .route("/v1/provisioner", post(provisioner_request))
        .route("/v1/watch", post(watch))
        .route("/v1/relay/watch", post(relay_watch))
        .with_state(app_state);
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
    let admin = tokio::spawn(serve_local_admin(admin_socket, store));
    tokio::select! {
        result = axum::serve(listener, app) => result.context("control server"),
        result = admin => result.context("local administration task")?,
    }
}

async fn status(State(AppState(store)): State<AppState>) -> Json<ControlStatus> {
    let state = store.state.lock().await;
    Json(ControlStatus {
        audience: state.audience.clone(),
        control_url: state.public_url.clone(),
        control_id: store.key.public().to_string(),
        revision: state.revision,
        centers: state.centers.len(),
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
    match state.invites[index].state {
        InviteState::Pending => {}
        InviteState::Claimed if state.invites[index].claimed_by.as_deref() == Some(&request.claim.endpoint_id) => {
            let map = signed_map(&state, &store.key, endpoint_id).map_err(ApiError::internal)?;
            return Ok(Json(JoinResult {
                name: state.invites[index].invite.name.clone(),
                kind: state.invites[index].invite.kind.clone(),
                map,
            }));
        }
        InviteState::Claimed => return Err(ApiError::conflict("invite was already claimed")),
        InviteState::Revoked => return Err(ApiError::gone("invite was revoked")),
    }
    let mut next = state.clone();
    let invite = next.invites[index].invite.clone();
    let managed_by = next.invites[index].managed_by.clone();
    add_claimed_node(&mut next, &invite, endpoint_id, managed_by.as_deref())?;
    next.invites[index].state = InviteState::Claimed;
    next.invites[index].claimed_by = Some(endpoint_id.to_string());
    next.revision = next
        .revision
        .checked_add(1)
        .ok_or_else(|| ApiError::internal("revision overflow"))?;
    let map = signed_map(&next, &store.key, endpoint_id).map_err(ApiError::internal)?;
    persist_candidate(&store, &mut state, next, true)?;
    Ok(Json(JoinResult {
        name: invite.name,
        kind: invite.kind,
        map,
    }))
}

async fn center_edge_invite(
    State(AppState(store)): State<AppState>,
    Json(request): Json<EdgeInviteRequest>,
) -> Result<Json<InviteResult>, ApiError> {
    let center_id = request.verify().map_err(ApiError::unauthorized)?;
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
        .centers
        .iter()
        .find(|center| center.endpoint_id == center_id.to_string())
        .map(|center| center.managed_by.clone())
        .ok_or_else(|| ApiError::forbidden("center is not registered"))?;
    if state
        .invites
        .iter()
        .any(|invite| invite.request_id.as_deref() == Some(&request.request_id))
    {
        return Err(ApiError::conflict("edge invitation request was already used"));
    }
    let kind = InviteKind::Edge {
        owner_id: center_id.to_string(),
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
    commit_candidate(&store, &mut state, next)?;
    Ok(Json(result))
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

    let response = dispatch_provisioner_mutation(&store, &mut state, &provisioner_id, &request)?;
    Ok(Json(response))
}

fn dispatch_provisioner_mutation(
    store: &Store,
    state: &mut ControlState,
    provisioner_id: &str,
    request: &ProvisionerRequest,
) -> Result<ProvisionerResponse, ApiError> {
    match &request.action {
        ProvisionerAction::GetTopology => unreachable!("queries are handled before mutation dispatch"),
        ProvisionerAction::InviteCenter { name, ttl_secs, secret } => provisioner_invite(
            store,
            state,
            provisioner_id,
            request,
            name,
            InviteKind::Center,
            *ttl_secs,
            secret,
        ),
        ProvisionerAction::InviteEdge {
            owner,
            name,
            ttl_secs,
            secret,
        } => {
            let owner_id = managed_center_id(state, owner, provisioner_id)?;
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
            commit_candidate(store, state, next)?;
            provisioner_ok(state)
        }
        ProvisionerAction::RemoveCenter { name } => {
            let Some(center) = state
                .centers
                .iter()
                .find(|item| item.name == *name && item.managed_by.as_deref() == Some(provisioner_id))
                .cloned()
            else {
                if state.centers.iter().any(|item| item.name == *name) {
                    return Err(ApiError::forbidden("center is managed by another authority"));
                }
                return provisioner_ok(state);
            };
            if state.edges.iter().any(|edge| edge.owner_id == center.endpoint_id) {
                return Err(ApiError::conflict("center still owns edges"));
            }
            if state.invites.iter().any(|invite| {
                invite_is_active_pending(invite)
                    && matches!(&invite.invite.kind, InviteKind::Edge { owner_id } if owner_id == &center.endpoint_id)
            }) {
                return Err(ApiError::conflict("center still has pending edge invites"));
            }
            check_expected_revision(state, request.expected_revision)?;
            let mut next = state.clone();
            next.centers.retain(|item| item.endpoint_id != center.endpoint_id);
            commit_candidate(store, state, next)?;
            provisioner_ok(state)
        }
        ProvisionerAction::RemoveEdge { owner, name } => {
            let owner_id = managed_center_id(state, owner, provisioner_id)?;
            let exists = state
                .edges
                .iter()
                .any(|item| item.owner_id == owner_id && item.name == *name);
            if !exists {
                return provisioner_ok(state);
            }
            check_expected_revision(state, request.expected_revision)?;
            let mut next = state.clone();
            next.edges
                .retain(|item| !(item.owner_id == owner_id && item.name == *name));
            commit_candidate(store, state, next)?;
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
            let owner_id = managed_center_id(state, owner, provisioner_id)?;
            let new_owner_id = managed_center_id(state, new_owner, provisioner_id)?;
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
                return Err(ApiError::conflict("target center already has an edge with this name"));
            }
            check_expected_revision(state, request.expected_revision)?;
            let mut next = state.clone();
            next.edges
                .iter_mut()
                .find(|item| item.owner_id == owner_id && item.name == *name && item.endpoint_id == endpoint_id)
                .expect("managed edge was checked above")
                .owner_id = new_owner_id;
            commit_candidate(store, state, next)?;
            provisioner_ok(state)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn provisioner_invite(
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
    commit_candidate(store, state, next)?;
    Ok(ProvisionerResponse::Invite(result))
}

fn provisioner_topology(state: &ControlState, provisioner_id: &str) -> ProvisionerTopology {
    let centers = state
        .centers
        .iter()
        .filter(|center| center.managed_by.as_deref() == Some(provisioner_id))
        .map(|center| ManagedCenterInfo {
            name: center.name.clone(),
            endpoint_id: center.endpoint_id.clone(),
            edges: state
                .edges
                .iter()
                .filter(|edge| edge.owner_id == center.endpoint_id)
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
        centers,
        invites,
    }
}

fn provisioner_ok(state: &ControlState) -> Result<ProvisionerResponse, ApiError> {
    Ok(ProvisionerResponse::Ok {
        revision: state.revision,
    })
}

fn managed_center_id(state: &ControlState, name: &str, provisioner_id: &str) -> Result<String, ApiError> {
    state
        .centers
        .iter()
        .find(|center| center.name == name && center.managed_by.as_deref() == Some(provisioner_id))
        .map(|center| center.endpoint_id.clone())
        .ok_or_else(|| ApiError::bad(format!("unknown managed center '{name}'")))
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
    wait_for_revision(&store, endpoint_id, request.known_revision, false).await?;
    let state = store.state.lock().await;
    Ok(Json(
        signed_map(&state, &store.key, endpoint_id).map_err(ApiError::internal)?,
    ))
}

async fn relay_watch(
    State(AppState(store)): State<AppState>,
    Json(request): Json<WatchRequest>,
) -> Result<Json<SignedSnapshot>, ApiError> {
    let endpoint_id = request.verify().map_err(ApiError::unauthorized)?;
    check_time(request.issued_at, unix_timestamp()).map_err(ApiError::unauthorized)?;
    wait_for_revision(&store, endpoint_id, request.known_revision, true).await?;
    let state = store.state.lock().await;
    anyhow_relay_exists(&state, endpoint_id)?;
    let mut members = Vec::with_capacity(state.centers.len() + state.edges.len());
    members.extend(state.centers.iter().map(|center| RelayMember {
        name: format!("center/{}", center.name),
        endpoint_id: center.endpoint_id.clone(),
    }));
    members.extend(state.edges.iter().map(|edge| RelayMember {
        name: format!(
            "edge/{}/{}",
            center_name(&state, &edge.owner_id).unwrap_or("unknown"),
            edge.name
        ),
        endpoint_id: edge.endpoint_id.clone(),
    }));
    members.sort_by(|left, right| left.endpoint_id.cmp(&right.endpoint_id));
    let snapshot = MembershipSnapshot {
        protocol_version: RELAY_PROTOCOL_VERSION,
        audience: state.audience.clone(),
        version: state.revision,
        issued_at: unix_timestamp(),
        members,
    };
    Ok(Json(
        SignedSnapshot::sign(snapshot, &store.key).map_err(ApiError::internal)?,
    ))
}

async fn wait_for_revision(
    store: &Arc<Store>,
    endpoint_id: EndpointId,
    known: u64,
    relay: bool,
) -> Result<(), ApiError> {
    loop {
        let notified = store.changed.notified();
        {
            let state = store.state.lock().await;
            if relay {
                anyhow_relay_exists(&state, endpoint_id)?;
            } else {
                anyhow_node_exists(&state, endpoint_id)?;
            }
            if state.revision > known {
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
        LocalAdminRequest::ListCenters => {
            let state = store.state.lock().await;
            Ok(LocalAdminResponse::Centers(overview(&state).centers))
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
                        centers: state
                            .centers
                            .iter()
                            .filter(|center| center.managed_by.as_deref() == Some(&item.endpoint_id))
                            .count(),
                    })
                    .collect(),
            ))
        }
        LocalAdminRequest::InviteCenter { name, ttl_secs } => {
            local_create_invite(store, name, InviteKind::Center, ttl_secs, None).await
        }
        LocalAdminRequest::InviteEdge { name, owner, ttl_secs } => {
            let (owner_id, managed_by) = {
                let state = store.state.lock().await;
                state
                    .centers
                    .iter()
                    .find(|center| center.name == owner)
                    .map(|center| (center.endpoint_id.clone(), center.managed_by.clone()))
                    .ok_or_else(|| ApiError::bad(format!("unknown center '{owner}'")))?
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
            if invite.state == InviteState::Claimed {
                return Err(ApiError::conflict("claimed invites cannot be revoked"));
            }
            invite.state = InviteState::Revoked;
            commit_candidate(store, &mut state, next)?;
            Ok(LocalAdminResponse::Ok)
        }
        LocalAdminRequest::RemoveCenter { name } => {
            let mut state = store.state.lock().await;
            let center = state
                .centers
                .iter()
                .find(|center| center.name == name)
                .cloned()
                .ok_or_else(|| ApiError::bad(format!("unknown center '{name}'")))?;
            if state.edges.iter().any(|edge| edge.owner_id == center.endpoint_id) {
                return Err(ApiError::conflict("center still owns edges"));
            }
            if state.invites.iter().any(|invite| {
                invite_is_active_pending(invite)
                    && matches!(
                        &invite.invite.kind,
                        InviteKind::Edge { owner_id } if owner_id == &center.endpoint_id
                    )
            }) {
                return Err(ApiError::conflict("center still has pending edge invites"));
            }
            let mut next = state.clone();
            next.centers.retain(|item| item.endpoint_id != center.endpoint_id);
            commit_candidate(store, &mut state, next)?;
            Ok(LocalAdminResponse::Ok)
        }
        LocalAdminRequest::TransferEdge { edge, new_center } => {
            let (owner_name, edge_name) = parse_edge_ref(&edge)?;
            let mut state = store.state.lock().await;
            let old_owner = center_id_by_name(&state, owner_name)?;
            let new_owner = center_id_by_name(&state, &new_center)?;
            if state
                .edges
                .iter()
                .any(|item| item.owner_id == new_owner && item.name == edge_name)
            {
                return Err(ApiError::conflict("target center already has an edge with this name"));
            }
            let mut next = state.clone();
            let record = next
                .edges
                .iter_mut()
                .find(|item| item.owner_id == old_owner && item.name == edge_name)
                .ok_or_else(|| ApiError::bad(format!("unknown edge '{edge}'")))?;
            record.owner_id = new_owner;
            commit_candidate(store, &mut state, next)?;
            Ok(LocalAdminResponse::Ok)
        }
        LocalAdminRequest::RemoveEdge { edge } => {
            let (owner_name, edge_name) = parse_edge_ref(&edge)?;
            let mut state = store.state.lock().await;
            let owner_id = center_id_by_name(&state, owner_name)?;
            let mut next = state.clone();
            let before = next.edges.len();
            next.edges
                .retain(|item| !(item.owner_id == owner_id && item.name == edge_name));
            if next.edges.len() == before {
                return Err(ApiError::bad(format!("unknown edge '{edge}'")));
            }
            commit_candidate(store, &mut state, next)?;
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
            commit_candidate(store, &mut state, next)?;
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
            commit_candidate(store, &mut state, next)?;
            Ok(LocalAdminResponse::Ok)
        }
        LocalAdminRequest::RemoveProvisioner { name } => {
            let mut state = store.state.lock().await;
            let Some(provisioner) = state.provisioners.iter().find(|item| item.name == name).cloned() else {
                return Err(ApiError::bad(format!("unknown provisioner '{name}'")));
            };
            if state
                .centers
                .iter()
                .any(|center| center.managed_by.as_deref() == Some(&provisioner.endpoint_id))
            {
                return Err(ApiError::conflict("provisioner still manages centers"));
            }
            if state.invites.iter().any(|invite| {
                invite_is_active_pending(invite) && invite.managed_by.as_deref() == Some(&provisioner.endpoint_id)
            }) {
                return Err(ApiError::conflict("provisioner still owns pending invites"));
            }
            let mut next = state.clone();
            next.provisioners
                .retain(|item| item.endpoint_id != provisioner.endpoint_id);
            commit_candidate(store, &mut state, next)?;
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
    commit_candidate(store, &mut state, next)?;
    Ok(LocalAdminResponse::Invite(result))
}

fn overview(state: &ControlState) -> Overview {
    Overview {
        revision: state.revision,
        centers: state
            .centers
            .iter()
            .map(|center| CenterInfo {
                name: center.name.clone(),
                endpoint_id: center.endpoint_id.clone(),
                edges: state
                    .edges
                    .iter()
                    .filter(|edge| edge.owner_id == center.endpoint_id)
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
                owner_name: center_name(state, &edge.owner_id).unwrap_or("unknown").into(),
            })
            .collect(),
        relays: state
            .relays
            .iter()
            .map(|relay| RelayNodeInfo {
                name: relay.name.clone(),
                endpoint_id: relay.endpoint_id.clone(),
                url: relay.url.clone(),
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
        .ok_or_else(|| ApiError::bad("edge must be written as <center>/<edge>"))
}

fn center_id_by_name(state: &ControlState, name: &str) -> Result<String, ApiError> {
    state
        .centers
        .iter()
        .find(|center| center.name == name)
        .map(|center| center.endpoint_id.clone())
        .ok_or_else(|| ApiError::bad(format!("unknown center '{name}'")))
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
            println!("centers:  {}", value.centers.len());
            println!("edges:    {}", value.edges.len());
            println!("relays:   {}", value.relays.len());
        }
        LocalAdminResponse::Centers(values) => {
            for center in values {
                println!("{}", center.name);
                println!("  endpoint_id: {}", center.endpoint_id);
                println!("  edges:       {}", center.edges);
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
                println!("  centers:    {}", provisioner.centers);
            }
        }
        LocalAdminResponse::Invite(value) => println!("{}", value.join_url),
        LocalAdminResponse::Ok => {}
        LocalAdminResponse::Error(message) => anyhow::bail!(message),
    }
    Ok(())
}

fn commit_candidate(store: &Store, current: &mut ControlState, mut next: ControlState) -> Result<(), ApiError> {
    next.revision = next
        .revision
        .checked_add(1)
        .ok_or_else(|| ApiError::internal("revision overflow"))?;
    persist_candidate(store, current, next, true)
}

fn persist_candidate(
    store: &Store,
    current: &mut ControlState,
    next: ControlState,
    notify: bool,
) -> Result<(), ApiError> {
    persist_state(&store.dir, &next).map_err(ApiError::internal)?;
    *current = next;
    if notify {
        store.changed.notify_waiters();
    }
    Ok(())
}

fn add_claimed_node(
    state: &mut ControlState,
    invite: &Invite,
    endpoint_id: EndpointId,
    managed_by: Option<&str>,
) -> Result<(), ApiError> {
    match &invite.kind {
        InviteKind::Center => {
            if state
                .centers
                .iter()
                .any(|item| item.name == invite.name || item.endpoint_id == endpoint_id.to_string())
            {
                return Err(ApiError::conflict("center name or identity already exists"));
            }
            state.centers.push(CenterRecord {
                name: invite.name.clone(),
                endpoint_id: endpoint_id.to_string(),
                managed_by: managed_by.map(ToOwned::to_owned),
            });
        }
        InviteKind::Edge { owner_id } => {
            anyhow_center_exists(state, owner_id)?;
            if state.edges.iter().any(|item| {
                item.owner_id == *owner_id && item.name == invite.name || item.endpoint_id == endpoint_id.to_string()
            }) {
                return Err(ApiError::conflict("edge name or identity already exists"));
            }
            state.edges.push(EdgeRecord {
                name: invite.name.clone(),
                endpoint_id: endpoint_id.to_string(),
                owner_id: owner_id.clone(),
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
        })
        .collect();
    let (allowed_centers, edges) =
        if let Some(edge) = state.edges.iter().find(|edge| edge.endpoint_id == recipient_string) {
            (vec![edge.owner_id.clone()], vec![])
        } else if state
            .centers
            .iter()
            .any(|center| center.endpoint_id == recipient_string)
        {
            let edges = state
                .edges
                .iter()
                .filter(|edge| edge.owner_id == recipient_string)
                .map(|edge| EdgeInfo {
                    name: edge.name.clone(),
                    endpoint_id: edge.endpoint_id.clone(),
                    owner_id: edge.owner_id.clone(),
                    owner_name: center_name(state, &edge.owner_id).unwrap_or("unknown").to_string(),
                })
                .collect();
            (vec![], edges)
        } else if state.relays.iter().any(|relay| relay.endpoint_id == recipient_string) {
            (vec![], vec![])
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
            allowed_centers,
            edges,
        },
        key,
    )
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
        InviteKind::Center => state.centers.iter().any(|item| item.name == name),
        InviteKind::Edge { owner_id } => state
            .edges
            .iter()
            .any(|item| item.owner_id == *owner_id && item.name == name),
        InviteKind::Relay { url } => state.relays.iter().any(|item| item.name == name || item.url == *url),
    };
    let pending_duplicate = state.invites.iter().any(|record| {
        invite_is_active_pending(record)
            && match (&record.invite.kind, kind) {
                (InviteKind::Center, InviteKind::Center) => record.invite.name == name,
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

fn center_name<'a>(state: &'a ControlState, id: &str) -> Option<&'a str> {
    state
        .centers
        .iter()
        .find(|item| item.endpoint_id == id)
        .map(|item| item.name.as_str())
}

fn anyhow_center_exists(state: &ControlState, id: &str) -> Result<(), ApiError> {
    if state.centers.iter().any(|item| item.endpoint_id == id) {
        Ok(())
    } else {
        Err(ApiError::bad("unknown center"))
    }
}

fn anyhow_node_exists(state: &ControlState, id: EndpointId) -> Result<(), ApiError> {
    if state.centers.iter().any(|item| item.endpoint_id == id.to_string())
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

fn random_token(bytes: usize) -> String {
    let mut value = vec![0u8; bytes];
    rand::rng().fill_bytes(&mut value);
    URL_SAFE_NO_PAD.encode(value)
}

fn open_exclusive(dir: &Path) -> Result<(scale_core::FileLock, SecretKey, ControlState)> {
    let lock = scale_core::FileLock::try_acquire(&lock_path(dir))
        .context("control state is already in use (stop as-control before offline bootstrap)")?;
    let key = scale_core::read_secret(&key_path(dir))?;
    let state = scale_core::read_json(&state_path(dir))?;
    Ok((lock, key, state))
}

fn persist_state(dir: &Path, state: &ControlState) -> Result<()> {
    scale_core::write_json(&state_path(dir), state)
}

fn key_path(dir: &Path) -> PathBuf {
    dir.join("control.key")
}
fn state_path(dir: &Path) -> PathBuf {
    dir.join("state.json")
}
fn lock_path(dir: &Path) -> PathBuf {
    dir.join("control.lock")
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
    use control_api::ProvisionerHttpRequest;

    async fn send_provisioner_request(
        store: Arc<Store>,
        request: ProvisionerHttpRequest,
    ) -> Result<Json<ProvisionerResponse>, ApiError> {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, request.authorization.parse().unwrap());
        provisioner_request(State(AppState(store)), headers, Bytes::from(request.body)).await
    }

    #[test]
    fn bootstrap_is_single_center_and_persistent() {
        let dir = tempfile::tempdir().unwrap();
        init(Some(dir.path().into()), "http://127.0.0.1:3350".into(), "test".into()).unwrap();
        bootstrap_center(Some(dir.path().into()), "main".into(), 900).unwrap();
        let (_, key, state) = open_exclusive(dir.path()).unwrap();
        assert_eq!(state.invites.len(), 1);
        assert_eq!(state.invites[0].invite.control_id, key.public().to_string());
        drop(state);
    }

    #[test]
    fn bootstrap_relay_is_signed_and_replaces_pending_invite() {
        let dir = tempfile::tempdir().unwrap();
        init(Some(dir.path().into()), "http://127.0.0.1:3350".into(), "test".into()).unwrap();
        bootstrap_relay(
            Some(dir.path().into()),
            "relay-a".into(),
            "http://localhost:3340".into(),
            900,
        )
        .unwrap();
        bootstrap_relay(
            Some(dir.path().into()),
            "relay-a".into(),
            "http://localhost:3340".into(),
            900,
        )
        .unwrap();
        let (_, key, state) = open_exclusive(dir.path()).unwrap();
        assert_eq!(state.invites.len(), 1);
        assert_eq!(state.invites[0].invite.control_id, key.public().to_string());
        assert_eq!(
            state.invites[0].invite.kind,
            InviteKind::Relay {
                url: "http://localhost:3340/".into()
            }
        );
    }

    #[test]
    fn bootstrap_relay_validates_input() {
        let dir = tempfile::tempdir().unwrap();
        init(Some(dir.path().into()), "http://127.0.0.1:3350".into(), "test".into()).unwrap();
        assert!(
            bootstrap_relay(
                Some(dir.path().into()),
                "bad name".into(),
                "https://relay.example.com".into(),
                900,
            )
            .is_err()
        );
        assert!(
            bootstrap_relay(
                Some(dir.path().into()),
                "relay-a".into(),
                "http://relay.example.com".into(),
                900,
            )
            .is_err()
        );
        assert!(
            bootstrap_relay(
                Some(dir.path().into()),
                "relay-a".into(),
                "https://relay.example.com".into(),
                0,
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
            revision: 3,
            centers: vec![
                CenterRecord {
                    name: "a".into(),
                    endpoint_id: a.public().to_string(),
                    managed_by: None,
                },
                CenterRecord {
                    name: "b".into(),
                    endpoint_id: b.public().to_string(),
                    managed_by: None,
                },
            ],
            edges: vec![EdgeRecord {
                name: "box".into(),
                endpoint_id: edge.public().to_string(),
                owner_id: b.public().to_string(),
            }],
            relays: vec![],
            invites: vec![],
            provisioners: vec![],
        };
        let edge_map = signed_map(&state, &key, edge.public()).unwrap();
        assert_eq!(edge_map.map.allowed_centers, vec![b.public().to_string()]);
        assert!(signed_map(&state, &key, a.public()).unwrap().map.edges.is_empty());
        assert_eq!(signed_map(&state, &key, b.public()).unwrap().map.edges.len(), 1);
    }

    #[test]
    fn failed_persistence_does_not_publish_candidate_state() {
        let dir = tempfile::tempdir().unwrap();
        let invalid_dir = dir.path().join("not-a-directory");
        std::fs::write(&invalid_dir, b"file").unwrap();
        let key = SecretKey::generate();
        let mut current = ControlState {
            schema: STATE_SCHEMA,
            audience: "test".into(),
            public_url: "http://127.0.0.1:1".into(),
            revision: 1,
            centers: vec![],
            edges: vec![],
            relays: vec![],
            invites: vec![],
            provisioners: vec![],
        };
        let mut next = current.clone();
        next.revision = 2;
        let store = Store {
            dir: invalid_dir,
            key,
            state: Mutex::new(current.clone()),
            changed: Notify::new(),
            _lock: scale_core::FileLock::acquire(&dir.path().join("control.lock")).unwrap(),
        };

        assert!(persist_candidate(&store, &mut current, next, true).is_err());
        assert_eq!(current.revision, 1);
    }

    #[tokio::test]
    async fn center_edge_invites_are_self_owned_and_replay_protected() {
        let dir = tempfile::tempdir().unwrap();
        init(Some(dir.path().into()), "http://127.0.0.1:3350".into(), "test".into()).unwrap();
        let (lock, control_key, mut state) = open_exclusive(dir.path()).unwrap();
        let center = SecretKey::generate();
        state.centers.push(CenterRecord {
            name: "main".into(),
            endpoint_id: center.public().to_string(),
            managed_by: None,
        });
        persist_state(dir.path(), &state).unwrap();
        let store = Arc::new(Store {
            dir: dir.path().into(),
            key: control_key,
            state: Mutex::new(state),
            changed: Notify::new(),
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
        let error = center_edge_invite(State(AppState(store.clone())), Json(unauthorized))
            .await
            .unwrap_err();
        assert_eq!(error.status, StatusCode::FORBIDDEN);

        let request = EdgeInviteRequest::sign(
            &center,
            "test".into(),
            "center-request".into(),
            unix_timestamp(),
            "box".into(),
            900,
        )
        .unwrap();
        let response = center_edge_invite(State(AppState(store.clone())), Json(request.clone()))
            .await
            .unwrap();
        assert!(response.0.join_url.contains("/join#"));
        let state = store.state.lock().await;
        assert_eq!(
            state.invites.last().unwrap().invite.kind,
            InviteKind::Edge {
                owner_id: center.public().to_string()
            }
        );
        drop(state);

        let error = center_edge_invite(State(AppState(store)), Json(request))
            .await
            .unwrap_err();
        assert_eq!(error.status, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn provisioner_requests_are_scoped_authenticated_and_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        init(Some(dir.path().into()), "http://127.0.0.1:3350".into(), "test".into()).unwrap();
        let (lock, control_key, mut state) = open_exclusive(dir.path()).unwrap();
        let provisioner = SecretKey::generate();
        let other_provisioner = SecretKey::generate();
        let center = SecretKey::generate();
        let other_center = SecretKey::generate();
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
        state.centers = vec![
            CenterRecord {
                name: "job-a".into(),
                endpoint_id: center.public().to_string(),
                managed_by: Some(provisioner.public().to_string()),
            },
            CenterRecord {
                name: "job-b".into(),
                endpoint_id: other_center.public().to_string(),
                managed_by: Some(other_provisioner.public().to_string()),
            },
        ];
        persist_state(dir.path(), &state).unwrap();
        let store = Arc::new(Store {
            dir: dir.path().into(),
            key: control_key,
            state: Mutex::new(state),
            changed: Notify::new(),
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
        assert_eq!(topology.centers.len(), 1);
        assert_eq!(topology.centers[0].name, "job-a");

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
        let invite_action = ProvisionerAction::InviteCenter {
            name: "job-new".into(),
            ttl_secs: 900,
            secret: "a".repeat(43),
        };
        let invite_request = ProvisionerRequest::sign(
            &provisioner,
            "test".into(),
            "invite-center-1".into(),
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
            "invite-center-1".into(),
            unix_timestamp(),
            Some(revision_after_first),
            ProvisionerAction::InviteCenter {
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
            "invite-center-stale".into(),
            unix_timestamp(),
            Some(revision),
            ProvisionerAction::InviteCenter {
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
    async fn provisioner_enrollment_persists_center_edge_grouping() {
        let dir = tempfile::tempdir().unwrap();
        init(Some(dir.path().into()), "http://127.0.0.1:3350".into(), "test".into()).unwrap();
        let (lock, control_key, mut state) = open_exclusive(dir.path()).unwrap();
        let provisioner = SecretKey::generate();
        state.provisioners.push(ProvisionerRecord {
            name: "controller".into(),
            endpoint_id: provisioner.public().to_string(),
        });
        persist_state(dir.path(), &state).unwrap();
        let store = Arc::new(Store {
            dir: dir.path().into(),
            key: control_key,
            state: Mutex::new(state),
            changed: Notify::new(),
            _lock: lock,
        });

        let center_secret = "c".repeat(43);
        let center_invite = ProvisionerRequest::sign(
            &provisioner,
            "test".into(),
            "center-invite".into(),
            unix_timestamp(),
            Some(store.state.lock().await.revision),
            ProvisionerAction::InviteCenter {
                name: "job".into(),
                ttl_secs: 900,
                secret: center_secret,
            },
        )
        .unwrap();
        let ProvisionerResponse::Invite(center_result) =
            send_provisioner_request(store.clone(), center_invite).await.unwrap().0
        else {
            panic!("expected center invite");
        };
        let center_token = JoinToken::decode(center_result.join_url.split_once('#').unwrap().1).unwrap();
        let center_key = SecretKey::generate();
        let center_claim =
            ClaimRequest::sign(center_token, &center_key, unix_timestamp(), "center-claim".into()).unwrap();
        let _ = claim(State(AppState(store.clone())), Json(center_claim)).await.unwrap();

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
        assert_eq!(topology.centers.len(), 1);
        assert_eq!(topology.centers[0].name, "job");
        assert_eq!(topology.centers[0].endpoint_id, center_key.public().to_string());
        assert_eq!(topology.centers[0].edges.len(), 1);
        assert_eq!(topology.centers[0].edges[0].name, "lab");
        assert_eq!(topology.centers[0].edges[0].endpoint_id, edge_key.public().to_string());
    }

    #[test]
    fn expired_invites_do_not_reserve_names() {
        let key = SecretKey::generate();
        let mut state = ControlState {
            schema: STATE_SCHEMA,
            audience: "test".into(),
            public_url: "http://127.0.0.1:1".into(),
            revision: 1,
            centers: vec![],
            edges: vec![],
            relays: vec![],
            invites: vec![],
            provisioners: vec![],
        };
        create_invite(&key, &mut state, "job".into(), InviteKind::Center, 1).unwrap();
        state.invites[0].invite.expires_at = unix_timestamp() - 1;
        assert!(validate_invite_name(&state, "job", &InviteKind::Center).is_ok());
    }
}
