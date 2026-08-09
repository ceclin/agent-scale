//! Centralizes local state conventions so every Client process resolves the
//! same identity and IPC namespace.

use std::ops::{Deref, DerefMut};
use std::path::PathBuf;

use anyhow::{Context, Result};
use iroh::SecretKey;
use protocol::{ExecParams, McpTransport};
use serde::{Deserialize, Serialize};
#[cfg(windows)]
use sha2::{Digest, Sha256};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
const CONFIG_SCHEMA: u32 = 1;

/// Client home: $AGENT_SCALE_HOME or ~/.agent-scale.
pub fn home() -> PathBuf {
    if let Ok(h) = std::env::var("AGENT_SCALE_HOME") {
        return PathBuf::from(h);
    }
    // home_dir() is correct cross-platform (USERPROFILE on Windows, $HOME with a
    // passwd-db fallback on Unix). Fail loudly rather than scatter client keys
    // and config into the cwd when there's genuinely no home.
    std::env::home_dir()
        .expect("no home directory found; set $AGENT_SCALE_HOME (or $HOME / %USERPROFILE%)")
        .join(".agent-scale")
}

pub fn key_path() -> PathBuf {
    home().join("client.key")
}
pub fn config_path() -> PathBuf {
    home().join("config.json")
}
pub fn daemon_dir() -> PathBuf {
    home().join("daemon")
}
pub fn local_endpoint() -> String {
    #[cfg(unix)]
    {
        daemon_dir().join("sock").to_string_lossy().into_owned()
    }
    #[cfg(windows)]
    {
        // Named pipes live in a machine-wide namespace. Key the name by the
        // configured Client home so independent profiles owned by one user can
        // run concurrently without exposing the path itself in the pipe name.
        let normalized = home().to_string_lossy().replace('/', "\\").to_lowercase();
        let digest = hex::encode(Sha256::digest(normalized.as_bytes()));
        format!(r"\\.\pipe\agent-scale-{}", &digest[..24])
    }
}
pub fn registry_path() -> PathBuf {
    daemon_dir().join("registry.json")
}
pub fn log_path() -> PathBuf {
    daemon_dir().join("log")
}
pub fn daemon_lock_path() -> PathBuf {
    daemon_dir().join("instance.lock")
}

/// Use this whenever a caller may initialize the Client identity on demand.
pub fn load_or_create_key() -> Result<SecretKey> {
    scale_core::load_or_create_secret(&key_path())
}

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub schema_version: u32,
    #[serde(default)]
    pub edges: Vec<EdgeCfg>,
    /// Present only in managed mode; verify its cached signature before use.
    #[serde(default)]
    pub control: Option<ControlCfg>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schema_version: CONFIG_SCHEMA,
            edges: Vec::new(),
            control: None,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ControlCfg {
    pub name: String,
    pub url: String,
    pub control_id: String,
    pub audience: String,
    pub map: control_api::SignedNodeMap,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct EdgeCfg {
    pub name: String,
    pub endpoint_id: String,
    /// Ordered candidates used when direct discovery is unavailable.
    pub relays: Vec<String>,
    /// Prevents simple-mode edits from overriding Control-owned state.
    #[serde(default)]
    pub managed: bool,
}

pub fn load_config() -> Result<Config> {
    let p = config_path();
    let data =
        std::fs::read(&p).with_context(|| format!("read config {} (run `keygen` + `edge add` first)", p.display()))?;
    parse_config(&data)
}

/// Like `load_config`, but a missing file yields an empty config.
pub fn load_config_or_default() -> Result<Config> {
    let p = config_path();
    match std::fs::read(&p) {
        Ok(data) => parse_config(&data),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
        Err(e) => Err(e).with_context(|| format!("read {}", p.display())),
    }
}

pub fn save_config(cfg: &Config) -> Result<()> {
    scale_core::write_json(&config_path(), cfg)
}

pub struct ConfigTransaction {
    config: Config,
    _lock: scale_core::FileLock,
}

impl ConfigTransaction {
    pub fn commit(self) -> Result<()> {
        save_config(&self.config)
    }
}

impl Deref for ConfigTransaction {
    type Target = Config;

    fn deref(&self) -> &Self::Target {
        &self.config
    }
}

impl DerefMut for ConfigTransaction {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.config
    }
}

pub fn config_transaction() -> Result<ConfigTransaction> {
    let lock = scale_core::FileLock::acquire(&home().join("config.transaction.lock"))?;
    let config = load_config_or_default()?;
    Ok(ConfigTransaction { config, _lock: lock })
}

fn parse_config(data: &[u8]) -> Result<Config> {
    let config: Config = serde_json::from_slice(data).context("parse config.json")?;
    anyhow::ensure!(
        config.schema_version == CONFIG_SCHEMA,
        "unsupported config schema {}; remove config.json and enroll again",
        config.schema_version
    );
    Ok(config)
}

/// Treat this as discovery metadata only; lifecycle control stays on private IPC.
#[derive(Serialize, Deserialize)]
pub struct Registry {
    pub pid: u32,
    pub endpoint: String,
    pub version: String,
}

/// The local IPC request envelope shared by short-lived clients and the daemon.
#[derive(Serialize, Deserialize)]
pub struct ClientReq {
    pub edge: String,
    pub op: ClientOp,
}

#[derive(Serialize, Deserialize)]
pub struct LocalRequest {
    pub version: String,
    pub command: LocalCommand,
}

#[derive(Serialize, Deserialize)]
pub enum LocalCommand {
    Work(ClientReq),
    Admin(DaemonAdmin),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum DaemonAdmin {
    Status,
    Reload,
    Shutdown,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub pid: u32,
    pub version: String,
    pub active_requests: usize,
    pub configured_edges: usize,
}

#[derive(Serialize, Deserialize)]
pub enum ClientOp {
    Exec(ExecParams),
    Upload {
        local: String,
        remote: String,
    },
    Download {
        remote: String,
        local: String,
    },
    McpList,
    McpUpsert {
        name: String,
        transport: McpTransport,
    },
    McpRemove {
        name: String,
    },
    /// Open a transparent MCP pipe to the edge's named MCP server.
    McpConnect {
        name: String,
    },
}
