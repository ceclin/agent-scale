use as_edge::iroh_edge;
use std::{
    collections::HashSet,
    io::IsTerminal,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use control_api::{ClaimRequest, InviteKind, JoinResult, JoinToken, SignedNodeMap, WatchRequest};
use iroh::SecretKey;
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

mod service;

use service::{install as service_install, status as service_status, uninstall as service_uninstall};

#[derive(Parser)]
#[command(name = "as-edge", about = "Edge agent for agent-scale")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Enroll from a one-time as-control invitation.
    Join(JoinArgs),
    /// Run an agent — turns this machine into a test-machine endpoint.
    Run(RunArgs),
    /// Print an agent's EndpointId (generating its key on first use).
    Id { who: String },
    /// List agent identities on this machine.
    Ls,
    /// Remove an agent identity (its key + pinned center).
    Rm { who: String },
    /// Manage MCP definitions stored by one local edge identity.
    Mcp {
        #[arg(long)]
        who: String,
        #[command(subcommand)]
        command: McpCommand,
    },
    /// Manage the current-user background service.
    Service {
        #[command(subcommand)]
        command: ServiceCommand,
    },
}

#[derive(Subcommand)]
enum McpCommand {
    Add {
        name: String,
        #[arg(long, conflicts_with_all = ["sse", "argv"])]
        http: Option<String>,
        #[arg(long, conflicts_with = "argv")]
        sse: Option<String>,
        #[arg(long)]
        cwd: Option<String>,
        #[arg(trailing_var_arg = true)]
        argv: Vec<String>,
    },
    Ls,
    Rm {
        name: String,
    },
}

#[derive(Args)]
struct JoinArgs {
    join_url: String,
    #[arg(long, conflicts_with = "install")]
    foreground: bool,
    #[arg(long)]
    install: bool,
}

#[derive(Subcommand)]
enum ServiceCommand {
    /// Install and start a persistent simple-mode edge service.
    Install { who: String },
    /// Show the persistent service status.
    Status { who: String },
    /// Remove the service while preserving its identity.
    Uninstall { who: String },
}

#[derive(Args)]
struct RunArgs {
    /// Who this agent is for. Its identity lives at
    /// $AGENT_SCALE_HOME/<who>/agent.key (or ~/.agent-scale/...). Use distinct
    /// values to run several agents on one machine (e.g. share a test box).
    who: Option<String>,

    /// Custom relay URL(s) the edge registers with (repeatable). When omitted
    /// in simple mode, uses the official relays bundled with iroh.
    #[arg(short = 'r', long = "relay")]
    relays: Vec<String>,

    /// Trusted center EndpointId (strict). Omit for trust-on-first-use.
    #[arg(long)]
    center: Option<String>,

    /// Explicit key-file path, overriding WHO. Generated on first use.
    #[arg(long)]
    secret_key_file: Option<PathBuf>,
}

fn main() -> std::process::ExitCode {
    // Built-in dispatch: the edge sets AS_EDGE_BUILTIN when re-execing for fd/rg
    // (portable, no argv[0] tricks); a matching argv[0] — installed/symlinked as
    // `fd` or `rg` — also works as a fallback.
    let arg0 = std::env::args().next().unwrap_or_default();
    let basename = Path::new(&arg0)
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    let which = std::env::var(as_edge::exec::BUILTIN_ENV).unwrap_or(basename);

    match which.as_str() {
        "fd" => {
            fd_lib::main();
            std::process::ExitCode::SUCCESS
        }
        "rg" => rg_lib::main(),
        _ => {
            agent_main();
            std::process::ExitCode::SUCCESS
        }
    }
}

fn home_base() -> PathBuf {
    if let Ok(h) = std::env::var("AGENT_SCALE_HOME") {
        return PathBuf::from(h);
    }
    // home_dir() is correct cross-platform (USERPROFILE on Windows, $HOME with a
    // passwd-db fallback on Unix). Fail loudly rather than scatter the agent key
    // into the cwd when there's genuinely no home.
    std::env::home_dir()
        .expect("no home directory found; set $AGENT_SCALE_HOME (or $HOME / %USERPROFILE%)")
        .join(".agent-scale")
}

fn who_dir(who: &str) -> Result<PathBuf> {
    anyhow::ensure!(
        !who.is_empty() && who != "." && who != ".." && !who.contains('/') && !who.contains('\\'),
        "invalid WHO: {who:?}"
    );
    Ok(home_base().join(who))
}

fn resolve_key_path(who: Option<&str>, key_file: Option<&PathBuf>) -> Result<PathBuf> {
    if let Some(p) = key_file {
        return Ok(p.clone());
    }
    let who =
        who.ok_or_else(|| anyhow::anyhow!("specify WHO (e.g. `run me --relay ...`) or --secret-key-file <PATH>"))?;
    Ok(who_dir(who)?.join("agent.key"))
}

fn load_or_create_key(path: &Path) -> Result<SecretKey> {
    scale_core::load_or_create_secret(path)
}

fn agent_main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Join(args) => {
            let rt = tokio::runtime::Runtime::new().unwrap();
            if let Err(error) = rt.block_on(join_control(args)) {
                eprintln!("as-edge: {error:#}");
                std::process::exit(1);
            }
        }
        Cmd::Run(args) => {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(run(args));
        }
        Cmd::Id { who } => match resolve_key_path(Some(&who), None) {
            Ok(p) => match load_or_create_key(&p) {
                Ok(key) => println!("{}", key.public()),
                Err(error) => {
                    eprintln!("as-edge: {error:#}");
                    std::process::exit(1);
                }
            },
            Err(e) => {
                eprintln!("as-edge: {e:#}");
                std::process::exit(2);
            }
        },
        Cmd::Ls => {
            if let Err(e) = cmd_ls() {
                eprintln!("as-edge: {e:#}");
                std::process::exit(1);
            }
        }
        Cmd::Rm { who } => {
            if let Err(e) = cmd_rm(&who) {
                eprintln!("as-edge: {e:#}");
                std::process::exit(1);
            }
        }
        Cmd::Mcp { who, command } => {
            if let Err(error) = cmd_mcp(&who, command) {
                eprintln!("as-edge: {error:#}");
                std::process::exit(1);
            }
        }
        Cmd::Service { command } => {
            let result = match command {
                ServiceCommand::Install { who } => service_install(&who).map(|()| {
                    println!("installed and started edge service '{who}'");
                }),
                ServiceCommand::Status { who } => service_status(&who),
                ServiceCommand::Uninstall { who } => service_uninstall(&who),
            };
            if let Err(error) = result {
                eprintln!("as-edge: {error:#}");
                std::process::exit(1);
            }
        }
    }
}

fn cmd_mcp(who: &str, command: McpCommand) -> Result<()> {
    let store = as_edge::mcp_registry::RegistryStore::new(who_dir(who)?.join("mcp.json"));
    match command {
        McpCommand::Add {
            name,
            http,
            sse,
            cwd,
            argv,
        } => {
            anyhow::ensure!(
                cwd.is_none() || (http.is_none() && sse.is_none()),
                "--cwd is only valid for stdio MCP servers"
            );
            let transport = parse_mcp_transport(http, sse, cwd, argv)?;
            let updated = store.upsert(name.clone(), transport)?;
            println!("{} MCP '{name}'", if updated { "updated" } else { "added" });
        }
        McpCommand::Ls => {
            let catalog = store.list()?;
            if catalog.servers.is_empty() {
                println!("no MCP servers configured");
            }
            for (name, transport) in catalog.servers {
                println!("{name}: {}", describe_mcp(&transport));
            }
        }
        McpCommand::Rm { name } => {
            store.remove(&name)?;
            println!("removed MCP '{name}'");
        }
    }
    Ok(())
}

fn parse_mcp_transport(
    http: Option<String>,
    sse: Option<String>,
    cwd: Option<String>,
    argv: Vec<String>,
) -> Result<protocol::McpTransport> {
    if let Some(url) = http {
        return Ok(protocol::McpTransport::Http { url });
    }
    if let Some(url) = sse {
        return Ok(protocol::McpTransport::Sse { url });
    }
    let (command, args) = argv
        .split_first()
        .context("specify `-- <command>`, `--http <url>`, or `--sse <url>`")?;
    Ok(protocol::McpTransport::Stdio {
        command: command.clone(),
        args: args.to_vec(),
        cwd,
    })
}

fn describe_mcp(transport: &protocol::McpTransport) -> String {
    match transport {
        protocol::McpTransport::Stdio { command, args, cwd } => {
            let mut value = format!("stdio: {command}");
            if !args.is_empty() {
                value.push(' ');
                value.push_str(&args.join(" "));
            }
            if let Some(cwd) = cwd {
                value.push_str(&format!(" (cwd: {cwd})"));
            }
            value
        }
        protocol::McpTransport::Http { url } => format!("http: {url}"),
        protocol::McpTransport::Sse { url } => format!("sse: {url}"),
    }
}

fn cmd_ls() -> Result<()> {
    let base = home_base();
    let mut found = false;
    if let Ok(entries) = std::fs::read_dir(&base) {
        let mut dirs: Vec<_> = entries.flatten().map(|e| e.path()).collect();
        dirs.sort();
        for dir in dirs {
            let keyfile = dir.join("agent.key");
            if !keyfile.is_file() {
                continue;
            }
            found = true;
            let who = dir.file_name().unwrap_or_default().to_string_lossy();
            let id = std::fs::read(&keyfile)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                .map(|a| SecretKey::from_bytes(&a).public().to_string())
                .unwrap_or_else(|| "<unreadable>".into());
            let pinned = std::fs::read_to_string(dir.join("trusted_center"))
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            println!("{who}");
            println!("  endpoint_id:   {id}");
            if let Ok(data) = std::fs::read(dir.join("control.json")) {
                match serde_json::from_slice::<ControlProfile>(&data) {
                    Ok(profile) => {
                        println!("  control:       {}", profile.control_url);
                        println!("  owner:         {}", profile.map.map.allowed_centers.join(", "));
                    }
                    Err(_) => println!("  control:       <unreadable>"),
                }
            } else {
                match pinned {
                    Some(c) => println!("  trusts center: {c}"),
                    None => println!("  trusts center: (none pinned yet)"),
                }
            }
        }
    }
    if !found {
        println!("no agents (create one with `as-edge run <who>`)");
    }
    Ok(())
}

fn cmd_rm(who: &str) -> Result<()> {
    let dir = who_dir(who)?;
    anyhow::ensure!(dir.join("agent.key").is_file(), "no agent named '{who}'");
    std::fs::remove_dir_all(&dir).with_context(|| format!("remove {}", dir.display()))?;
    println!("removed agent '{who}'");
    Ok(())
}

async fn run(args: RunArgs) {
    if let Err(e) = run_iroh_edge(&args).await {
        error!("agent error: {e}");
    }
}

async fn run_iroh_edge(args: &RunArgs) -> Result<()> {
    let key_path = resolve_key_path(args.who.as_deref(), args.secret_key_file.as_ref())?;
    let key = load_or_create_key(&key_path)?;
    let profile = load_control_profile(&key_path.with_file_name("control.json"))?;
    if profile.is_some() {
        anyhow::ensure!(
            args.relays.is_empty() && args.center.is_none(),
            "a control-managed edge cannot override --relay or --center"
        );
    }
    let (relays, relay_ca_der) = if let Some(profile) = profile.as_ref() {
        profile
            .map
            .map
            .relays
            .iter()
            .map(|relay| -> Result<iroh::RelayConfig> {
                let url = relay
                    .url
                    .parse::<iroh::RelayUrl>()
                    .map_err(|error| anyhow::anyhow!("bad relay in control map: {error}"))?;
                Ok(scale_transport::managed_relay_config(url, relay.qad_port))
            })
            .collect::<Result<Vec<_>>>()
            .map(|relays| (relays, Some(profile.map.map.relay_ca_der.clone())))?
    } else {
        if args.relays.is_empty() {
            info!("using official iroh relays (simple mode)");
        }
        (
            scale_transport::relay_urls_or_default(&args.relays)?
                .into_iter()
                .map(iroh::RelayConfig::from)
                .collect(),
            None,
        )
    };

    // --center => strict pinning; otherwise trust-on-first-use, remembered
    // alongside the key file.
    let pin = if let Some(profile) = &profile {
        verify_profile(profile, key.public())?;
        let allowed = profile
            .map
            .map
            .allowed_centers
            .iter()
            .map(|value| {
                value
                    .parse::<iroh::EndpointId>()
                    .map_err(|error| anyhow::anyhow!("invalid center in control map: {error}"))
            })
            .collect::<Result<HashSet<_>>>()?;
        iroh_edge::CenterPin::managed(allowed)
    } else {
        match args.center.as_deref() {
            Some(c) => {
                let id: iroh::EndpointId = c.parse().map_err(|e| anyhow::anyhow!("bad --center: {e}"))?;
                iroh_edge::CenterPin::strict(id)
            }
            None => {
                let store = key_path.with_file_name("trusted_center");
                let existing = match std::fs::read_to_string(&store) {
                    Ok(value) => Some(
                        value
                            .trim()
                            .parse::<iroh::EndpointId>()
                            .with_context(|| format!("invalid trusted center in {}", store.display()))?,
                    ),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                    Err(error) => return Err(error).with_context(|| format!("read {}", store.display())),
                };
                match &existing {
                    Some(id) => info!("trusting pinned center {id}"),
                    None => warn!("no --center and none pinned yet: trusting the FIRST center to connect (TOFU)"),
                }
                iroh_edge::CenterPin::tofu(existing, store)
            }
        }
    };

    println!("edge endpoint_id: {}", key.public());
    if profile.is_none() && args.relays.is_empty() {
        println!("relay mode: official iroh network");
    }
    let endpoint = scale_transport::build_endpoint_with_config(
        key.clone(),
        relays,
        relay_ca_der,
        vec![scale_transport::ALPN.to_vec(), iroh_blobs::ALPN.to_vec()],
    )
    .await?;
    if let Some(profile) = profile {
        spawn_control_watch(
            key.clone(),
            key_path.with_file_name("control.json"),
            endpoint.clone(),
            pin.clone(),
            profile,
        );
    }
    let store = scale_transport::blobs::open_store(key_path.with_file_name("blobs")).await?;
    let mcp_registry = as_edge::mcp_registry::RegistryStore::new(key_path.with_file_name("mcp.json"));
    iroh_edge::serve(endpoint, pin, store, mcp_registry).await
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ControlProfile {
    schema_version: u32,
    name: String,
    control_url: String,
    control_id: String,
    audience: String,
    endpoint_id: String,
    map: SignedNodeMap,
}

async fn join_control(args: JoinArgs) -> Result<()> {
    let parsed = reqwest::Url::parse(&args.join_url).context("invalid join URL")?;
    let token = JoinToken::decode(parsed.fragment().context("join URL is missing its token fragment")?)?;
    let control_id = token.verify()?;
    let (who, audience, control_url) = match &token.invite.kind {
        InviteKind::Edge { .. } => (
            token.invite.name.clone(),
            token.invite.audience.clone(),
            token.invite.control_url.clone(),
        ),
        _ => anyhow::bail!("this invitation is not for an edge"),
    };
    let dir = who_dir(&who)?;
    std::fs::create_dir_all(&dir)?;
    let profile_path = dir.join("control.json");
    anyhow::ensure!(!profile_path.exists(), "edge '{who}' is already enrolled in control");
    let key_path = dir.join("agent.key");
    let key = load_or_create_key(&key_path)?;
    let request = ClaimRequest::sign(token, &key, unix_timestamp(), random_nonce())?;
    let response = control_client()
        .post(api_url(&control_url, "v1/claim")?)
        .json(&request)
        .send()
        .await
        .context("claim edge invitation")?;
    let status = response.status();
    let body = response.bytes().await?;
    anyhow::ensure!(
        status.is_success(),
        "control rejected edge claim ({status}): {}",
        String::from_utf8_lossy(&body)
    );
    let joined: JoinResult = serde_json::from_slice(&body).context("decode edge join response")?;
    joined.map.verify(control_id, key.public())?;
    let profile = ControlProfile {
        schema_version: 1,
        name: who.clone(),
        control_url,
        control_id: control_id.to_string(),
        audience,
        endpoint_id: key.public().to_string(),
        map: joined.map,
    };
    persist_profile(&profile_path, &profile).await?;
    println!("enrolled edge '{who}' ({})", key.public());

    let install = if args.foreground {
        false
    } else if args.install {
        true
    } else if std::io::stdin().is_terminal() {
        eprint!("Run as a persistent current-user service? [Y/n] ");
        use std::io::Write;
        std::io::stderr().flush()?;
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        !matches!(answer.trim().to_ascii_lowercase().as_str(), "n" | "no")
    } else {
        anyhow::bail!("non-interactive join requires --foreground or --install");
    };
    if install {
        if let Err(error) = service_install(&who) {
            eprintln!("service installation failed: {error:#}");
            eprintln!("enrollment was preserved; run `as-edge run {who}` in the foreground");
            return Err(error);
        }
        println!("installed and started edge service '{who}'");
        Ok(())
    } else {
        run_iroh_edge(&RunArgs {
            who: Some(who),
            relays: vec![],
            center: None,
            secret_key_file: None,
        })
        .await
    }
}

fn load_control_profile(path: &Path) -> Result<Option<ControlProfile>> {
    match std::fs::read(path) {
        Ok(data) => {
            let profile: ControlProfile =
                serde_json::from_slice(&data).with_context(|| format!("parse {}", path.display()))?;
            anyhow::ensure!(profile.schema_version == 1, "unsupported edge profile schema");
            Ok(Some(profile))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

fn verify_profile(profile: &ControlProfile, endpoint_id: iroh::EndpointId) -> Result<()> {
    let control_id = profile.control_id.parse().context("invalid control id in profile")?;
    anyhow::ensure!(
        profile.endpoint_id == endpoint_id.to_string(),
        "control profile belongs to another edge key"
    );
    profile.map.verify(control_id, endpoint_id)?;
    anyhow::ensure!(
        profile.map.map.audience == profile.audience && profile.map.map.control_url == profile.control_url,
        "control map binding mismatch"
    );
    Ok(())
}

fn spawn_control_watch(
    key: SecretKey,
    path: PathBuf,
    endpoint: iroh::Endpoint,
    pin: iroh_edge::CenterPin,
    mut profile: ControlProfile,
) {
    tokio::spawn(async move {
        let control_id: iroh::EndpointId = match profile.control_id.parse() {
            Ok(id) => id,
            Err(error) => {
                warn!("invalid control id: {error}");
                return;
            }
        };
        let url = match api_url(&profile.control_url, "v1/watch") {
            Ok(url) => url,
            Err(error) => {
                warn!("invalid control URL: {error:#}");
                return;
            }
        };
        let client = control_client();
        let mut current_relays: HashSet<String> =
            profile.map.map.relays.iter().map(|relay| relay.url.clone()).collect();
        let mut backoff = 1u64;
        loop {
            let request = match WatchRequest::sign(&key, profile.map.map.revision, unix_timestamp(), random_nonce()) {
                Ok(request) => request,
                Err(error) => {
                    warn!("cannot sign control watch: {error:#}");
                    return;
                }
            };
            match client.post(url.clone()).json(&request).send().await {
                Ok(response) if response.status().is_success() => match response.json::<SignedNodeMap>().await {
                    Ok(next) => {
                        let valid = next.verify(control_id, key.public()).and_then(|()| {
                            anyhow::ensure!(next.map.revision >= profile.map.map.revision, "control map rollback");
                            anyhow::ensure!(
                                next.map.audience == profile.audience && next.map.control_url == profile.control_url,
                                "control map binding mismatch"
                            );
                            Ok(())
                        });
                        if let Err(error) = valid {
                            warn!("invalid control map: {error:#}");
                        } else if let Err(error) = apply_control_map(&endpoint, &pin, &mut current_relays, &next).await
                        {
                            warn!("cannot apply control map: {error:#}");
                        } else {
                            profile.map = next;
                            if let Err(error) = persist_profile(&path, &profile).await {
                                warn!("cannot cache control map: {error:#}");
                            }
                            backoff = 1;
                            continue;
                        }
                    }
                    Err(error) => warn!("cannot decode control map: {error}"),
                },
                Ok(response)
                    if response.status() == reqwest::StatusCode::FORBIDDEN
                        || response.status() == reqwest::StatusCode::GONE =>
                {
                    warn!(status = %response.status(), "edge enrollment was revoked; disconnecting all centers");
                    if let Err(error) = pin.replace_managed(HashSet::new()) {
                        warn!("cannot revoke center authorization: {error:#}");
                    }
                    return;
                }
                Ok(response) => {
                    warn!(status = %response.status(), "control watch failed; retaining cached authorization")
                }
                Err(error) => warn!("control unavailable; retaining cached authorization: {error}"),
            }
            tokio::time::sleep(Duration::from_secs(backoff)).await;
            backoff = (backoff * 2).min(60);
        }
    });
}

async fn apply_control_map(
    endpoint: &iroh::Endpoint,
    pin: &iroh_edge::CenterPin,
    current_relays: &mut HashSet<String>,
    map: &SignedNodeMap,
) -> Result<()> {
    let next_relays: HashSet<String> = map.map.relays.iter().map(|relay| relay.url.clone()).collect();
    for value in next_relays.difference(current_relays) {
        let url: iroh::RelayUrl = value
            .parse()
            .map_err(|error| anyhow::anyhow!("invalid relay {value}: {error}"))?;
        endpoint
            .insert_relay(url.clone(), std::sync::Arc::new(iroh::RelayConfig::from(url)))
            .await;
    }
    for value in current_relays.difference(&next_relays) {
        if let Ok(url) = value.parse::<iroh::RelayUrl>() {
            endpoint.remove_relay(&url).await;
        }
    }
    let allowed = map
        .map
        .allowed_centers
        .iter()
        .map(|value| {
            value
                .parse::<iroh::EndpointId>()
                .map_err(|error| anyhow::anyhow!("invalid allowed center: {error}"))
        })
        .collect::<Result<HashSet<_>>>()?;
    pin.replace_managed(allowed)?;
    *current_relays = next_relays;
    Ok(())
}

async fn persist_profile(path: &Path, profile: &ControlProfile) -> Result<()> {
    let path = path.to_owned();
    let mut data = serde_json::to_vec_pretty(profile)?;
    data.push(b'\n');
    tokio::task::spawn_blocking(move || scale_core::atomic_write(&path, &data))
        .await
        .context("join edge profile writer")??;
    Ok(())
}

fn control_client() -> reqwest::Client {
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::new()
}
fn api_url(base: &str, path: &str) -> Result<reqwest::Url> {
    reqwest::Url::parse(&format!("{}/", base.trim_end_matches('/')))?
        .join(path)
        .context("build control API URL")
}
fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
fn random_nonce() -> String {
    use base64::Engine;
    use rand::Rng;
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
