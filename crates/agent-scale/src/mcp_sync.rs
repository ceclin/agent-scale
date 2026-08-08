use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result};
use clap::ValueEnum;
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use toml_edit::{Array, DocumentMut, Item, Table, Value as TomlValue, value};

use crate::{client, common};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, ValueEnum)]
pub enum ClientKind {
    Claude,
    Codex,
}

impl ClientKind {
    fn key(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
        }
    }
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct Manifest {
    version: u32,
    #[serde(default)]
    clients: BTreeMap<String, BTreeMap<String, String>>,
}

#[derive(Debug)]
struct PreparedFile {
    path: PathBuf,
    bytes: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
struct SyncJournal {
    version: u32,
    files: Vec<JournalFile>,
}

#[derive(Debug, Deserialize, Serialize)]
struct JournalFile {
    relative_path: PathBuf,
    bytes: Vec<u8>,
}

enum ReconcileAction {
    Put {
        alias: String,
        edge: String,
        server: String,
    },
    Remove(String),
}

pub async fn sync(edges: Vec<String>, clients: Vec<ClientKind>, project: Option<PathBuf>, check: bool) -> Result<()> {
    anyhow::ensure!(!edges.is_empty(), "mcp sync requires at least one -e/--edge");
    let edge_names: BTreeSet<_> = edges.into_iter().collect();
    let client_kinds: BTreeSet<_> = clients.into_iter().collect();
    anyhow::ensure!(!client_kinds.is_empty(), "mcp sync requires --client");

    let root = project_root(project)?;
    let lock_dir = common::home().join("sync-locks");
    std::fs::create_dir_all(&lock_dir)?;
    let lock_name = digest(root.to_string_lossy().as_bytes());
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(lock_dir.join(lock_name))?;
    FileExt::lock_exclusive(&lock).context("lock project MCP sync")?;
    recover_journal(&root)?;

    let mut desired = BTreeMap::new();
    for edge in &edge_names {
        let catalog = client::mcp_list(edge.clone())
            .await
            .with_context(|| format!("read MCP catalog from edge '{edge}'"))?;
        for server in catalog.servers.keys() {
            let alias = format!("{edge}__{server}");
            anyhow::ensure!(
                desired.insert(alias.clone(), (edge.clone(), server.clone())).is_none(),
                "generated MCP alias collision: '{alias}'"
            );
        }
    }

    if check {
        for (edge, server) in desired.values() {
            client::mcp_check(edge.clone(), server.clone())
                .await
                .with_context(|| format!("health check {edge}/{server}"))?;
        }
    }

    let manifest_path = root.join(".agent-scale/mcp-sync.json");
    let mut manifest = load_manifest(&manifest_path)?;
    anyhow::ensure!(
        manifest.version == 0 || manifest.version == 1,
        "unsupported MCP sync manifest version {}",
        manifest.version
    );
    manifest.version = 1;

    let mut prepared = Vec::new();
    for kind in client_kinds {
        let owned = manifest.clients.entry(kind.key().into()).or_default();
        prepared.push(match kind {
            ClientKind::Claude => prepare_claude(&root, &desired, owned)?,
            ClientKind::Codex => prepare_codex(&root, &desired, owned)?,
        });
    }
    prepared.push(PreparedFile {
        path: manifest_path,
        bytes: with_newline(serde_json::to_vec_pretty(&manifest)?),
    });

    commit_prepared(&root, &prepared)?;
    FileExt::unlock(&lock).ok();
    println!(
        "synchronized {} MCP server(s) from {} edge(s) into {}",
        desired.len(),
        edge_names.len(),
        root.display()
    );
    Ok(())
}

fn journal_path(root: &Path) -> PathBuf {
    root.join(".agent-scale/mcp-sync-journal.json")
}

fn commit_prepared(root: &Path, prepared: &[PreparedFile]) -> Result<()> {
    let files = prepared
        .iter()
        .map(|file| {
            let relative_path = file
                .path
                .strip_prefix(root)
                .with_context(|| format!("sync output escaped project root: {}", file.path.display()))?
                .to_owned();
            validate_relative_path(&relative_path)?;
            Ok(JournalFile {
                relative_path,
                bytes: file.bytes.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let journal = SyncJournal { version: 1, files };
    let path = journal_path(root);
    write_if_changed(&path, &with_newline(serde_json::to_vec_pretty(&journal)?))?;
    apply_journal(root, &journal)?;
    std::fs::remove_file(&path).with_context(|| format!("remove completed journal {}", path.display()))?;
    sync_dir(path.parent().context("journal path has no parent")?)
}

fn recover_journal(root: &Path) -> Result<()> {
    let path = journal_path(root);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).with_context(|| format!("read journal {}", path.display())),
    };
    let journal: SyncJournal =
        serde_json::from_slice(&bytes).with_context(|| format!("parse journal {}", path.display()))?;
    anyhow::ensure!(
        journal.version == 1,
        "unsupported MCP sync journal version {}",
        journal.version
    );
    apply_journal(root, &journal)?;
    std::fs::remove_file(&path).with_context(|| format!("remove recovered journal {}", path.display()))?;
    sync_dir(path.parent().context("journal path has no parent")?)
}

fn apply_journal(root: &Path, journal: &SyncJournal) -> Result<()> {
    for file in &journal.files {
        validate_relative_path(&file.relative_path)?;
        write_if_changed(&root.join(&file.relative_path), &file.bytes)?;
    }
    Ok(())
}

fn validate_relative_path(path: &Path) -> Result<()> {
    anyhow::ensure!(
        !path.as_os_str().is_empty() && path.components().all(|part| matches!(part, Component::Normal(_))),
        "unsafe path in MCP sync journal: {}",
        path.display()
    );
    Ok(())
}

fn project_root(override_path: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = override_path {
        anyhow::ensure!(path.is_dir(), "project path is not a directory: {}", path.display());
        return path.canonicalize().context("resolve project path");
    }
    let cwd = std::env::current_dir()?;
    for directory in cwd.ancestors() {
        if directory.join(".jj").exists() || directory.join(".git").exists() {
            return Ok(directory.to_path_buf());
        }
    }
    Ok(cwd)
}

fn load_manifest(path: &Path) -> Result<Manifest> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Manifest::default()),
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

fn proxy_json(edge: &str, server: &str) -> Value {
    json!({
        "command": "agent-scale",
        "args": ["-e", edge, "mcp", "run", server]
    })
}

fn prepare_claude(
    root: &Path,
    desired: &BTreeMap<String, (String, String)>,
    owned: &mut BTreeMap<String, String>,
) -> Result<PreparedFile> {
    let path = root.join(".mcp.json");
    let mut document = match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice::<Value>(&bytes).with_context(|| format!("parse {}", path.display()))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => json!({}),
        Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
    };
    let root_object = document.as_object_mut().context(".mcp.json root must be an object")?;
    let servers = root_object
        .entry("mcpServers")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .context(".mcp.json mcpServers must be an object")?;

    let current = servers
        .iter()
        .map(|(alias, value)| (alias.clone(), json_fingerprint(value)))
        .collect();
    for action in reconcile(
        desired,
        owned,
        &current,
        |edge, server| json_fingerprint(&proxy_json(edge, server)),
        "Claude",
    )? {
        match action {
            ReconcileAction::Put { alias, edge, server } => {
                servers.insert(alias, proxy_json(&edge, &server));
            }
            ReconcileAction::Remove(alias) => {
                servers.remove(&alias);
            }
        }
    }

    Ok(PreparedFile {
        path,
        bytes: with_newline(serde_json::to_vec_pretty(&document)?),
    })
}

fn prepare_codex(
    root: &Path,
    desired: &BTreeMap<String, (String, String)>,
    owned: &mut BTreeMap<String, String>,
) -> Result<PreparedFile> {
    let path = root.join(".codex/config.toml");
    let source = match std::fs::read_to_string(&path) {
        Ok(source) => source,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
    };
    let mut document = source
        .parse::<DocumentMut>()
        .with_context(|| format!("parse {}", path.display()))?;
    if !document.contains_key("mcp_servers") {
        document["mcp_servers"] = Item::Table(Table::new());
    }
    let servers = document["mcp_servers"]
        .as_table_mut()
        .context("Codex mcp_servers must be a table")?;

    let current = servers
        .iter()
        .map(|(alias, item)| (alias.to_string(), toml_fingerprint(item)))
        .collect();
    for action in reconcile(
        desired,
        owned,
        &current,
        |edge, server| toml_fingerprint(&proxy_toml(edge, server)),
        "Codex",
    )? {
        match action {
            ReconcileAction::Put { alias, edge, server } => {
                servers.insert(&alias, proxy_toml(&edge, &server));
            }
            ReconcileAction::Remove(alias) => {
                servers.remove(&alias);
            }
        }
    }

    Ok(PreparedFile {
        path,
        bytes: document.to_string().into_bytes(),
    })
}

fn reconcile<DesiredHash>(
    desired: &BTreeMap<String, (String, String)>,
    owned: &mut BTreeMap<String, String>,
    current: &BTreeMap<String, String>,
    desired_hash: DesiredHash,
    client: &str,
) -> Result<Vec<ReconcileAction>>
where
    DesiredHash: Fn(&str, &str) -> String,
{
    let mut actions = Vec::new();
    for (alias, previous_hash) in owned.clone() {
        if desired.contains_key(&alias) {
            continue;
        }
        if let Some(current_hash) = current.get(&alias) {
            anyhow::ensure!(
                *current_hash == previous_hash,
                "{client} MCP entry '{alias}' was modified; refusing to remove it"
            );
            actions.push(ReconcileAction::Remove(alias.clone()));
        }
        owned.remove(&alias);
    }

    for (alias, (edge, server)) in desired {
        let next_hash = desired_hash(edge, server);
        match (owned.get(alias), current.get(alias)) {
            (None, Some(_)) => {
                anyhow::bail!("{client} MCP entry '{alias}' already exists and is not managed by agent-scale")
            }
            (Some(previous_hash), Some(current_hash)) if current_hash != previous_hash => {
                anyhow::bail!("{client} MCP entry '{alias}' was modified; refusing to overwrite it")
            }
            (Some(previous_hash), Some(_)) if *previous_hash == next_hash => continue,
            _ => actions.push(ReconcileAction::Put {
                alias: alias.clone(),
                edge: edge.clone(),
                server: server.clone(),
            }),
        }
        owned.insert(alias.clone(), next_hash);
    }
    Ok(actions)
}

fn proxy_toml(edge: &str, server: &str) -> Item {
    let mut table = Table::new();
    table["command"] = value("agent-scale");
    let mut args = Array::new();
    for argument in ["-e", edge, "mcp", "run", server] {
        args.push(argument);
    }
    table["args"] = Item::Value(TomlValue::Array(args));
    Item::Table(table)
}

fn json_fingerprint(value: &Value) -> String {
    digest(&serde_json::to_vec(value).unwrap_or_default())
}

fn toml_fingerprint(item: &Item) -> String {
    let Some(table) = item.as_table() else {
        return digest(item.to_string().as_bytes());
    };
    let mut semantic = BTreeMap::<String, Value>::new();
    for (key, value) in table.iter() {
        let converted = if let Some(value) = value.as_value() {
            toml_value_to_json(value)
        } else {
            Value::String(value.to_string())
        };
        semantic.insert(key.to_string(), converted);
    }
    digest(&serde_json::to_vec(&semantic).unwrap_or_default())
}

fn toml_value_to_json(value: &TomlValue) -> Value {
    match value {
        TomlValue::String(value) => Value::String(value.value().to_string()),
        TomlValue::Integer(value) => json!(value.value()),
        TomlValue::Float(value) => json!(value.value()),
        TomlValue::Boolean(value) => json!(value.value()),
        TomlValue::Datetime(value) => Value::String(value.value().to_string()),
        TomlValue::Array(values) => Value::Array(values.iter().map(toml_value_to_json).collect()),
        TomlValue::InlineTable(table) => Value::Object(
            table
                .iter()
                .map(|(key, value)| (key.to_string(), toml_value_to_json(value)))
                .collect(),
        ),
    }
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn with_newline(mut bytes: Vec<u8>) -> Vec<u8> {
    if !bytes.ends_with(b"\n") {
        bytes.push(b'\n');
    }
    bytes
}

fn write_if_changed(path: &Path, bytes: &[u8]) -> Result<()> {
    if std::fs::read(path).ok().as_deref() == Some(bytes) {
        return Ok(());
    }
    let parent = path.parent().context("output path has no parent")?;
    std::fs::create_dir_all(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("replace {}", path.display()))?;
    sync_dir(parent)?;
    Ok(())
}

#[cfg(unix)]
fn sync_dir(path: &Path) -> Result<()> {
    std::fs::File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_dir(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn desired() -> BTreeMap<String, (String, String)> {
        BTreeMap::from([("win__debugger".into(), ("win".into(), "debugger".into()))])
    }

    #[test]
    fn adapters_preserve_handwritten_entries() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join(".mcp.json"),
            r#"{"mcpServers":{"manual":{"command":"manual"}},"other":true}"#,
        )
        .unwrap();
        std::fs::create_dir(directory.path().join(".codex")).unwrap();
        std::fs::write(
            directory.path().join(".codex/config.toml"),
            "# keep this comment\nmodel = \"gpt\"\n\n[mcp_servers.manual]\ncommand = \"manual\"\n",
        )
        .unwrap();

        let mut claude_owned = BTreeMap::new();
        let claude = prepare_claude(directory.path(), &desired(), &mut claude_owned).unwrap();
        let parsed: Value = serde_json::from_slice(&claude.bytes).unwrap();
        assert_eq!(parsed["other"], true);
        assert_eq!(parsed["mcpServers"]["manual"]["command"], "manual");
        assert_eq!(
            parsed["mcpServers"]["win__debugger"]["args"],
            json!(["-e", "win", "mcp", "run", "debugger"])
        );

        let mut codex_owned = BTreeMap::new();
        let codex = prepare_codex(directory.path(), &desired(), &mut codex_owned).unwrap();
        let text = String::from_utf8(codex.bytes).unwrap();
        assert!(text.contains("# keep this comment"));
        assert!(text.contains("[mcp_servers.manual]"));
        assert!(text.contains("[mcp_servers.win__debugger]"));
        assert!(text.contains("args = [\"-e\", \"win\", \"mcp\", \"run\", \"debugger\"]"));
    }

    #[test]
    fn modified_generated_entry_is_a_conflict() {
        let directory = tempfile::tempdir().unwrap();
        let mut owned = BTreeMap::new();
        let first = prepare_claude(directory.path(), &desired(), &mut owned).unwrap();
        let mut document: Value = serde_json::from_slice(&first.bytes).unwrap();
        document["mcpServers"]["win__debugger"]["command"] = json!("custom-wrapper");
        std::fs::write(
            directory.path().join(".mcp.json"),
            serde_json::to_vec_pretty(&document).unwrap(),
        )
        .unwrap();

        let error = prepare_claude(directory.path(), &desired(), &mut owned).unwrap_err();
        assert!(error.to_string().contains("was modified"));
    }

    #[test]
    fn interrupted_multi_file_sync_rolls_forward_from_journal() {
        let directory = tempfile::tempdir().unwrap();
        let journal = SyncJournal {
            version: 1,
            files: vec![
                JournalFile {
                    relative_path: PathBuf::from(".mcp.json"),
                    bytes: b"new claude\n".to_vec(),
                },
                JournalFile {
                    relative_path: PathBuf::from(".codex/config.toml"),
                    bytes: b"new codex\n".to_vec(),
                },
            ],
        };
        let path = journal_path(directory.path());
        write_if_changed(&path, &with_newline(serde_json::to_vec_pretty(&journal).unwrap())).unwrap();
        std::fs::write(directory.path().join(".mcp.json"), b"partially applied\n").unwrap();

        recover_journal(directory.path()).unwrap();

        assert_eq!(
            std::fs::read(directory.path().join(".mcp.json")).unwrap(),
            b"new claude\n"
        );
        assert_eq!(
            std::fs::read(directory.path().join(".codex/config.toml")).unwrap(),
            b"new codex\n"
        );
        assert!(!path.exists());
    }

    #[test]
    fn journal_rejects_paths_outside_the_project() {
        assert!(validate_relative_path(Path::new("../outside")).is_err());
        assert!(validate_relative_path(Path::new("/absolute")).is_err());
    }
}
