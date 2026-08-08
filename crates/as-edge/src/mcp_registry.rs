use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use fs2::FileExt;
use protocol::{McpCatalog, McpTransport};
use serde::{Deserialize, Serialize};

const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
struct RegistryFile {
    version: u32,
    revision: u64,
    #[serde(default)]
    servers: std::collections::BTreeMap<String, McpTransport>,
}

impl Default for RegistryFile {
    fn default() -> Self {
        Self {
            version: SCHEMA_VERSION,
            revision: 0,
            servers: Default::default(),
        }
    }
}

/// Concurrent, process-safe storage for one edge identity's MCP definitions.
#[derive(Clone, Debug)]
pub struct RegistryStore {
    path: PathBuf,
    lock_path: PathBuf,
}

impl RegistryStore {
    pub fn new(path: PathBuf) -> Self {
        let lock_path = path.with_extension("lock");
        Self { path, lock_path }
    }

    pub fn list(&self) -> Result<McpCatalog> {
        self.ensure_parent()?;
        let lock = self.open_lock()?;
        FileExt::lock_shared(&lock).context("lock MCP registry")?;
        let registry = self.load_unlocked()?;
        FileExt::unlock(&lock).ok();
        Ok(McpCatalog {
            revision: registry.revision,
            servers: registry.servers,
        })
    }

    pub fn upsert(&self, name: String, transport: McpTransport) -> Result<bool> {
        validate_name(&name)?;
        validate_transport(&transport)?;
        self.mutate(|registry| Ok(registry.servers.insert(name, transport).is_some()))
    }

    pub fn remove(&self, name: &str) -> Result<()> {
        validate_name(name)?;
        self.mutate(|registry| {
            anyhow::ensure!(registry.servers.remove(name).is_some(), "no MCP named '{name}'");
            Ok(())
        })
    }

    pub fn get(&self, name: &str) -> Result<McpTransport> {
        validate_name(name)?;
        self.list()?
            .servers
            .remove(name)
            .with_context(|| format!("no MCP named '{name}'"))
    }

    fn mutate<T>(&self, change: impl FnOnce(&mut RegistryFile) -> Result<T>) -> Result<T> {
        self.ensure_parent()?;
        let lock = self.open_lock()?;
        FileExt::lock_exclusive(&lock).context("lock MCP registry")?;
        let mut registry = self.load_unlocked()?;
        let value = change(&mut registry)?;
        registry.revision = registry
            .revision
            .checked_add(1)
            .context("MCP registry revision overflow")?;
        self.save_unlocked(&registry)?;
        FileExt::unlock(&lock).ok();
        Ok(value)
    }

    fn ensure_parent(&self) -> Result<()> {
        let parent = self.path.parent().context("MCP registry has no parent")?;
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        set_private_dir(parent)?;
        Ok(())
    }

    fn open_lock(&self) -> Result<File> {
        OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&self.lock_path)
            .with_context(|| format!("open {}", self.lock_path.display()))
    }

    fn load_unlocked(&self) -> Result<RegistryFile> {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(RegistryFile::default());
            }
            Err(error) => {
                return Err(error).with_context(|| format!("read {}", self.path.display()));
            }
        };
        let registry: RegistryFile =
            serde_json::from_slice(&bytes).with_context(|| format!("parse {}", self.path.display()))?;
        anyhow::ensure!(
            registry.version == SCHEMA_VERSION,
            "unsupported MCP registry version {} (expected {SCHEMA_VERSION})",
            registry.version
        );
        Ok(registry)
    }

    fn save_unlocked(&self, registry: &RegistryFile) -> Result<()> {
        let parent = self.path.parent().context("MCP registry has no parent")?;
        let mut temp = tempfile::NamedTempFile::new_in(parent)
            .with_context(|| format!("create temporary file in {}", parent.display()))?;
        serde_json::to_writer_pretty(&mut temp, registry)?;
        temp.write_all(b"\n")?;
        temp.as_file().sync_all()?;
        set_private_file(temp.path())?;
        temp.persist(&self.path)
            .map_err(|error| error.error)
            .with_context(|| format!("replace {}", self.path.display()))?;
        sync_dir(parent)?;
        Ok(())
    }
}

fn validate_name(name: &str) -> Result<()> {
    anyhow::ensure!(!name.is_empty() && !name.contains('\0'), "invalid MCP name {name:?}");
    Ok(())
}

fn validate_transport(transport: &McpTransport) -> Result<()> {
    match transport {
        McpTransport::Stdio { command, .. } => {
            anyhow::ensure!(!command.is_empty(), "stdio MCP command cannot be empty");
        }
        McpTransport::Http { url } | McpTransport::Sse { url } => {
            let parsed = reqwest::Url::parse(url).context("invalid MCP URL")?;
            anyhow::ensure!(
                matches!(parsed.scheme(), "http" | "https"),
                "MCP URL must use http or https"
            );
        }
    }
    Ok(())
}

#[cfg(unix)]
fn set_private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_dir(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_file(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn sync_dir(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_dir(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stdio(command: &str) -> McpTransport {
        McpTransport::Stdio {
            command: command.into(),
            args: vec![],
            cwd: None,
        }
    }

    #[test]
    fn registry_crud_is_persistent_and_revisioned() {
        let dir = tempfile::tempdir().unwrap();
        let store = RegistryStore::new(dir.path().join("mcp.json"));
        assert_eq!(store.list().unwrap().revision, 0);
        assert!(!store.upsert("one".into(), stdio("cat")).unwrap());
        assert!(store.upsert("one".into(), stdio("other")).unwrap());
        assert_eq!(store.list().unwrap().revision, 2);
        assert_eq!(store.get("one").unwrap(), stdio("other"));
        store.remove("one").unwrap();
        assert!(store.list().unwrap().servers.is_empty());
        assert_eq!(store.list().unwrap().revision, 3);
    }
}
