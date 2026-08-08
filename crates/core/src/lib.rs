//! Concentrates file-permission and durability invariants so callers cannot
//! accidentally create weaker identity or state files.

use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use fs2::FileExt;
use iroh_base::SecretKey;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tempfile::NamedTempFile;

/// An exclusive advisory lock held until this value is dropped.
pub struct FileLock {
    _file: File,
}

impl FileLock {
    /// Exclusively lock `path`, creating the lock file with private permissions.
    pub fn acquire(path: &Path) -> Result<Self> {
        Self::open(path, false)
    }

    /// Try to exclusively lock `path` without waiting.
    pub fn try_acquire(path: &Path) -> Result<Self> {
        Self::open(path, true)
    }

    fn open(path: &Path, nonblocking: bool) -> Result<Self> {
        if let Some(parent) = path.parent() {
            ensure_private_dir(parent)?;
        }
        let mut options = OpenOptions::new();
        options.create(true).read(true).write(true);
        set_private_create_mode(&mut options);
        let file = options
            .open(path)
            .with_context(|| format!("open lock {}", path.display()))?;
        if nonblocking {
            file.try_lock_exclusive()
        } else {
            file.lock_exclusive()
        }
        .with_context(|| format!("lock {}", path.display()))?;
        Ok(Self { _file: file })
    }
}

/// Create `path` and make the final directory private to the current Unix user.
pub fn ensure_private_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path).with_context(|| format!("create directory {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("secure directory {}", path.display()))?;
    }
    Ok(())
}

/// Load a 32-byte Ed25519 identity, creating it only when the path is absent.
///
/// Existing unreadable or malformed files are never replaced.
pub fn load_or_create_secret(path: &Path) -> Result<SecretKey> {
    let parent = path.parent().context("identity path has no parent")?;
    ensure_private_dir(parent)?;
    let _lock = FileLock::acquire(&lock_path(path))?;

    match read_secret(path) {
        Ok(key) => return Ok(key),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == ErrorKind::NotFound) => {}
        Err(error) => return Err(error),
    }

    let key = SecretKey::generate();
    let mut temp = private_temp(parent)?;
    temp.write_all(&key.to_bytes())
        .with_context(|| format!("write new identity for {}", path.display()))?;
    temp.as_file()
        .sync_all()
        .with_context(|| format!("sync new identity for {}", path.display()))?;
    temp.persist_noclobber(path)
        .map_err(|error| error.error)
        .with_context(|| format!("install new identity {}", path.display()))?;
    sync_parent(parent)?;
    Ok(key)
}

/// Read an existing 32-byte Ed25519 identity without creating or repairing it.
pub fn read_secret(path: &Path) -> Result<SecretKey> {
    let mut file = File::open(path).with_context(|| format!("read identity {}", path.display()))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .with_context(|| format!("read identity {}", path.display()))?;
    let raw: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!(
            "invalid identity {}: expected 32 bytes, got {}",
            path.display(),
            bytes.len()
        )
    })?;
    Ok(SecretKey::from_bytes(&raw))
}

/// Atomically and durably replace a private local state file.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("state path has no parent")?;
    ensure_private_dir(parent)?;
    let _lock = FileLock::acquire(&lock_path(path))?;
    atomic_write_unlocked(path, bytes)
}

/// Serialize and atomically replace a private JSON state file.
pub fn write_json<T: Serialize + ?Sized>(path: &Path, value: &T) -> Result<()> {
    let mut data = serde_json::to_vec_pretty(value).context("serialize durable JSON")?;
    data.push(b'\n');
    atomic_write(path, &data)
}

/// Read and deserialize a JSON state file.
pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let data = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&data).with_context(|| format!("parse {}", path.display()))
}

fn atomic_write_unlocked(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("state path has no parent")?;
    let mut temp = private_temp(parent)?;
    temp.write_all(bytes)
        .with_context(|| format!("write temporary state for {}", path.display()))?;
    temp.as_file()
        .sync_all()
        .with_context(|| format!("sync temporary state for {}", path.display()))?;
    temp.persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("replace {}", path.display()))?;
    sync_parent(parent)
}

fn private_temp(parent: &Path) -> Result<NamedTempFile> {
    let temp =
        NamedTempFile::new_in(parent).with_context(|| format!("create temporary file in {}", parent.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("secure temporary file in {}", parent.display()))?;
    }
    Ok(temp)
}

fn lock_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_owned();
    value.push(".lock");
    PathBuf::from(value)
}

#[cfg(unix)]
fn set_private_create_mode(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
}

#[cfg(not(unix))]
fn set_private_create_mode(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> Result<()> {
    File::open(parent)
        .with_context(|| format!("open directory {} for sync", parent.display()))?
        .sync_all()
        .with_context(|| format!("sync directory {}", parent.display()))
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_identity_is_not_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.key");
        std::fs::write(&path, b"broken").unwrap();

        let error = load_or_create_secret(&path).unwrap_err().to_string();

        assert!(error.contains("expected 32 bytes"));
        assert_eq!(std::fs::read(path).unwrap(), b"broken");
    }

    #[test]
    fn identity_creation_is_stable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.key");

        let first = load_or_create_secret(&path).unwrap();
        let second = load_or_create_secret(&path).unwrap();

        assert_eq!(first.public(), second.public());
        assert_eq!(std::fs::read(path).unwrap().len(), 32);
    }

    #[test]
    fn atomic_json_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        write_json(&path, &vec!["one", "two"]).unwrap();
        let value: Vec<String> = read_json(&path).unwrap();
        assert_eq!(value, ["one", "two"]);
    }
}
