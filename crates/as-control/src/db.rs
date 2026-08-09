use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result};
use control_api::{Invite, InviteKind};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use super::{
    ClientRecord, ControlState, EdgeRecord, InviteRecord, InviteState, ProvisionerRecord, RelayRecord, STATE_SCHEMA,
    unix_timestamp,
};

const MIGRATION_1: &str = include_str!("schema.sql");

#[derive(Clone)]
pub struct Database {
    connection: Arc<Mutex<Connection>>,
}

impl Database {
    pub fn create(path: &Path, state: &ControlState) -> Result<Self> {
        let db = Self::open_connection(path)?;
        db.migrate()?;
        db.replace_sync(state)?;
        Ok(db)
    }

    pub fn open(path: &Path) -> Result<Self> {
        anyhow::ensure!(
            path.exists(),
            "control database is missing; run `as-control init` to initialize a new network"
        );
        let db = Self::open_connection(path)?;
        db.migrate()?;
        Ok(db)
    }

    fn open_connection(path: &Path) -> Result<Self> {
        let connection = Connection::open(path).with_context(|| format!("open {}", path.display()))?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "wal_autocheckpoint", 1000)?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    fn migrate(&self) -> Result<()> {
        let mut connection = self.connection.lock().expect("database mutex poisoned");
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(
            "CREATE TABLE IF NOT EXISTS migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL) STRICT;",
        )?;
        let applied: bool = transaction
            .query_row("SELECT 1 FROM migrations WHERE version = 1", [], |_| Ok(true))
            .optional()?
            .unwrap_or(false);
        if !applied {
            transaction.execute_batch(MIGRATION_1)?;
            transaction.execute(
                "INSERT INTO migrations(version, applied_at) VALUES (1, ?1)",
                [unix_timestamp()],
            )?;
        }
        let applied: bool = transaction
            .query_row("SELECT 1 FROM migrations WHERE version = 2", [], |_| Ok(true))
            .optional()?
            .unwrap_or(false);
        if !applied {
            if !has_column(&transaction, "metadata", "relay_ca_der")? {
                transaction.execute("ALTER TABLE metadata ADD COLUMN relay_ca_der BLOB", [])?;
            }
            if !has_column(&transaction, "relays", "qad_port")? {
                transaction.execute(
                    "ALTER TABLE relays ADD COLUMN qad_port INTEGER CHECK (qad_port BETWEEN 1 AND 65535)",
                    [],
                )?;
            }
            transaction.execute(
                "INSERT INTO migrations(version, applied_at) VALUES (2, ?1)",
                [unix_timestamp()],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn load(&self) -> Result<ControlState> {
        let connection = self.connection.lock().expect("database mutex poisoned");
        let (schema, audience, public_url, relay_ca_der, revision) = connection
            .query_row(
                "SELECT schema_version, audience, public_url, relay_ca_der, revision FROM metadata WHERE id = 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, u32>(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .context("database is not initialized; run `as-control init` to initialize a new network")?;
        anyhow::ensure!(schema == STATE_SCHEMA, "unsupported state schema {schema}");
        let revision = u64::try_from(revision).context("negative control revision")?;

        let provisioners = query_all(
            &connection,
            "SELECT name, endpoint_id FROM provisioners WHERE active = 1 ORDER BY name",
            |row| {
                Ok(ProvisionerRecord {
                    name: row.get(0)?,
                    endpoint_id: row.get(1)?,
                })
            },
        )?;
        let clients = query_all(
            &connection,
            "SELECT name, endpoint_id, managed_by FROM clients ORDER BY name",
            |row| {
                Ok(ClientRecord {
                    name: row.get(0)?,
                    endpoint_id: row.get(1)?,
                    managed_by: row.get(2)?,
                })
            },
        )?;
        let edges = query_all(
            &connection,
            "SELECT name, endpoint_id, owner_id FROM edges ORDER BY owner_id, name",
            |row| {
                Ok(EdgeRecord {
                    name: row.get(0)?,
                    endpoint_id: row.get(1)?,
                    owner_id: row.get(2)?,
                })
            },
        )?;
        let relays = query_all(
            &connection,
            "SELECT name, endpoint_id, url, qad_port FROM relays ORDER BY name",
            |row| {
                Ok(RelayRecord {
                    name: row.get(0)?,
                    endpoint_id: row.get(1)?,
                    url: row.get(2)?,
                    qad_port: row.get(3)?,
                })
            },
        )?;
        let invites = query_all(
            &connection,
            "SELECT invite_json, state, claimed_by, request_id, managed_by, request_hash, terminal_at FROM invitations ORDER BY rowid",
            |row| {
                let invite_json: String = row.get(0)?;
                let invite: Invite = serde_json::from_str(&invite_json).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        invite_json.len(),
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?;
                let state_value: String = row.get(1)?;
                let state = match state_value.as_str() {
                    "pending" => InviteState::Pending,
                    "claimed" => InviteState::Claimed,
                    "revoked" => InviteState::Revoked,
                    _ => return Err(rusqlite::Error::InvalidQuery),
                };
                Ok(InviteRecord {
                    invite,
                    state,
                    claimed_by: row.get(2)?,
                    request_id: row.get(3)?,
                    managed_by: row.get(4)?,
                    request_hash: row.get(5)?,
                    terminal_at: row.get(6)?,
                })
            },
        )?;
        Ok(ControlState {
            schema,
            audience,
            public_url,
            relay_ca_der,
            revision,
            clients,
            edges,
            relays,
            invites,
            provisioners,
        })
    }

    pub fn replace_sync(&self, state: &ControlState) -> Result<()> {
        let mut connection = self.connection.lock().expect("database mutex poisoned");
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stored_revision: Option<i64> = transaction
            .query_row("SELECT revision FROM metadata WHERE id = 1", [], |row| row.get(0))
            .optional()?;
        if let Some(stored_revision) = stored_revision {
            let stored_revision = u64::try_from(stored_revision).context("negative stored control revision")?;
            anyhow::ensure!(
                state.revision == stored_revision || state.revision == stored_revision.saturating_add(1),
                "control revision must remain unchanged or advance atomically by one (stored {stored_revision}, candidate {})",
                state.revision
            );
        }
        transaction.execute("DELETE FROM invitations", [])?;
        transaction.execute("DELETE FROM edges", [])?;
        transaction.execute("DELETE FROM clients", [])?;
        transaction.execute("DELETE FROM relays", [])?;
        transaction.execute("UPDATE provisioners SET active = 0", [])?;
        let revision = i64::try_from(state.revision).context("control revision exceeds SQLite range")?;
        transaction.execute(
            "INSERT INTO metadata(id, schema_version, audience, public_url, relay_ca_der, revision) VALUES (1, ?1, ?2, ?3, ?4, ?5) ON CONFLICT(id) DO UPDATE SET schema_version=excluded.schema_version, audience=excluded.audience, public_url=excluded.public_url, relay_ca_der=excluded.relay_ca_der, revision=excluded.revision",
            params![state.schema, state.audience, state.public_url, state.relay_ca_der, revision],
        )?;
        for item in &state.provisioners {
            transaction.execute(
                "INSERT INTO provisioners(endpoint_id, name, active) VALUES (?1, ?2, 1) ON CONFLICT(endpoint_id) DO UPDATE SET name=excluded.name, active=1",
                params![item.endpoint_id, item.name],
            )?;
        }
        for item in &state.clients {
            transaction.execute(
                "INSERT INTO clients(endpoint_id, name, managed_by) VALUES (?1, ?2, ?3)",
                params![item.endpoint_id, item.name, item.managed_by],
            )?;
        }
        for item in &state.edges {
            transaction.execute(
                "INSERT INTO edges(endpoint_id, name, owner_id) VALUES (?1, ?2, ?3)",
                params![item.endpoint_id, item.name, item.owner_id],
            )?;
        }
        for item in &state.relays {
            transaction.execute(
                "INSERT INTO relays(endpoint_id, name, url, qad_port) VALUES (?1, ?2, ?3, ?4)",
                params![item.endpoint_id, item.name, item.url, item.qad_port],
            )?;
        }
        for item in &state.invites {
            let (kind, owner_id) = match &item.invite.kind {
                InviteKind::Client => ("client", None),
                InviteKind::Edge { owner_id } => (
                    "edge",
                    state
                        .clients
                        .iter()
                        .any(|client| client.endpoint_id == *owner_id)
                        .then_some(owner_id.as_str()),
                ),
                InviteKind::Relay { .. } => ("relay", None),
            };
            if let Some(endpoint_id) = item.managed_by.as_deref() {
                transaction.execute(
                    "INSERT INTO provisioners(endpoint_id, name, active) VALUES (?1, ?2, 0) ON CONFLICT(endpoint_id) DO NOTHING",
                    params![endpoint_id, format!("deleted:{endpoint_id}")],
                )?;
            }
            let state_value = match item.state {
                InviteState::Pending => "pending",
                InviteState::Claimed => "claimed",
                InviteState::Revoked => "revoked",
            };
            transaction.execute(
                "INSERT INTO invitations(invite_id, name, kind, owner_id, invite_json, expires_at, state, claimed_by, request_id, managed_by, request_hash, terminal_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![item.invite.invite_id, item.invite.name, kind, owner_id, serde_json::to_string(&item.invite)?, item.invite.expires_at, state_value, item.claimed_by, item.request_id, item.managed_by, item.request_hash, item.terminal_at],
            )?;
        }
        transaction.execute(
            "DELETE FROM provisioners WHERE active = 0 AND endpoint_id NOT IN (SELECT managed_by FROM invitations WHERE managed_by IS NOT NULL) AND endpoint_id NOT IN (SELECT managed_by FROM clients WHERE managed_by IS NOT NULL)",
            [],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub async fn replace(&self, state: ControlState) -> Result<()> {
        let database = self.clone();
        tokio::task::spawn_blocking(move || database.replace_sync(&state))
            .await
            .context("join SQLite writer")?
    }
}

fn query_all<T>(
    connection: &Connection,
    sql: &str,
    map: impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
) -> Result<Vec<T>> {
    let mut statement = connection.prepare(sql)?;
    Ok(statement.query_map([], map)?.collect::<rusqlite::Result<Vec<_>>>()?)
}

fn has_column(transaction: &rusqlite::Transaction<'_>, table: &str, column: &str) -> Result<bool> {
    let mut statement = transaction.prepare(&format!("PRAGMA table_info({table})"))?;
    let names = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(names.iter().any(|name| name == column))
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh_base::SecretKey;

    fn empty_state() -> ControlState {
        ControlState {
            schema: STATE_SCHEMA,
            audience: "test".into(),
            public_url: "http://127.0.0.1:3350".into(),
            relay_ca_der: vec![1, 2, 3],
            revision: 0,
            clients: vec![],
            edges: vec![],
            relays: vec![],
            invites: vec![],
            provisioners: vec![],
        }
    }

    #[test]
    fn fresh_schema_and_migration_are_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.db");
        let database = Database::create(&path, &empty_state()).unwrap();
        database.migrate().unwrap();
        let connection = database.connection.lock().unwrap();
        let count: i64 = connection
            .query_row("SELECT count(*) FROM migrations WHERE version = 1", [], |row| {
                row.get(0)
            })
            .unwrap();
        let journal: String = connection
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        let foreign_keys: i64 = connection
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
        assert_eq!(journal, "wal");
        assert_eq!(foreign_keys, 1);
    }

    #[test]
    fn unique_and_foreign_key_failures_are_atomic() {
        let dir = tempfile::tempdir().unwrap();
        let database = Database::create(&dir.path().join("control.db"), &empty_state()).unwrap();
        let mut invalid = empty_state();
        invalid.revision = 1;
        invalid.edges.push(EdgeRecord {
            name: "box".into(),
            endpoint_id: SecretKey::generate().public().to_string(),
            owner_id: SecretKey::generate().public().to_string(),
        });
        assert!(database.replace_sync(&invalid).is_err());
        let loaded = database.load().unwrap();
        assert_eq!(loaded.revision, 0);
        assert!(loaded.edges.is_empty());

        invalid.edges.clear();
        invalid.clients = vec![
            ClientRecord {
                name: "same".into(),
                endpoint_id: SecretKey::generate().public().to_string(),
                managed_by: None,
            },
            ClientRecord {
                name: "same".into(),
                endpoint_id: SecretKey::generate().public().to_string(),
                managed_by: None,
            },
        ];
        assert!(database.replace_sync(&invalid).is_err());
        assert_eq!(database.load().unwrap().revision, 0);

        let mut skipped = empty_state();
        skipped.revision = 2;
        assert!(database.replace_sync(&skipped).is_err());
        assert_eq!(database.load().unwrap().revision, 0);
    }

    #[test]
    fn deleted_provisioner_history_lasts_until_invitation_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let key = SecretKey::generate();
        let provisioner_id = SecretKey::generate().public().to_string();
        let mut state = empty_state();
        state.provisioners.push(ProvisionerRecord {
            name: "controller".into(),
            endpoint_id: provisioner_id.clone(),
        });
        crate::create_invite(&key, &mut state, "job".into(), InviteKind::Client, 900).unwrap();
        state.invites[0].managed_by = Some(provisioner_id.clone());
        let database = Database::create(&dir.path().join("control.db"), &state).unwrap();

        state.provisioners.clear();
        state.revision = 1;
        database.replace_sync(&state).unwrap();
        let restored = database.load().unwrap();
        assert!(restored.provisioners.is_empty());
        assert_eq!(restored.invites[0].managed_by.as_deref(), Some(provisioner_id.as_str()));

        state.invites.clear();
        database.replace_sync(&state).unwrap();
        let connection = database.connection.lock().unwrap();
        let count: i64 = connection
            .query_row("SELECT count(*) FROM provisioners", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }
}
