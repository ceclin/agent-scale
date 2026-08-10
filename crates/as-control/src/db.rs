use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result};
use control_api::{Invite, InviteKind};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use super::{
    ClientRecord, ControlState, EdgeRecord, InviteRecord, InviteState, ProvisionerRecord,
    RELAY_CREDENTIAL_LIFETIME_SECS, RelayRecord, RevocationRecord, STATE_SCHEMA, StateChange, StateDelta,
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
        db.initialize_sync(state)?;
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
        let applied: bool = transaction
            .query_row("SELECT 1 FROM migrations WHERE version = 3", [], |_| Ok(true))
            .optional()?
            .unwrap_or(false);
        if !applied {
            let now = unix_timestamp();
            let expires_at = now.saturating_add(RELAY_CREDENTIAL_LIFETIME_SECS);
            if !has_column(&transaction, "metadata", "relay_revision")? {
                transaction.execute(
                    "ALTER TABLE metadata ADD COLUMN relay_revision INTEGER NOT NULL DEFAULT 1",
                    [],
                )?;
            }
            if !has_column(&transaction, "clients", "credential_generation")? {
                transaction.execute(
                    "ALTER TABLE clients ADD COLUMN credential_generation INTEGER NOT NULL DEFAULT 1",
                    [],
                )?;
                transaction.execute(
                    "ALTER TABLE clients ADD COLUMN credential_issued_at INTEGER NOT NULL DEFAULT 0",
                    [],
                )?;
                transaction.execute(
                    "ALTER TABLE clients ADD COLUMN credential_expires_at INTEGER NOT NULL DEFAULT 1",
                    [],
                )?;
                transaction.execute(
                    "UPDATE clients SET credential_generation = max(1, (SELECT revision FROM metadata WHERE id = 1)), credential_issued_at = ?1, credential_expires_at = ?2",
                    params![now, expires_at],
                )?;
            }
            if !has_column(&transaction, "edges", "credential_generation")? {
                transaction.execute(
                    "ALTER TABLE edges ADD COLUMN credential_generation INTEGER NOT NULL DEFAULT 1",
                    [],
                )?;
                transaction.execute(
                    "ALTER TABLE edges ADD COLUMN credential_issued_at INTEGER NOT NULL DEFAULT 0",
                    [],
                )?;
                transaction.execute(
                    "ALTER TABLE edges ADD COLUMN credential_expires_at INTEGER NOT NULL DEFAULT 1",
                    [],
                )?;
                transaction.execute(
                    "UPDATE edges SET credential_generation = max(1, (SELECT revision FROM metadata WHERE id = 1)), credential_issued_at = ?1, credential_expires_at = ?2",
                    params![now, expires_at],
                )?;
            }
            transaction.execute_batch(
                "CREATE TABLE IF NOT EXISTS relay_revocations (
                    endpoint_id TEXT PRIMARY KEY,
                    revoked_through_generation INTEGER NOT NULL CHECK (revoked_through_generation > 0),
                    expires_at INTEGER NOT NULL,
                    revision INTEGER NOT NULL CHECK (revision > 0)
                ) STRICT;",
            )?;
            transaction.execute("UPDATE metadata SET schema_version = ?1", [STATE_SCHEMA])?;
            transaction.execute("INSERT INTO migrations(version, applied_at) VALUES (3, ?1)", [now])?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn load(&self) -> Result<ControlState> {
        let connection = self.connection.lock().expect("database mutex poisoned");
        let (schema, audience, public_url, relay_ca_der, revision, relay_revision) = connection
            .query_row(
                "SELECT schema_version, audience, public_url, relay_ca_der, revision, relay_revision FROM metadata WHERE id = 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, u32>(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                },
            )
            .context("database is not initialized; run `as-control init` to initialize a new network")?;
        anyhow::ensure!(schema == STATE_SCHEMA, "unsupported state schema {schema}");
        let revision = u64::try_from(revision).context("negative control revision")?;
        let relay_revision = u64::try_from(relay_revision).context("negative Relay revision")?;

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
            "SELECT name, endpoint_id, managed_by, credential_generation, credential_issued_at, credential_expires_at FROM clients ORDER BY name",
            |row| {
                Ok(ClientRecord {
                    name: row.get(0)?,
                    endpoint_id: row.get(1)?,
                    managed_by: row.get(2)?,
                    credential_generation: u64::try_from(row.get::<_, i64>(3)?)
                        .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(3, 0))?,
                    credential_issued_at: row.get(4)?,
                    credential_expires_at: row.get(5)?,
                })
            },
        )?;
        let edges = query_all(
            &connection,
            "SELECT name, endpoint_id, owner_id, credential_generation, credential_issued_at, credential_expires_at FROM edges ORDER BY owner_id, name",
            |row| {
                Ok(EdgeRecord {
                    name: row.get(0)?,
                    endpoint_id: row.get(1)?,
                    owner_id: row.get(2)?,
                    credential_generation: u64::try_from(row.get::<_, i64>(3)?)
                        .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(3, 0))?,
                    credential_issued_at: row.get(4)?,
                    credential_expires_at: row.get(5)?,
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
        let revocations = query_all(
            &connection,
            "SELECT endpoint_id, revoked_through_generation, expires_at, revision FROM relay_revocations ORDER BY endpoint_id",
            |row| {
                Ok(RevocationRecord {
                    endpoint_id: row.get(0)?,
                    revoked_through_generation: u64::try_from(row.get::<_, i64>(1)?)
                        .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(1, 0))?,
                    expires_at: row.get(2)?,
                    revision: u64::try_from(row.get::<_, i64>(3)?)
                        .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(3, 0))?,
                })
            },
        )?;
        Ok(ControlState {
            schema,
            audience,
            public_url,
            relay_ca_der,
            revision,
            relay_revision,
            clients,
            edges,
            relays,
            invites,
            provisioners,
            revocations,
        })
    }

    fn initialize_sync(&self, state: &ControlState) -> Result<()> {
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
        let stored_relay_revision: Option<i64> = transaction
            .query_row("SELECT relay_revision FROM metadata WHERE id = 1", [], |row| row.get(0))
            .optional()?;
        if let Some(stored_relay_revision) = stored_relay_revision {
            let stored_relay_revision =
                u64::try_from(stored_relay_revision).context("negative stored Relay revision")?;
            anyhow::ensure!(
                state.relay_revision == stored_relay_revision
                    || state.relay_revision == stored_relay_revision.saturating_add(1),
                "Relay revision must remain unchanged or advance atomically by one"
            );
        }
        anyhow::ensure!(
            state
                .revocations
                .iter()
                .all(|revocation| revocation.revision <= state.relay_revision),
            "revocation record is ahead of the Relay revision"
        );
        transaction.execute("DELETE FROM invitations", [])?;
        transaction.execute("DELETE FROM edges", [])?;
        transaction.execute("DELETE FROM clients", [])?;
        transaction.execute("DELETE FROM relays", [])?;
        transaction.execute("DELETE FROM relay_revocations", [])?;
        transaction.execute("UPDATE provisioners SET active = 0", [])?;
        let revision = i64::try_from(state.revision).context("control revision exceeds SQLite range")?;
        let relay_revision = i64::try_from(state.relay_revision).context("Relay revision exceeds SQLite range")?;
        transaction.execute(
            "INSERT INTO metadata(id, schema_version, audience, public_url, relay_ca_der, revision, relay_revision) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT(id) DO UPDATE SET schema_version=excluded.schema_version, audience=excluded.audience, public_url=excluded.public_url, relay_ca_der=excluded.relay_ca_der, revision=excluded.revision, relay_revision=excluded.relay_revision",
            params![state.schema, state.audience, state.public_url, state.relay_ca_der, revision, relay_revision],
        )?;
        for item in &state.provisioners {
            transaction.execute(
                "INSERT INTO provisioners(endpoint_id, name, active) VALUES (?1, ?2, 1) ON CONFLICT(endpoint_id) DO UPDATE SET name=excluded.name, active=1",
                params![item.endpoint_id, item.name],
            )?;
        }
        for item in &state.clients {
            let credential_generation = i64::try_from(item.credential_generation)
                .context("Client credential generation exceeds SQLite range")?;
            transaction.execute(
                "INSERT INTO clients(endpoint_id, name, managed_by, credential_generation, credential_issued_at, credential_expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![item.endpoint_id, item.name, item.managed_by, credential_generation, item.credential_issued_at, item.credential_expires_at],
            )?;
        }
        for item in &state.edges {
            let credential_generation =
                i64::try_from(item.credential_generation).context("Edge credential generation exceeds SQLite range")?;
            transaction.execute(
                "INSERT INTO edges(endpoint_id, name, owner_id, credential_generation, credential_issued_at, credential_expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![item.endpoint_id, item.name, item.owner_id, credential_generation, item.credential_issued_at, item.credential_expires_at],
            )?;
        }
        for item in &state.relays {
            transaction.execute(
                "INSERT INTO relays(endpoint_id, name, url, qad_port) VALUES (?1, ?2, ?3, ?4)",
                params![item.endpoint_id, item.name, item.url, item.qad_port],
            )?;
        }
        for item in &state.revocations {
            let revoked_through_generation = i64::try_from(item.revoked_through_generation)
                .context("revoked credential generation exceeds SQLite range")?;
            let revision = i64::try_from(item.revision).context("revocation revision exceeds SQLite range")?;
            transaction.execute(
                "INSERT INTO relay_revocations(endpoint_id, revoked_through_generation, expires_at, revision) VALUES (?1, ?2, ?3, ?4)",
                params![item.endpoint_id, revoked_through_generation, item.expires_at, revision],
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

    fn apply_delta_sync(
        &self,
        expected_revision: u64,
        expected_relay_revision: u64,
        revision: u64,
        relay_revision: u64,
        delta: &StateDelta,
    ) -> Result<()> {
        anyhow::ensure!(
            revision == expected_revision || revision == expected_revision.saturating_add(1),
            "control revision must remain unchanged or advance atomically by one"
        );
        anyhow::ensure!(
            relay_revision == expected_relay_revision || relay_revision == expected_relay_revision.saturating_add(1),
            "Relay revision must remain unchanged or advance atomically by one"
        );
        let mut connection = self.connection.lock().expect("database mutex poisoned");
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        for change in &delta.changes {
            match change {
                StateChange::PutClient(item) => {
                    if let Some(endpoint_id) = item.managed_by.as_deref() {
                        ensure_provisioner_placeholder(&transaction, endpoint_id)?;
                    }
                    let generation = i64::try_from(item.credential_generation)
                        .context("Client credential generation exceeds SQLite range")?;
                    transaction.execute(
                        "INSERT INTO clients(endpoint_id, name, managed_by, credential_generation, credential_issued_at, credential_expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT(endpoint_id) DO UPDATE SET name=excluded.name, managed_by=excluded.managed_by, credential_generation=excluded.credential_generation, credential_issued_at=excluded.credential_issued_at, credential_expires_at=excluded.credential_expires_at",
                        params![item.endpoint_id, item.name, item.managed_by, generation, item.credential_issued_at, item.credential_expires_at],
                    )?;
                }
                StateChange::DeleteClient(endpoint_id) => {
                    transaction.execute("DELETE FROM clients WHERE endpoint_id = ?1", [endpoint_id])?;
                }
                StateChange::PutEdge(item) => {
                    let generation = i64::try_from(item.credential_generation)
                        .context("Edge credential generation exceeds SQLite range")?;
                    transaction.execute(
                        "INSERT INTO edges(endpoint_id, name, owner_id, credential_generation, credential_issued_at, credential_expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT(endpoint_id) DO UPDATE SET name=excluded.name, owner_id=excluded.owner_id, credential_generation=excluded.credential_generation, credential_issued_at=excluded.credential_issued_at, credential_expires_at=excluded.credential_expires_at",
                        params![item.endpoint_id, item.name, item.owner_id, generation, item.credential_issued_at, item.credential_expires_at],
                    )?;
                }
                StateChange::DeleteEdge(endpoint_id) => {
                    transaction.execute("DELETE FROM edges WHERE endpoint_id = ?1", [endpoint_id])?;
                }
                StateChange::PutRelay(item) => {
                    transaction.execute(
                        "INSERT INTO relays(endpoint_id, name, url, qad_port) VALUES (?1, ?2, ?3, ?4) ON CONFLICT(endpoint_id) DO UPDATE SET name=excluded.name, url=excluded.url, qad_port=excluded.qad_port",
                        params![item.endpoint_id, item.name, item.url, item.qad_port],
                    )?;
                }
                StateChange::DeleteRelay(endpoint_id) => {
                    transaction.execute("DELETE FROM relays WHERE endpoint_id = ?1", [endpoint_id])?;
                }
                StateChange::PutInvite(item) => {
                    if let Some(endpoint_id) = item.managed_by.as_deref() {
                        ensure_provisioner_placeholder(&transaction, endpoint_id)?;
                    }
                    let (kind, owner_id) = match &item.invite.kind {
                        InviteKind::Client => ("client", None),
                        InviteKind::Edge { owner_id } => ("edge", Some(owner_id.as_str())),
                        InviteKind::Relay { .. } => ("relay", None),
                    };
                    let state = match item.state {
                        InviteState::Pending => "pending",
                        InviteState::Claimed => "claimed",
                        InviteState::Revoked => "revoked",
                    };
                    transaction.execute(
                        "INSERT INTO invitations(invite_id, name, kind, owner_id, invite_json, expires_at, state, claimed_by, request_id, managed_by, request_hash, terminal_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12) ON CONFLICT(invite_id) DO UPDATE SET name=excluded.name, kind=excluded.kind, owner_id=excluded.owner_id, invite_json=excluded.invite_json, expires_at=excluded.expires_at, state=excluded.state, claimed_by=excluded.claimed_by, request_id=excluded.request_id, managed_by=excluded.managed_by, request_hash=excluded.request_hash, terminal_at=excluded.terminal_at",
                        params![item.invite.invite_id, item.invite.name, kind, owner_id, serde_json::to_string(&item.invite)?, item.invite.expires_at, state, item.claimed_by, item.request_id, item.managed_by, item.request_hash, item.terminal_at],
                    )?;
                }
                StateChange::DeleteInvite(invite_id) => {
                    transaction.execute("DELETE FROM invitations WHERE invite_id = ?1", [invite_id])?;
                }
                StateChange::PutProvisioner(item) => {
                    transaction.execute(
                        "INSERT INTO provisioners(endpoint_id, name, active) VALUES (?1, ?2, 1) ON CONFLICT(endpoint_id) DO UPDATE SET name=excluded.name, active=1",
                        params![item.endpoint_id, item.name],
                    )?;
                }
                StateChange::DeleteProvisioner(endpoint_id) => {
                    transaction.execute(
                        "UPDATE provisioners SET active = 0 WHERE endpoint_id = ?1",
                        [endpoint_id],
                    )?;
                }
                StateChange::PutRevocation(item) => {
                    anyhow::ensure!(
                        item.revision <= relay_revision,
                        "revocation record is ahead of Relay revision"
                    );
                    let generation = i64::try_from(item.revoked_through_generation)
                        .context("revoked credential generation exceeds SQLite range")?;
                    let item_revision =
                        i64::try_from(item.revision).context("revocation revision exceeds SQLite range")?;
                    transaction.execute(
                        "INSERT INTO relay_revocations(endpoint_id, revoked_through_generation, expires_at, revision) VALUES (?1, ?2, ?3, ?4) ON CONFLICT(endpoint_id) DO UPDATE SET revoked_through_generation=excluded.revoked_through_generation, expires_at=excluded.expires_at, revision=excluded.revision",
                        params![item.endpoint_id, generation, item.expires_at, item_revision],
                    )?;
                }
                StateChange::DeleteRevocation(endpoint_id) => {
                    transaction.execute("DELETE FROM relay_revocations WHERE endpoint_id = ?1", [endpoint_id])?;
                }
            }
        }
        transaction.execute(
            "DELETE FROM provisioners WHERE active = 0 AND endpoint_id NOT IN (SELECT managed_by FROM invitations WHERE managed_by IS NOT NULL) AND endpoint_id NOT IN (SELECT managed_by FROM clients WHERE managed_by IS NOT NULL)",
            [],
        )?;
        let revision = i64::try_from(revision).context("control revision exceeds SQLite range")?;
        let relay_revision = i64::try_from(relay_revision).context("Relay revision exceeds SQLite range")?;
        let expected_revision = i64::try_from(expected_revision).context("control revision exceeds SQLite range")?;
        let expected_relay_revision =
            i64::try_from(expected_relay_revision).context("Relay revision exceeds SQLite range")?;
        let changed = transaction.execute(
            "UPDATE metadata SET revision = ?1, relay_revision = ?2 WHERE id = 1 AND revision = ?3 AND relay_revision = ?4",
            params![revision, relay_revision, expected_revision, expected_relay_revision],
        )?;
        anyhow::ensure!(changed == 1, "durable Control revision changed while applying mutation");
        transaction.commit()?;
        Ok(())
    }

    pub async fn apply_delta(
        &self,
        expected_revision: u64,
        expected_relay_revision: u64,
        revision: u64,
        relay_revision: u64,
        delta: StateDelta,
    ) -> Result<()> {
        let database = self.clone();
        tokio::task::spawn_blocking(move || {
            database.apply_delta_sync(
                expected_revision,
                expected_relay_revision,
                revision,
                relay_revision,
                &delta,
            )
        })
        .await
        .context("join SQLite writer")?
    }

    pub fn apply_sync(&self, previous: &ControlState, next: &ControlState) -> Result<()> {
        let mut connection = self.connection.lock().expect("database mutex poisoned");
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (stored_revision, stored_relay_revision) = transaction.query_row(
            "SELECT revision, relay_revision FROM metadata WHERE id = 1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )?;
        let stored_revision = u64::try_from(stored_revision).context("negative stored control revision")?;
        let stored_relay_revision = u64::try_from(stored_relay_revision).context("negative stored Relay revision")?;
        anyhow::ensure!(
            stored_revision == previous.revision && stored_relay_revision == previous.relay_revision,
            "durable Control state changed while applying mutation"
        );
        anyhow::ensure!(
            next.revision == previous.revision || next.revision == previous.revision.saturating_add(1),
            "control revision must remain unchanged or advance atomically by one"
        );
        anyhow::ensure!(
            next.relay_revision == previous.relay_revision
                || next.relay_revision == previous.relay_revision.saturating_add(1),
            "Relay revision must remain unchanged or advance atomically by one"
        );
        anyhow::ensure!(
            next.revocations
                .iter()
                .all(|revocation| revocation.revision <= next.relay_revision),
            "revocation record is ahead of the Relay revision"
        );

        let previous_invites: HashMap<_, _> = previous
            .invites
            .iter()
            .map(|item| (item.invite.invite_id.as_str(), item))
            .collect();
        let next_invites: HashMap<_, _> = next
            .invites
            .iter()
            .map(|item| (item.invite.invite_id.as_str(), item))
            .collect();
        for invite_id in previous_invites.keys().filter(|key| !next_invites.contains_key(**key)) {
            transaction.execute("DELETE FROM invitations WHERE invite_id = ?1", [invite_id])?;
        }

        let previous_edges: HashMap<_, _> = previous
            .edges
            .iter()
            .map(|item| (item.endpoint_id.as_str(), item))
            .collect();
        let next_edges: HashMap<_, _> = next
            .edges
            .iter()
            .map(|item| (item.endpoint_id.as_str(), item))
            .collect();
        for endpoint_id in previous_edges.keys().filter(|key| !next_edges.contains_key(**key)) {
            transaction.execute("DELETE FROM edges WHERE endpoint_id = ?1", [endpoint_id])?;
        }

        let previous_clients: HashMap<_, _> = previous
            .clients
            .iter()
            .map(|item| (item.endpoint_id.as_str(), item))
            .collect();
        let next_clients: HashMap<_, _> = next
            .clients
            .iter()
            .map(|item| (item.endpoint_id.as_str(), item))
            .collect();
        for endpoint_id in previous_clients.keys().filter(|key| !next_clients.contains_key(**key)) {
            transaction.execute("DELETE FROM clients WHERE endpoint_id = ?1", [endpoint_id])?;
        }

        let previous_relays: HashMap<_, _> = previous
            .relays
            .iter()
            .map(|item| (item.endpoint_id.as_str(), item))
            .collect();
        let next_relays: HashMap<_, _> = next
            .relays
            .iter()
            .map(|item| (item.endpoint_id.as_str(), item))
            .collect();
        for endpoint_id in previous_relays.keys().filter(|key| !next_relays.contains_key(**key)) {
            transaction.execute("DELETE FROM relays WHERE endpoint_id = ?1", [endpoint_id])?;
        }

        let previous_revocations: HashMap<_, _> = previous
            .revocations
            .iter()
            .map(|item| (item.endpoint_id.as_str(), item))
            .collect();
        let next_revocations: HashMap<_, _> = next
            .revocations
            .iter()
            .map(|item| (item.endpoint_id.as_str(), item))
            .collect();
        for endpoint_id in previous_revocations
            .keys()
            .filter(|key| !next_revocations.contains_key(**key))
        {
            transaction.execute("DELETE FROM relay_revocations WHERE endpoint_id = ?1", [endpoint_id])?;
        }

        let previous_provisioners: HashMap<_, _> = previous
            .provisioners
            .iter()
            .map(|item| (item.endpoint_id.as_str(), item))
            .collect();
        let next_provisioners: HashMap<_, _> = next
            .provisioners
            .iter()
            .map(|item| (item.endpoint_id.as_str(), item))
            .collect();

        for endpoint_id in next
            .clients
            .iter()
            .filter_map(|client| client.managed_by.as_deref())
            .chain(next.invites.iter().filter_map(|invite| invite.managed_by.as_deref()))
        {
            transaction.execute(
                "INSERT INTO provisioners(endpoint_id, name, active) VALUES (?1, ?2, 0) ON CONFLICT(endpoint_id) DO NOTHING",
                params![endpoint_id, format!("deleted:{endpoint_id}")],
            )?;
        }
        for item in &next.provisioners {
            if previous_provisioners.get(item.endpoint_id.as_str()).copied() != Some(item) {
                transaction.execute(
                    "INSERT INTO provisioners(endpoint_id, name, active) VALUES (?1, ?2, 1) ON CONFLICT(endpoint_id) DO UPDATE SET name=excluded.name, active=1",
                    params![item.endpoint_id, item.name],
                )?;
            }
        }

        for item in &next.clients {
            if previous_clients.get(item.endpoint_id.as_str()).copied() != Some(item) {
                let generation = i64::try_from(item.credential_generation)
                    .context("Client credential generation exceeds SQLite range")?;
                transaction.execute(
                    "INSERT INTO clients(endpoint_id, name, managed_by, credential_generation, credential_issued_at, credential_expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT(endpoint_id) DO UPDATE SET name=excluded.name, managed_by=excluded.managed_by, credential_generation=excluded.credential_generation, credential_issued_at=excluded.credential_issued_at, credential_expires_at=excluded.credential_expires_at",
                    params![item.endpoint_id, item.name, item.managed_by, generation, item.credential_issued_at, item.credential_expires_at],
                )?;
            }
        }
        for item in &next.edges {
            if previous_edges.get(item.endpoint_id.as_str()).copied() != Some(item) {
                let generation = i64::try_from(item.credential_generation)
                    .context("Edge credential generation exceeds SQLite range")?;
                transaction.execute(
                    "INSERT INTO edges(endpoint_id, name, owner_id, credential_generation, credential_issued_at, credential_expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT(endpoint_id) DO UPDATE SET name=excluded.name, owner_id=excluded.owner_id, credential_generation=excluded.credential_generation, credential_issued_at=excluded.credential_issued_at, credential_expires_at=excluded.credential_expires_at",
                    params![item.endpoint_id, item.name, item.owner_id, generation, item.credential_issued_at, item.credential_expires_at],
                )?;
            }
        }
        for item in &next.relays {
            if previous_relays.get(item.endpoint_id.as_str()).copied() != Some(item) {
                transaction.execute(
                    "INSERT INTO relays(endpoint_id, name, url, qad_port) VALUES (?1, ?2, ?3, ?4) ON CONFLICT(endpoint_id) DO UPDATE SET name=excluded.name, url=excluded.url, qad_port=excluded.qad_port",
                    params![item.endpoint_id, item.name, item.url, item.qad_port],
                )?;
            }
        }
        for item in &next.revocations {
            if previous_revocations.get(item.endpoint_id.as_str()).copied() != Some(item) {
                let generation = i64::try_from(item.revoked_through_generation)
                    .context("revoked credential generation exceeds SQLite range")?;
                let revision = i64::try_from(item.revision).context("revocation revision exceeds SQLite range")?;
                transaction.execute(
                    "INSERT INTO relay_revocations(endpoint_id, revoked_through_generation, expires_at, revision) VALUES (?1, ?2, ?3, ?4) ON CONFLICT(endpoint_id) DO UPDATE SET revoked_through_generation=excluded.revoked_through_generation, expires_at=excluded.expires_at, revision=excluded.revision",
                    params![item.endpoint_id, generation, item.expires_at, revision],
                )?;
            }
        }
        for item in &next.invites {
            if previous_invites.get(item.invite.invite_id.as_str()).copied() != Some(item) {
                let (kind, owner_id) = match &item.invite.kind {
                    InviteKind::Client => ("client", None),
                    InviteKind::Edge { owner_id } => (
                        "edge",
                        next.clients
                            .iter()
                            .any(|client| client.endpoint_id == *owner_id)
                            .then_some(owner_id.as_str()),
                    ),
                    InviteKind::Relay { .. } => ("relay", None),
                };
                let state = match item.state {
                    InviteState::Pending => "pending",
                    InviteState::Claimed => "claimed",
                    InviteState::Revoked => "revoked",
                };
                transaction.execute(
                    "INSERT INTO invitations(invite_id, name, kind, owner_id, invite_json, expires_at, state, claimed_by, request_id, managed_by, request_hash, terminal_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12) ON CONFLICT(invite_id) DO UPDATE SET name=excluded.name, kind=excluded.kind, owner_id=excluded.owner_id, invite_json=excluded.invite_json, expires_at=excluded.expires_at, state=excluded.state, claimed_by=excluded.claimed_by, request_id=excluded.request_id, managed_by=excluded.managed_by, request_hash=excluded.request_hash, terminal_at=excluded.terminal_at",
                    params![item.invite.invite_id, item.invite.name, kind, owner_id, serde_json::to_string(&item.invite)?, item.invite.expires_at, state, item.claimed_by, item.request_id, item.managed_by, item.request_hash, item.terminal_at],
                )?;
            }
        }

        for endpoint_id in previous_provisioners
            .keys()
            .filter(|key| !next_provisioners.contains_key(**key))
        {
            transaction.execute(
                "UPDATE provisioners SET active = 0 WHERE endpoint_id = ?1",
                [endpoint_id],
            )?;
        }
        transaction.execute(
            "DELETE FROM provisioners WHERE active = 0 AND endpoint_id NOT IN (SELECT managed_by FROM invitations WHERE managed_by IS NOT NULL) AND endpoint_id NOT IN (SELECT managed_by FROM clients WHERE managed_by IS NOT NULL)",
            [],
        )?;

        let revision = i64::try_from(next.revision).context("control revision exceeds SQLite range")?;
        let relay_revision = i64::try_from(next.relay_revision).context("Relay revision exceeds SQLite range")?;
        let expected_revision = i64::try_from(previous.revision).context("control revision exceeds SQLite range")?;
        let expected_relay_revision =
            i64::try_from(previous.relay_revision).context("Relay revision exceeds SQLite range")?;
        let changed = transaction.execute(
            "UPDATE metadata SET schema_version = ?1, audience = ?2, public_url = ?3, relay_ca_der = ?4, revision = ?5, relay_revision = ?6 WHERE id = 1 AND revision = ?7 AND relay_revision = ?8",
            params![next.schema, next.audience, next.public_url, next.relay_ca_der, revision, relay_revision, expected_revision, expected_relay_revision],
        )?;
        anyhow::ensure!(changed == 1, "durable Control revision changed while applying mutation");
        transaction.commit()?;
        Ok(())
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

fn ensure_provisioner_placeholder(transaction: &rusqlite::Transaction<'_>, endpoint_id: &str) -> Result<()> {
    transaction.execute(
        "INSERT INTO provisioners(endpoint_id, name, active) VALUES (?1, ?2, 0) ON CONFLICT(endpoint_id) DO NOTHING",
        params![endpoint_id, format!("deleted:{endpoint_id}")],
    )?;
    Ok(())
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
            relay_revision: 1,
            clients: vec![],
            edges: vec![],
            relays: vec![],
            invites: vec![],
            provisioners: vec![],
            revocations: vec![],
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
            credential_generation: 1,
            credential_issued_at: 0,
            credential_expires_at: i64::MAX,
        });
        assert!(database.apply_sync(&empty_state(), &invalid).is_err());
        let loaded = database.load().unwrap();
        assert_eq!(loaded.revision, 0);
        assert!(loaded.edges.is_empty());

        invalid.edges.clear();
        invalid.clients = vec![
            ClientRecord {
                name: "same".into(),
                endpoint_id: SecretKey::generate().public().to_string(),
                managed_by: None,
                credential_generation: 1,
                credential_issued_at: 0,
                credential_expires_at: i64::MAX,
            },
            ClientRecord {
                name: "same".into(),
                endpoint_id: SecretKey::generate().public().to_string(),
                managed_by: None,
                credential_generation: 1,
                credential_issued_at: 0,
                credential_expires_at: i64::MAX,
            },
        ];
        assert!(database.apply_sync(&empty_state(), &invalid).is_err());
        assert_eq!(database.load().unwrap().revision, 0);

        let mut skipped = empty_state();
        skipped.revision = 2;
        assert!(database.apply_sync(&empty_state(), &skipped).is_err());
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

        let previous = state.clone();
        state.provisioners.clear();
        state.revision = 1;
        database.apply_sync(&previous, &state).unwrap();
        let restored = database.load().unwrap();
        assert!(restored.provisioners.is_empty());
        assert_eq!(restored.invites[0].managed_by.as_deref(), Some(provisioner_id.as_str()));

        let previous = state.clone();
        state.invites.clear();
        database.apply_sync(&previous, &state).unwrap();
        let connection = database.connection.lock().unwrap();
        let count: i64 = connection
            .query_row("SELECT count(*) FROM provisioners", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }
}
