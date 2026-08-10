CREATE TABLE IF NOT EXISTS migrations (
    version INTEGER PRIMARY KEY,
    applied_at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS metadata (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    schema_version INTEGER NOT NULL,
    audience TEXT NOT NULL CHECK (length(audience) > 0),
    public_url TEXT NOT NULL CHECK (length(public_url) > 0),
    relay_ca_der BLOB NOT NULL CHECK (length(relay_ca_der) > 0),
    revision INTEGER NOT NULL CHECK (revision >= 0),
    relay_revision INTEGER NOT NULL CHECK (relay_revision > 0)
) STRICT;

CREATE TABLE IF NOT EXISTS provisioners (
    endpoint_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1))
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS provisioners_active_name
ON provisioners(name) WHERE active = 1;

CREATE TABLE IF NOT EXISTS clients (
    endpoint_id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    managed_by TEXT REFERENCES provisioners(endpoint_id) ON DELETE RESTRICT,
    credential_generation INTEGER NOT NULL CHECK (credential_generation > 0),
    credential_issued_at INTEGER NOT NULL,
    credential_expires_at INTEGER NOT NULL CHECK (credential_expires_at > credential_issued_at)
) STRICT;

CREATE TABLE IF NOT EXISTS edges (
    endpoint_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    owner_id TEXT NOT NULL REFERENCES clients(endpoint_id) ON DELETE RESTRICT,
    credential_generation INTEGER NOT NULL CHECK (credential_generation > 0),
    credential_issued_at INTEGER NOT NULL,
    credential_expires_at INTEGER NOT NULL CHECK (credential_expires_at > credential_issued_at),
    UNIQUE(owner_id, name)
) STRICT;

CREATE TABLE IF NOT EXISTS relay_revocations (
    endpoint_id TEXT PRIMARY KEY,
    revoked_through_generation INTEGER NOT NULL CHECK (revoked_through_generation > 0),
    expires_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0)
) STRICT;

CREATE TABLE IF NOT EXISTS relays (
    endpoint_id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    url TEXT NOT NULL UNIQUE,
    qad_port INTEGER CHECK (qad_port BETWEEN 1 AND 65535)
) STRICT;

CREATE TABLE IF NOT EXISTS invitations (
    invite_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('client', 'edge', 'relay')),
    owner_id TEXT REFERENCES clients(endpoint_id) ON DELETE SET NULL,
    invite_json TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'claimed', 'revoked')),
    claimed_by TEXT,
    request_id TEXT UNIQUE,
    managed_by TEXT REFERENCES provisioners(endpoint_id) ON DELETE SET NULL,
    request_hash TEXT,
    terminal_at INTEGER,
    CHECK (kind = 'edge' OR owner_id IS NULL),
    CHECK ((state = 'pending') = (terminal_at IS NULL))
) STRICT;
