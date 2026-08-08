CREATE TABLE IF NOT EXISTS migrations (
    version INTEGER PRIMARY KEY,
    applied_at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS metadata (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    schema_version INTEGER NOT NULL,
    audience TEXT NOT NULL CHECK (length(audience) > 0),
    public_url TEXT NOT NULL CHECK (length(public_url) > 0),
    revision INTEGER NOT NULL CHECK (revision >= 0)
) STRICT;

CREATE TABLE IF NOT EXISTS provisioners (
    endpoint_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1))
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS provisioners_active_name
ON provisioners(name) WHERE active = 1;

CREATE TABLE IF NOT EXISTS centers (
    endpoint_id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    managed_by TEXT REFERENCES provisioners(endpoint_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE IF NOT EXISTS edges (
    endpoint_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    owner_id TEXT NOT NULL REFERENCES centers(endpoint_id) ON DELETE RESTRICT,
    UNIQUE(owner_id, name)
) STRICT;

CREATE TABLE IF NOT EXISTS relays (
    endpoint_id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    url TEXT NOT NULL UNIQUE
) STRICT;

CREATE TABLE IF NOT EXISTS invitations (
    invite_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('center', 'edge', 'relay')),
    owner_id TEXT REFERENCES centers(endpoint_id) ON DELETE SET NULL,
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
