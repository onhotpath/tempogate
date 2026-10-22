-- The Postgres schema starts here, equal to the SQLite schema after its
-- migration 0014 (state/sqlite/migrations/0001 to 0014 explain each table
-- and column). Every later migration is a pair with the same number and name
-- in both directories.
--
-- Differences from SQLite are only those of the dialect:
--   - TIMESTAMP becomes TIMESTAMPTZ (microsecond precision, compared as
--     instants) and BLOB becomes BYTEA.
--   - Defaults SQLite needed only to add a NOT NULL column to a populated
--     table are dropped: every writer sets those columns.
--   - Keys that are ordered or range-compared (keypairs.kid,
--     integration_keys.id) use COLLATE "C", so they order bytewise like
--     SQLite, whatever the database's default collation.
--   - SQLite's explicit idx_integration_keys_id_desc is left out: the
--     primary key index already serves id DESC scans.
-- No column is generated and no default reads the clock: the application
-- passes every time (state/doc.go).

CREATE TABLE keypairs (
    kid         TEXT COLLATE "C" PRIMARY KEY,
    alg         TEXT NOT NULL,
    private_pem BYTEA NOT NULL,
    public_pem  BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL,
    retired_at  TIMESTAMPTZ
);

CREATE INDEX idx_keypairs_created_at ON keypairs(created_at);

CREATE TABLE auth_requests (
    internal_state        TEXT PRIMARY KEY,
    client_id             TEXT NOT NULL,
    redirect_uri          TEXT NOT NULL,
    scope                 TEXT NOT NULL,
    client_state          TEXT NOT NULL,
    code_challenge        TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL,
    nonce                 TEXT NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL,
    expires_at            TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_auth_requests_expires_at ON auth_requests(expires_at);

CREATE TABLE auth_codes (
    code_hash             TEXT PRIMARY KEY,
    client_id             TEXT NOT NULL,
    redirect_uri          TEXT NOT NULL,
    subject               TEXT NOT NULL,
    email                 TEXT NOT NULL,
    scope                 TEXT NOT NULL,
    code_challenge        TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL,
    nonce                 TEXT NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL,
    expires_at            TIMESTAMPTZ NOT NULL,
    consumed_at           TIMESTAMPTZ,
    family_id             TEXT NOT NULL DEFAULT ''
);

CREATE INDEX idx_auth_codes_expires_at ON auth_codes(expires_at);

CREATE TABLE refresh_tokens (
    token_hash  TEXT PRIMARY KEY,
    jti         TEXT NOT NULL,
    client_id   TEXT NOT NULL,
    subject     TEXT NOT NULL,
    email       TEXT NOT NULL,
    family_id   TEXT NOT NULL,
    auth_time   TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    revoked_at  TIMESTAMPTZ
);

CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
CREATE INDEX idx_refresh_tokens_family_id ON refresh_tokens(family_id);
CREATE INDEX idx_refresh_tokens_email ON refresh_tokens(email);

CREATE TABLE integration_keys (
    id          TEXT COLLATE "C" PRIMARY KEY,
    namespace   TEXT NOT NULL,
    role        TEXT NOT NULL CHECK (role IN ('read', 'write', 'worker', 'admin')),
    owner       TEXT NOT NULL,
    jti         TEXT NOT NULL UNIQUE,
    created_at  TIMESTAMPTZ NOT NULL,
    expires_at  TIMESTAMPTZ,
    revoked_at  TIMESTAMPTZ
);

CREATE INDEX idx_integration_keys_owner     ON integration_keys(owner);
CREATE INDEX idx_integration_keys_namespace ON integration_keys(namespace);

CREATE TABLE jti_denylist (
    jti        TEXT PRIMARY KEY,
    revoked_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE device_codes (
    device_code_hash TEXT PRIMARY KEY,
    user_code        TEXT NOT NULL UNIQUE,
    client_id        TEXT NOT NULL,
    scope            TEXT NOT NULL,
    subject          TEXT,
    email            TEXT,
    approved_at      TIMESTAMPTZ,
    denied_at        TIMESTAMPTZ,
    last_polled_at   TIMESTAMPTZ,
    interval_seconds INTEGER NOT NULL DEFAULT 5,
    created_at       TIMESTAMPTZ NOT NULL,
    expires_at       TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_device_codes_expires_at ON device_codes(expires_at);

CREATE TABLE browser_sessions (
    sid_hash    TEXT PRIMARY KEY,
    subject     TEXT NOT NULL,
    email       TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_browser_sessions_expires_at ON browser_sessions(expires_at);
