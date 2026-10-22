-- Refresh-token lifecycle: absolute session lifetime, reuse detection and
-- revocation (RFC 9700 §4.14.2).
--
-- auth_time   the original sign-in time, carried through every rotation;
--             a session ends at auth_time + OIDC_REFRESH_MAX_LIFETIME.
-- family_id   random id minted at sign-in and carried through rotations, so
--             a replay or an operator can revoke the whole chain at once.
-- consumed_at set when the token is rotated, instead of deleting the row; the
--             tombstone is what lets a replay be recognised. Tombstones are
--             kept until the whole family is dead (past its absolute
--             expiry, or every row expired and consumed or revoked); the
--             reaper `serve` runs (reaper.go) then deletes the family.
-- revoked_at  set on every row of a revoked family, live or consumed, so a
--             rotation racing the revocation cannot persist its child.
--
-- Columns are added (not the table rebuilt) so this composes with other
-- migrations that add columns to refresh_tokens. The defaults exist only
-- because SQLite needs one to add a NOT NULL column; every writer sets both,
-- and a row that somehow kept the epoch auth_time is past any absolute
-- lifetime, so it fails closed.
--
-- Backfill: existing rows predate lineage tracking. Each becomes its own
-- family. The original sign-in time was never recorded, so auth_time takes
-- the row's created_at (its last rotation, the latest the sign-in could have
-- been): existing sessions end at most OIDC_REFRESH_MAX_LIFETIME after their
-- last refresh before the upgrade.
ALTER TABLE refresh_tokens ADD COLUMN auth_time TIMESTAMP NOT NULL DEFAULT '1970-01-01 00:00:00';
ALTER TABLE refresh_tokens ADD COLUMN family_id TEXT NOT NULL DEFAULT '';
ALTER TABLE refresh_tokens ADD COLUMN consumed_at TIMESTAMP;
ALTER TABLE refresh_tokens ADD COLUMN revoked_at TIMESTAMP;

UPDATE refresh_tokens
   SET auth_time = created_at,
       family_id = lower(hex(randomblob(16)));

CREATE INDEX idx_refresh_tokens_family_id ON refresh_tokens(family_id);
CREATE INDEX idx_refresh_tokens_email ON refresh_tokens(email);
