-- One row per refresh-token family: the lock that keeps a rotation from
-- persisting a live child into a family being revoked (state/doc.go,
-- "Refresh families"). Under READ COMMITTED the guarded INSERT SQLite uses
-- is write skew, so SaveRefresh locks this row FOR SHARE before inserting a
-- token, and every revocation updates it before revoking the tokens:
-- whichever commits second sees the other.
--
-- revoked_at is the family's revocation, stamped once. Backfilled from the
-- tokens, though a database at the baseline has none yet.
CREATE TABLE refresh_families (
    family_id  TEXT PRIMARY KEY,
    revoked_at TIMESTAMPTZ
);

INSERT INTO refresh_families (family_id, revoked_at)
SELECT family_id, min(revoked_at) FROM refresh_tokens GROUP BY family_id;
