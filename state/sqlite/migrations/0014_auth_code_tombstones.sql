-- Authorization-code replay revokes what the code issued (RFC 6749 §4.1.2).
--
-- consumed_at set when the code is redeemed, instead of deleting the row; the
--             tombstone is what lets a replay be recognised. It lives until
--             the code's expires_at, when the reaper (reaper.go) deletes it
--             with every other expired code; a replay after that is refused
--             as unknown.
-- family_id   the refresh-token family the redemption started, written in
--             the same statement that consumes the code, so a replay that
--             races the first redemption still finds it.
--
-- Columns are added (not the table rebuilt) so this composes with other
-- migrations that add columns to auth_codes. The family_id default exists
-- only because SQLite needs one to add a NOT NULL column; it stays '' until
-- the code is redeemed.
ALTER TABLE auth_codes ADD COLUMN consumed_at TIMESTAMP;
ALTER TABLE auth_codes ADD COLUMN family_id TEXT NOT NULL DEFAULT '';
