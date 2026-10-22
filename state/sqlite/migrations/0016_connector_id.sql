-- The upstream connector an identity came through. A token's sub is
-- `<connector_id>:<subject>`, composed at mint time and never stored, so
-- `subject` keeps the upstream's own value and identities stay keyed by the
-- pair: the same upstream subject at two connectors is two people.
--
-- Google was the only connector before this migration, so 'google' is the
-- correct backfill for every existing row. The defaults exist only because
-- SQLite needs one to add a NOT NULL column; every writer sets the column.
-- device_codes carries an identity only once approved, like subject, so its
-- column is nullable and only approved rows are backfilled. The backfill
-- keys on approved_at rather than subject so it does not depend on 0010
-- having run first (migrate fills in missing lower versions too).
ALTER TABLE auth_requests ADD COLUMN connector_id TEXT NOT NULL DEFAULT 'google';
ALTER TABLE auth_codes ADD COLUMN connector_id TEXT NOT NULL DEFAULT 'google';
ALTER TABLE refresh_tokens ADD COLUMN connector_id TEXT NOT NULL DEFAULT 'google';
ALTER TABLE browser_sessions ADD COLUMN connector_id TEXT NOT NULL DEFAULT 'google';
ALTER TABLE device_codes ADD COLUMN connector_id TEXT;

UPDATE device_codes SET connector_id = 'google' WHERE approved_at IS NOT NULL;
