-- The upstream connector an identity came through; the SQLite twin of this
-- migration explains the column. Google was the only connector before it,
-- so 'google' backfills every existing row. The default is dropped once the
-- rows are filled, as in the baseline: every writer sets the column.
-- device_codes carries an identity only once approved, so its column is
-- nullable and only approved rows are backfilled, keyed on approved_at as
-- in SQLite.
ALTER TABLE auth_requests ADD COLUMN connector_id TEXT NOT NULL DEFAULT 'google';
ALTER TABLE auth_requests ALTER COLUMN connector_id DROP DEFAULT;
ALTER TABLE auth_codes ADD COLUMN connector_id TEXT NOT NULL DEFAULT 'google';
ALTER TABLE auth_codes ALTER COLUMN connector_id DROP DEFAULT;
ALTER TABLE refresh_tokens ADD COLUMN connector_id TEXT NOT NULL DEFAULT 'google';
ALTER TABLE refresh_tokens ALTER COLUMN connector_id DROP DEFAULT;
ALTER TABLE browser_sessions ADD COLUMN connector_id TEXT NOT NULL DEFAULT 'google';
ALTER TABLE browser_sessions ALTER COLUMN connector_id DROP DEFAULT;
ALTER TABLE device_codes ADD COLUMN connector_id TEXT;

UPDATE device_codes SET connector_id = 'google' WHERE approved_at IS NOT NULL;
