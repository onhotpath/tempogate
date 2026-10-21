-- Bearer secrets at rest: refresh tokens (live and consumed tombstones),
-- authorization codes, device codes and verification-page session ids are
-- stored as the lowercase hex SHA-256 of the value, and looked up by it. A
-- copy of the database (a backup, a volume snapshot) then holds nothing a
-- client could present. The values are 256-bit random, so an unsalted hash
-- is enough: there is no dictionary to try.
--
-- user_code stays in clear: it is eight characters from a 20-letter
-- alphabet, so its hash would be reversed by enumerating every code in
-- seconds. It is not a credential on its own either: approving it needs a
-- signed-in browser session, and it dies with its short-lived device code.
--
-- SQLite has no SHA-256, so existing rows cannot be rehashed here. They are
-- short-lived and deleted instead: everyone signs in once more after the
-- upgrade (pre-1.0, acceptable). The columns are renamed in place rather
-- than the tables rebuilt, so columns other migrations add survive.
DELETE FROM refresh_tokens;
DELETE FROM auth_codes;
DELETE FROM device_codes;
DELETE FROM browser_sessions;

ALTER TABLE refresh_tokens RENAME COLUMN token TO token_hash;
ALTER TABLE auth_codes RENAME COLUMN code TO code_hash;
ALTER TABLE device_codes RENAME COLUMN device_code TO device_code_hash;
ALTER TABLE browser_sessions RENAME COLUMN sid TO sid_hash;
