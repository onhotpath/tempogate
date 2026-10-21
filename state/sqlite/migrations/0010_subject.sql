-- The upstream (Google) `sub` becomes the identity tempogate mints as the
-- token's sub; email stays as a claim. Every table that carries an identity
-- across a hop records it. Rows written before this migration get '' (or
-- NULL for device_codes, whose identity is stamped only on approval); the
-- handlers reject such rows (invalid_grant / restart sign-in), because they
-- were admitted without the hosted-domain check and have no subject to mint.
ALTER TABLE auth_codes ADD COLUMN subject TEXT NOT NULL DEFAULT '';
ALTER TABLE refresh_tokens ADD COLUMN subject TEXT NOT NULL DEFAULT '';
ALTER TABLE browser_sessions ADD COLUMN subject TEXT NOT NULL DEFAULT '';
ALTER TABLE device_codes ADD COLUMN subject TEXT;
