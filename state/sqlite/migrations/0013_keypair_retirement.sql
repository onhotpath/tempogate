-- Signing-key retirement. A retired keypair never signs again and leaves
-- JWKS once KEYS_RETIREMENT_GRACE has elapsed after retired_at; NULL means
-- active. Added in place (no table rebuild), so existing keypairs keep their
-- rows and load as active.
ALTER TABLE keypairs ADD COLUMN retired_at TIMESTAMP;
