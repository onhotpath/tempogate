-- First-party browser session table for the device-flow verification UI.
-- sid is an opaque 32-byte random value (base64url) carried in a signed
-- HttpOnly cookie scoped to the verification pages; the cookie's signature
-- protects integrity, this row binds it to the authenticated email and an
-- absolute expiry. TTL enforcement is the handler's concern (it owns the
-- clock); the row survives until consume / forced revocation, or until the
-- reaper `serve` runs (reaper.go) deletes it after expiry.
CREATE TABLE browser_sessions (
    sid         TEXT PRIMARY KEY,
    email       TEXT NOT NULL,
    created_at  TIMESTAMP NOT NULL,
    expires_at  TIMESTAMP NOT NULL
);

CREATE INDEX idx_browser_sessions_expires_at ON browser_sessions(expires_at);
