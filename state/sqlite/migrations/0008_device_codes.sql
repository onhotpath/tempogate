-- RFC 8628 §3.1: per-flow row holding the device_code (the long, machine-side
-- token the polling client presents at /token) and the user_code (the short,
-- human-typeable token shown on the device and entered on the verification
-- page). user_code is stored already normalised (uppercase, no dashes) so the
-- verification path's lookup is a plain UNIQUE-index probe rather than a
-- post-hoc fold; the handler is responsible for normalising on the way in.
--
-- approved_at / denied_at carry the pending → approved/denied transition;
-- both NULL means "still awaiting user action on the verification page".
-- last_polled_at + interval_seconds back the server-enforced slow_down logic
-- (§3.5): a poll arriving sooner than interval_seconds since the last one
-- returns slow_down and bumps interval_seconds by +5. Expiry is the handler's
-- concern (it owns the clock); the row is deleted on consume or, once
-- expired, by the reaper `serve` runs (reaper.go), like auth_codes.
CREATE TABLE device_codes (
    device_code      TEXT PRIMARY KEY,
    user_code        TEXT NOT NULL UNIQUE,
    client_id        TEXT NOT NULL,
    scope            TEXT NOT NULL,
    email            TEXT,
    approved_at      TIMESTAMP,
    denied_at        TIMESTAMP,
    last_polled_at   TIMESTAMP,
    interval_seconds INTEGER NOT NULL DEFAULT 5,
    created_at       TIMESTAMP NOT NULL,
    expires_at       TIMESTAMP NOT NULL
);

CREATE INDEX idx_device_codes_expires_at ON device_codes(expires_at);
