package oidc

import (
	"context"
	"errors"
	"time"
)

// ErrDeviceCodeNotFound is returned by a lookup or consume that finds no row
// — because the row was never written, was already consumed, or was reaped.
// The /token device_code grant maps this to OAuth2 invalid_grant; the
// verification page maps it to a 404 without distinguishing the cases so a
// caller cannot probe which user_codes are in use.
var ErrDeviceCodeNotFound = errors.New("oidc: device code not found")

// ErrDuplicateDeviceCode is returned by SaveDeviceCode when a row with the
// same device_code (PK) or user_code (UNIQUE) already exists. It is the
// consumer-side sentinel the /device_authorization handler matches via
// errors.Is so its regeneration loop is decoupled from the concrete store
// type; *sqlite.Store wraps this through its own typed sentinel.
var ErrDuplicateDeviceCode = errors.New("oidc: duplicate device code")

// ErrDeviceCodeNotPending is returned by Approve / Deny when the targeted
// row exists but is no longer in the pending state — its approved_at or
// denied_at is already stamped. The verification handler maps this to the
// same "already decided" response a second click on Approve or an Approve
// after Deny would produce, so the UI cannot be coaxed into flipping a
// decision by re-submitting the form.
var ErrDeviceCodeNotPending = errors.New("oidc: device code already approved or denied")

// DeviceCode is the per-flow row backing RFC 8628 — OAuth 2.0 Device
// Authorization Grant. It is created when a headless client posts to
// /device_authorization (§3.1), then transitions through pending → approved
// (or denied) as the user completes the verification flow on a second
// device, and is finally consumed by the polling /token call (§3.4) that
// mints the JWT.
//
// Code is the long, machine-side token the polling client presents; UserCode
// is the short, human-typeable token shown on the device and entered on the
// verification page (already normalised — uppercase, no dashes — so a lookup
// is a plain UNIQUE-index probe).
//
// Subject and Email are empty until Approve stamps the authenticated user onto
// the row;
// ApprovedAt and DeniedAt carry the pending → approved/denied transition,
// with both nil meaning "still awaiting user action". LastPolledAt and
// IntervalSeconds back the server-enforced slow_down rule (§3.5): a poll
// arriving sooner than IntervalSeconds since the last one returns slow_down
// and bumps the stored interval by +5.
type DeviceCode struct {
	Code            string
	UserCode        string
	ClientID        string
	Scope           string
	Subject         string
	Email           string
	ApprovedAt      *time.Time
	DeniedAt        *time.Time
	LastPolledAt    *time.Time
	IntervalSeconds int

	CreatedAt time.Time
	ExpiresAt time.Time
}

// DeviceCodeStore is the consumer-side state interface for the RFC 8628
// device-authorization grant (see state/doc.go). It carries every operation
// the three handler stages — /device_authorization (this PR),
// /token?grant_type=device_code, and the verification UI — need against the
// device_codes table; declaring them in one place keeps the contract
// discoverable without forcing each child handler to re-declare a near-
// duplicate narrow interface. The concrete *sqlite.Store satisfies it
// structurally; the type is exported only so the composition root can inject
// it via fx.As.
type DeviceCodeStore interface {
	// SaveDeviceCode persists a freshly minted device-flow row. A collision
	// on either device_code (PK) or user_code (UNIQUE) returns the store's
	// duplicate sentinel; the issuer's retry loop regenerates both halves
	// rather than picking a side, since user_code collisions are the only
	// realistic case (24^8 vs. device_code's 2^256) and the cost of
	// regenerating the device_code on the unlikely PK collision is zero.
	SaveDeviceCode(ctx context.Context, dc DeviceCode) error

	// LookupDeviceCodeByDeviceCode reads the row by its long machine-side
	// token (the poll path). Non-destructive. Returns ErrDeviceCodeNotFound
	// on zero rows.
	LookupDeviceCodeByDeviceCode(ctx context.Context, deviceCode string) (DeviceCode, error)

	// LookupDeviceCodeByUserCode reads the row by its short human-typeable
	// token (the verification-page path). Caller normalises (uppercase,
	// strip dashes) before calling; the column is stored already
	// normalised. Non-destructive. Returns ErrDeviceCodeNotFound on zero
	// rows. The result's Code may be empty: a store may keep only a hash of
	// the device code.
	LookupDeviceCodeByUserCode(ctx context.Context, userCode string) (DeviceCode, error)

	// PollDeviceCode records a /token poll and reports whether it arrived
	// inside the stored minimum interval since the previous one (RFC 8628
	// §3.5 slow_down), in which case the interval is also raised by 5
	// seconds. It must be atomic: of several concurrent polls inside one
	// interval at most one may report false. Returns ErrDeviceCodeNotFound
	// for an unknown device_code.
	PollDeviceCode(ctx context.Context, deviceCode string, now time.Time) (slowDown bool, err error)

	// ApproveDeviceCode atomically stamps the row as approved by id only
	// when it is still pending and not expired at now; otherwise
	// ErrDeviceCodeNotPending.
	ApproveDeviceCode(ctx context.Context, userCode string, id Identity, now time.Time) error

	// DenyDeviceCode atomically stamps the row as denied only when it is
	// still pending and not expired at now; otherwise ErrDeviceCodeNotPending.
	DenyDeviceCode(ctx context.Context, userCode string, now time.Time) error

	// ConsumeDeviceCode atomically deletes and returns the row, mirroring
	// ConsumeAuthCode: the loser of a concurrent poll sees zero rows and
	// gets ErrDeviceCodeNotFound. Called only on the final token-mint path,
	// after an Approve has stamped the row.
	ConsumeDeviceCode(ctx context.Context, deviceCode string) (DeviceCode, error)
}
