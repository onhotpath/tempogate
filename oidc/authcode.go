package oidc

import (
	"context"
	"errors"
	"time"
)

// ErrAuthRequestNotFound is returned by ConsumeAuthRequest when no pending
// request matches the given internal state — because the state was never
// issued, has already been consumed (single-use), or its row was reaped.
// The callback maps this to a 400 without distinguishing the cases, so a
// replayed state is indistinguishable from a forged one to the caller.
var ErrAuthRequestNotFound = errors.New("oidc: auth request not found")

// ErrAuthCodeNotFound is returned by ConsumeAuthCode when no code matches —
// because it was never issued, has already been redeemed (single-use), or
// its row was reaped. The /token handler maps this to OAuth2 invalid_grant
// without distinguishing the cases, so a replayed code is indistinguishable
// from a forged one to the caller.
var ErrAuthCodeNotFound = errors.New("oidc: auth code not found")

// ErrAuthCodeReused is returned by ConsumeAuthCode when the code was already
// redeemed. Together with it the store returns the consumed code, whose
// FamilyID names the refresh-token family the first redemption started, so
// the /token handler can revoke the tokens issued from it (RFC 6749 §4.1.2).
var ErrAuthCodeReused = errors.New("oidc: auth code already redeemed")

// AuthCode is the authorization code tempogate mints after Google has
// authenticated the user and the email passed the domain allowlist. It is
// single-use and short-lived: the downstream /token call exchanges it —
// together with the PKCE verifier matching CodeChallenge — for a signed JWT.
// Email is the verified upstream identity flat authz keys off in v1.
type AuthCode struct {
	Code                string
	ClientID            string
	RedirectURI         string
	Email               string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string

	// Nonce is carried from the AuthRequest so /token can stamp it into the
	// ID token's nonce claim (OIDC Core §2). Empty when the client sent no
	// nonce at /authorize.
	Nonce string

	// FamilyID is the refresh-token family the code's redemption started,
	// recorded atomically with the consume. Empty until redeemed.
	FamilyID string

	CreatedAt time.Time
	ExpiresAt time.Time
}

// CallbackStore is the consumer-side state interface for the /callback/google
// handler (see state/doc.go). It is distinct from AuthRequestStore — the
// authorize side only writes pending requests; the callback side consumes one
// (single-use) and persists the minted code. The concrete sqlite.Store
// satisfies it structurally; the type is exported only so the composition
// root can inject it via fx.As.
type CallbackStore interface {
	// ConsumeAuthRequest atomically loads and deletes the pending request
	// keyed by internalState, enforcing single use. It returns
	// ErrAuthRequestNotFound when no row matches. Expiry is the caller's
	// concern (it owns the clock); a consumed-but-expired request is still
	// returned and then rejected by the handler.
	ConsumeAuthRequest(ctx context.Context, internalState string) (AuthRequest, error)

	// SaveAuthCode persists a freshly minted authorization code.
	SaveAuthCode(ctx context.Context, ac AuthCode) error
}
