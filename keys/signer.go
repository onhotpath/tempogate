package keys

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
)

// ErrNoSigningKeys is returned by Mint when the backing *Keys has no keypair
// loaded (Init/Generate was never called, or the store is empty).
var ErrNoSigningKeys = errors.New("keys: signer has no keypair to sign with")

// permissionsClaim is Temporal's default JWT ClaimMapper contract: a flat
// []string of "<namespace>:<action>" (plus "system:<role>") entries. emailClaim
// is the OIDC-standard end-user identifier; tempogate carries it for human
// tokens so downstream audit can attribute actions without a second lookup.
// nonceClaim is the OIDC Core §2 binding: when a relying party sends `nonce`
// at /authorize the provider MUST echo it into the ID token so the RP can
// detect token replay/injection. clientIDClaim names the OAuth client an
// access token was issued to (RFC 9068 §2.2).
const (
	permissionsClaim   = "permissions"
	emailClaim         = "email"
	emailVerifiedClaim = "email_verified"
	nonceClaim         = "nonce"
	authTimeClaim      = "auth_time"
	clientIDClaim      = "client_id"
)

// AccessTokenType is the JWS typ header of every access token tempogate
// mints (RFC 9068 §2.1). Explicit typing (RFC 8725 §3.11) is what lets a
// resource server tell an access token from an ID token signed by the same
// key: the Verifier refuses anything else.
const AccessTokenType = "at+jwt"

// idTokenType is the typ an ID token carries: the plain JWT media type OIDC
// relying parties expect.
const idTokenType = "JWT"

// tokenConfig is the shared construction state for Signer and Verifier: both
// agree on the issuer/audience pair and read keypairs from the same *Keys, so
// a single functional-option set keeps the two halves from drifting. The
// denylist field is verifier-only — Signer ignores it — but lives here so
// WithDenylist composes with the other TokenOptions at one call site.
type tokenConfig struct {
	keys     *Keys
	issuer   string
	audience string
	now      func() time.Time
	denylist DenylistChecker
}

// TokenOption configures a Signer or a Verifier. It is distinct from the
// package-level Option (which configures the *Keys aggregate) so the two
// option spaces don't collide.
type TokenOption func(*tokenConfig)

// WithKeys supplies the keypair aggregate. The Signer signs with Latest(); the
// Verifier matches the token's kid against every public key the aggregate holds
// so verification survives a --force rotation.
func WithKeys(k *Keys) TokenOption {
	return func(c *tokenConfig) { c.keys = k }
}

// WithIssuer sets the iss claim the Signer stamps and the Verifier enforces.
// Empty issuer ⇒ the claim is neither written nor checked.
func WithIssuer(url string) TokenOption {
	return func(c *tokenConfig) { c.issuer = url }
}

// WithAudience sets the aud claim the Signer stamps on access tokens and the
// Verifier enforces: the Temporal audience (OIDC_ACCESS_TOKEN_AUDIENCE).
// Empty audience ⇒ the claim is neither written nor checked. ID tokens are
// unaffected; their aud is always the requesting client.
func WithAudience(aud string) TokenOption {
	return func(c *tokenConfig) { c.audience = aud }
}

// WithTokenClock swaps the clock used to stamp iat/nbf/exp (Signer) and to
// evaluate temporal claims (Verifier). Intended for tests.
//
// This is deliberately not named WithClock: the package already exports
// WithClock for the *Keys keypair-stamping clock, which is a different concern
// (when a keypair was created vs. when a token was issued).
func WithTokenClock(now func() time.Time) TokenOption {
	return func(c *tokenConfig) { c.now = now }
}

// WithDenylist plugs a jti-revocation check into the Verifier hot path. A
// signature-and-claims-valid token whose jti the checker reports as revoked
// is rejected with ErrTokenRevoked. The option is a no-op for Signer; pass
// the cache returned by NewDenylistCache rather than a raw store so the
// hot-path lookup is amortized across the cache TTL.
func WithDenylist(d DenylistChecker) TokenOption {
	return func(c *tokenConfig) { c.denylist = d }
}

func newTokenConfig(opts ...TokenOption) tokenConfig {
	c := tokenConfig{now: func() time.Time { return time.Now().UTC() }}
	for _, o := range opts {
		o(&c)
	}
	return c
}

// Signer mints tempogate-issued JWTs: access tokens (Mint), the shared
// primitive behind human token exchange, the CLI tokens and admin integration
// keys, whose claim shape is uniform so Temporal's default ClaimMapper sees
// the same token regardless of which flow produced it; and OIDC ID tokens
// (MintIDToken) for relying-party login.
type Signer struct {
	keys     *Keys
	issuer   string
	audience string
	now      func() time.Time

	// parsed memoizes the last signing key in its raw form. Parsing a
	// 4096-bit PEM on every mint is pure CPU waste, and so is handing jwx a
	// jwk.Key, which it re-exports to a fresh, un-precomputed *rsa.PrivateKey
	// on every sign. A kid names immutable key material (it is the key's
	// thumbprint), so a kid match is always a valid hit; Keys.Latest is
	// still asked on every mint, so rotation, retirement and publish-delay
	// activation take effect on the next mint.
	parsed atomic.Pointer[signingKey]
}

type signingKey struct {
	kid string
	key any
}

func NewSigner(opts ...TokenOption) *Signer {
	c := newTokenConfig(opts...)
	return &Signer{
		keys:     c.keys,
		issuer:   c.issuer,
		audience: c.audience,
		now:      c.now,
	}
}

// MintRequest is the per-token input for an access token. Permissions must
// already be in Temporal's "<namespace>:<action>" form (the caller owns that
// mapping). A zero TTL mints a token with no exp claim; every production
// caller sets one, because Temporal honours only exp and JWKS, never
// tempogate's revocation list.
type MintRequest struct {
	Subject     string
	Permissions []string
	TTL         time.Duration
	Email       string

	// ClientID, when non-empty, names the OAuth client the token was issued
	// to. Tokens minted through /token carry it; integration keys have no
	// client and omit it.
	ClientID string
}

// IDTokenRequest is the input for an OIDC ID token (OIDC Core §2). It
// carries identity only: an ID token is the relying party's proof of login,
// never a credential for Temporal, so it has no permissions.
type IDTokenRequest struct {
	Subject string
	Email   string

	// Audience is the requesting client_id. Required: OIDC Core §2 makes
	// the client the ID token's audience.
	Audience string

	// Nonce, when non-empty, is echoed into the `nonce` claim. OIDC Core §2
	// requires this whenever the relying party sent a nonce at /authorize;
	// the RP rejects an ID token whose nonce does not match.
	Nonce string

	// AuthTime is when the user authenticated upstream (auth_time).
	AuthTime time.Time

	TTL time.Duration
}

// Mint builds, signs, and serializes an access token for req. It returns the
// compact serialization and the token's jti (a UUIDv7, so jti ordering
// tracks issue time) for callers that persist a token registry or
// refresh-token mapping.
//
// ctx is accepted for signature stability with the future key-fetch path; the
// current in-memory keypair cache makes signing synchronous.
func (s *Signer) Mint(_ context.Context, req MintRequest) (string, string, error) {
	b, jti, err := s.builder(req.Subject, req.TTL)
	if err != nil {
		return "", "", err
	}
	b.Claim(permissionsClaim, req.Permissions)
	if s.audience != "" {
		b.Audience([]string{s.audience})
	}
	if req.Email != "" {
		b.Claim(emailClaim, req.Email)
	}
	if req.ClientID != "" {
		b.Claim(clientIDClaim, req.ClientID)
	}
	signed, err := s.sign(b, AccessTokenType)
	if err != nil {
		return "", "", err
	}
	return signed, jti, nil
}

// MintIDToken builds, signs, and serializes an OIDC ID token for req. Only
// tempogate-verified identities reach this point (Google asserted
// email_verified and the domain gate passed), so email_verified is always
// true.
func (s *Signer) MintIDToken(_ context.Context, req IDTokenRequest) (string, error) {
	if req.Audience == "" {
		return "", errors.New("keys: an ID token needs the client as its audience")
	}
	b, _, err := s.builder(req.Subject, req.TTL)
	if err != nil {
		return "", err
	}
	b.Audience([]string{req.Audience})
	if req.Email != "" {
		b.Claim(emailClaim, req.Email).Claim(emailVerifiedClaim, true)
	}
	if req.Nonce != "" {
		b.Claim(nonceClaim, req.Nonce)
	}
	if !req.AuthTime.IsZero() {
		b.Claim(authTimeClaim, req.AuthTime.Unix())
	}
	return s.sign(b, idTokenType)
}

// builder starts a token with the claims every tempogate JWT shares: sub,
// iss, iat, nbf, jti, and exp when ttl is positive.
func (s *Signer) builder(subject string, ttl time.Duration) (*jwt.Builder, string, error) {
	if s.keys == nil {
		return nil, "", ErrNoSigningKeys
	}
	id, err := uuid.NewV7()
	if err != nil {
		return nil, "", fmt.Errorf("keys: generate jti: %w", err)
	}
	jti := id.String()

	now := s.now()
	b := jwt.NewBuilder().
		Subject(subject).
		IssuedAt(now).
		NotBefore(now).
		JwtID(jti)
	if s.issuer != "" {
		b.Issuer(s.issuer)
	}
	if ttl > 0 {
		b.Expiration(now.Add(ttl))
	}
	return b, jti, nil
}

// sign signs b with the latest keypair, stamping kid and typ in the JWS
// protected header. Both Mint and MintIDToken go through here, so both use
// the cached parsed key.
func (s *Signer) sign(b *jwt.Builder, typ string) (string, error) {
	kp, err := s.keys.Latest()
	if err != nil {
		return "", err
	}

	privKey, err := s.signingKey(kp)
	if err != nil {
		return "", err
	}

	tok, err := b.Build()
	if err != nil {
		return "", fmt.Errorf("keys: build token: %w", err)
	}

	// The kid in the JWS protected header is what lets relying parties pick
	// the right JWKS entry.
	hdr := jws.NewHeaders()
	if err := hdr.Set(jws.KeyIDKey, kp.Kid); err != nil {
		return "", fmt.Errorf("keys: set kid: %w", err)
	}
	if err := hdr.Set(jws.TypeKey, typ); err != nil {
		return "", fmt.Errorf("keys: set typ: %w", err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), privKey, jws.WithProtectedHeaders(hdr)))
	if err != nil {
		return "", fmt.Errorf("keys: sign token: %w", err)
	}
	return string(signed), nil
}

// signingKey returns kp's private key parsed to its raw form, from cache when
// kp is the keypair the previous mint used. Only one entry is kept: just one
// keypair signs at a time, so a rotation costs a single re-parse.
func (s *Signer) signingKey(kp Keypair) (any, error) {
	if c := s.parsed.Load(); c != nil && c.kid == kp.Kid {
		return c.key, nil
	}
	parsed, err := jwk.ParseKey(kp.PrivatePEM, jwk.WithX509(true))
	if err != nil {
		return nil, fmt.Errorf("keys: parse private key (kid=%s): %w", kp.Kid, err)
	}
	raw, err := jwk.Export[any](parsed)
	if err != nil {
		return nil, fmt.Errorf("keys: export private key (kid=%s): %w", kp.Kid, err)
	}
	if priv, ok := raw.(*rsa.PrivateKey); ok {
		// Precompute before publishing the key to other goroutines: it
		// mutates the key, and without it crypto/rsa rebuilds the CRT
		// values on every signature.
		priv.Precompute()
	}
	s.parsed.Store(&signingKey{kid: kp.Kid, key: raw})
	return raw, nil
}
