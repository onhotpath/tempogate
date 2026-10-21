package keys

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
)

// ErrNoVerificationKeys is returned by Verify when the backing *Keys exposes
// no public keys to verify against.
var ErrNoVerificationKeys = errors.New("keys: verifier has no keys to verify against")

// ErrTokenRevoked is returned by Verify when the configured denylist reports
// the token's jti as revoked. Verifier callers (refresh exchange, /userinfo)
// map this to the same 401 they emit for any other invalid token; the
// distinct sentinel exists so future audit paths can log revocations apart
// from signature/expiry failures.
var ErrTokenRevoked = errors.New("keys: token has been revoked")

// ErrNotAccessToken is returned by Verify for a validly signed token that is
// not an access token (an ID token, or a token minted before access tokens
// were typed). Callers map it to the same 401 as any other invalid token.
var ErrNotAccessToken = errors.New("keys: token is not an access token")

// Verifier validates tempogate-issued access tokens for tempogate's own
// resource-server needs (/userinfo). It accepts access tokens only: ID tokens
// are signed by the same keys but are for relying-party login, never a
// credential. Temporal's gRPC frontend does not use this - it
// runs its own JWKS-backed verifier against /.well-known/jwks.json. Verifier
// exists so the parts of tempogate that consume their own tokens don't
// re-implement signature + claim checks inconsistently with the Signer.
//
// When a DenylistChecker is configured via WithDenylist, Verify rejects a
// signature-and-claims-valid token whose jti has been revoked. Temporal's
// frontend has no equivalent hook, so a revoked integration key keeps
// authorizing Temporal gRPC calls until its exp fires or its signing key is
// retired past grace; tempogate-mediated flows (refresh, /userinfo) honor the
// denylist within the cache's TTL.
type Verifier struct {
	keys     *Keys
	issuer   string
	audience string
	now      func() time.Time
	denylist DenylistChecker
}

func NewVerifier(opts ...TokenOption) *Verifier {
	c := newTokenConfig(opts...)
	return &Verifier{
		keys:     c.keys,
		issuer:   c.issuer,
		audience: c.audience,
		now:      c.now,
		denylist: c.denylist,
	}
}

// Verify checks the signature against every published public key (kid-matched,
// so a token minted before a --force rotation still verifies until its key's
// retirement grace elapses, the same moment the kid leaves JWKS) and enforces
// the temporal claims plus the configured iss/aud. It returns the parsed token
// so callers can read sub/permissions/jti.
//
// When a DenylistChecker is wired, the parsed token's jti is also consulted
// against it: a revoked jti yields ErrTokenRevoked. A jti-less token (older
// or hand-crafted) skips the check — the project mints UUIDv7 jti on every
// token, so absence is treated as a non-tempogate token rather than as an
// implicit revoke.
//
// ctx mirrors Signer.Mint for symmetry; verification is synchronous against
// the in-memory key cache.
func (v *Verifier) Verify(ctx context.Context, raw string) (jwt.Token, error) {
	if v.keys == nil {
		return nil, ErrNoVerificationKeys
	}

	set := jwk.NewSet()
	for _, kp := range v.keys.Published() {
		pub, err := jwk.ParseKey(kp.PublicPEM, jwk.WithX509(true))
		if err != nil {
			return nil, fmt.Errorf("keys: parse public key (kid=%s): %w", kp.Kid, err)
		}
		if err := pub.Set(jwk.KeyIDKey, kp.Kid); err != nil {
			return nil, fmt.Errorf("keys: set kid: %w", err)
		}
		if err := pub.Set(jwk.AlgorithmKey, jwa.RS256()); err != nil {
			return nil, fmt.Errorf("keys: set alg: %w", err)
		}
		if err := set.AddKey(pub); err != nil {
			return nil, fmt.Errorf("keys: add key to set (kid=%s): %w", kp.Kid, err)
		}
	}
	if set.Len() == 0 {
		return nil, ErrNoVerificationKeys
	}

	parseOpts := []jwt.ParseOption{
		jwt.WithKeySet(set),
		jwt.WithClock(jwt.ClockFunc(v.now)),
	}
	if v.issuer != "" {
		parseOpts = append(parseOpts, jwt.WithIssuer(v.issuer))
	}
	if v.audience != "" {
		parseOpts = append(parseOpts, jwt.WithAudience(v.audience))
	}

	tok, err := jwt.Parse([]byte(raw), parseOpts...)
	if err != nil {
		return nil, fmt.Errorf("keys: verify token: %w", err)
	}
	// The signature is verified, so the protected header is trustworthy.
	msg, err := jws.Parse([]byte(raw))
	if err != nil {
		return nil, fmt.Errorf("keys: parse token header: %w", err)
	}
	if typ, _ := msg.Signatures()[0].ProtectedHeaders().Type(); typ != AccessTokenType {
		return nil, ErrNotAccessToken
	}

	if v.denylist != nil {
		if jti, ok := tok.JwtID(); ok && jti != "" {
			revoked, err := v.denylist.IsRevoked(ctx, jti)
			if err != nil {
				return nil, fmt.Errorf("keys: check denylist: %w", err)
			}
			if revoked {
				return nil, ErrTokenRevoked
			}
		}
	}
	return tok, nil
}
