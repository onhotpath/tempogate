package keys

import (
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"go.uber.org/fx"

	"github.com/onhotpath/tempogate/redact"
)

type fxParams struct {
	fx.In

	Store           KeyStore
	Changes         ChangeFeed      `optional:"true"`
	Bootstrap       BootstrapLocker `optional:"true"`
	RetirementGrace time.Duration   `name:"keys_retirement_grace"`
	PublishDelay    time.Duration   `name:"keys_publish_delay"`

	EncryptionKey     string `name:"keys_encryption_key" optional:"true"`
	EncryptionKeyFile string `name:"keys_encryption_key_file" optional:"true"`

	Redaction *redact.Set `optional:"true"`
}

// newFx fails graph construction on a malformed KEK, or a negative grace or
// publish delay (rather than letting the options panic), so a typo is caught
// at startup and the operator sees which setting is wrong.
func newFx(p fxParams) (*Keys, error) {
	if p.RetirementGrace < 0 {
		return nil, fmt.Errorf("keys: KEYS_RETIREMENT_GRACE must not be negative, got %s", p.RetirementGrace)
	}
	if p.PublishDelay < 0 {
		return nil, fmt.Errorf("keys: KEYS_PUBLISH_DELAY must not be negative, got %s", p.PublishDelay)
	}
	kek, err := LoadEncryptionKey(p.EncryptionKey, p.EncryptionKeyFile)
	if kek != nil {
		// Every alphabet LoadEncryptionKey accepts.
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			p.Redaction.Declare(redact.Secret, enc.EncodeToString(kek))
		}
	}
	if err != nil {
		return nil, err
	}
	opts := []Option{
		WithStore(p.Store),
		WithRetirementGrace(p.RetirementGrace),
		WithPublishDelay(p.PublishDelay),
		WithChangeFeed(p.Changes),
		WithBootstrapLocker(p.Bootstrap),
	}
	if kek != nil {
		opts = append(opts, WithEncryptionKey(kek))
	}
	return New(opts...), nil
}

type signerParams struct {
	fx.In

	Keys *Keys

	Issuer              string `name:"oidc_issuer"`
	AccessTokenAudience string `name:"oidc_access_token_audience"`
}

// newSigner wires the JWT-minting Signer over the keypair aggregate. The
// issuer it stamps is the same value the OIDC discovery document advertises,
// so a relying party that fetched discovery sees a matching `iss`. Every
// access token, integration keys included, carries the Temporal audience, so
// a Temporal frontend configured to require it (global.authorization.audience,
// Temporal v1.29.0+) accepts them and refuses tokens minted for anything else.
func newSigner(p signerParams) (*Signer, error) {
	if p.AccessTokenAudience == "" {
		return nil, errEmptyAudience
	}
	return NewSigner(WithKeys(p.Keys), WithIssuer(p.Issuer), WithAudience(p.AccessTokenAudience)), nil
}

// errEmptyAudience stops startup rather than minting access tokens with no
// aud, which no audience check could then tell apart.
var errEmptyAudience = errors.New("keys: OIDC_ACCESS_TOKEN_AUDIENCE must not be empty")

type verifierParams struct {
	fx.In

	Keys     *Keys
	Denylist *DenylistCache

	Issuer              string `name:"oidc_issuer"`
	AccessTokenAudience string `name:"oidc_access_token_audience"`
}

// newVerifier wires the Verifier tempogate uses to validate its own access
// tokens (the /userinfo bearer check). Its issuer and audience must match
// newSigner's so a token this process mints verifies in the same process.
// The denylist cache is consulted on every verify so a revoked integration
// key stops authorizing tempogate-mediated flows within the cache's TTL.
func newVerifier(p verifierParams) (*Verifier, error) {
	if p.AccessTokenAudience == "" {
		return nil, errEmptyAudience
	}
	opts := []TokenOption{
		WithKeys(p.Keys),
		WithIssuer(p.Issuer),
		WithAudience(p.AccessTokenAudience),
	}
	if p.Denylist != nil {
		opts = append(opts, WithDenylist(p.Denylist))
	}
	return NewVerifier(opts...), nil
}

type denylistParams struct {
	fx.In

	Checker DenylistChecker
	Changes ChangeFeed `optional:"true"`
}

// newDenylistCache wraps the state store's DenylistChecker (provided by the
// STATE_DRIVER backend via fx.As) in the verifier-side read-through cache.
// DefaultDenylistTTL governs how stale a hot-path "active" answer can be;
// the store's change feed, when there is one, only shortens it (Follow).
func newDenylistCache(p denylistParams) *DenylistCache {
	return NewDenylistCache(WithDenylistChecker(p.Checker), WithDenylistChangeFeed(p.Changes))
}

// Fx wires *Keys plus the *Signer, *Verifier, and verifier-side
// *DenylistCache over it into the composition root. The KeyStore and
// DenylistChecker dependencies are both satisfied by the state store
// backend via fx.Annotate(..., fx.As(...)), as are the optional ChangeFeed
// and BootstrapLocker; oidc_issuer is contributed by config.
func Fx() fx.Option {
	return fx.Options(
		fx.Provide(newFx),
		fx.Provide(newSigner),
		fx.Provide(newDenylistCache),
		fx.Provide(newVerifier),
	)
}
