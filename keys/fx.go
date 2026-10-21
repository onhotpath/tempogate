package keys

import "go.uber.org/fx"

type fxParams struct {
	fx.In

	Store KeyStore

	EncryptionKey     string `name:"keys_encryption_key" optional:"true"`
	EncryptionKeyFile string `name:"keys_encryption_key_file" optional:"true"`
}

// newFx fails graph construction on a malformed KEK, so a typo is caught at
// startup rather than when the first key is written.
func newFx(p fxParams) (*Keys, error) {
	kek, err := LoadEncryptionKey(p.EncryptionKey, p.EncryptionKeyFile)
	if err != nil {
		return nil, err
	}
	opts := []Option{WithStore(p.Store)}
	if kek != nil {
		opts = append(opts, WithEncryptionKey(kek))
	}
	return New(opts...), nil
}

type signerParams struct {
	fx.In

	Keys *Keys

	Issuer string `name:"oidc_issuer"`
}

// newSigner wires the JWT-minting Signer over the keypair aggregate. The
// issuer it stamps is the same value the OIDC discovery document advertises,
// so a relying party that fetched discovery sees a matching `iss`. Audience
// is intentionally unset in v1: Temporal's default claim mapper does not
// enforce `aud`, and leaving it empty avoids minting a claim no verifier
// checks.
func newSigner(p signerParams) *Signer {
	return NewSigner(WithKeys(p.Keys), WithIssuer(p.Issuer))
}

type verifierParams struct {
	fx.In

	Keys     *Keys
	Denylist *DenylistCache

	Issuer string `name:"oidc_issuer"`
}

// newVerifier wires the Verifier tempogate uses to validate its own tokens
// (the /userinfo bearer check, refresh-token exchange). Its issuer must match
// newSigner's so a token this process mints verifies in the same process;
// audience is unset for the same reason it is on the Signer. The denylist
// cache is consulted on every verify so a revoked integration key stops
// authorizing tempogate-mediated flows within the cache's TTL.
func newVerifier(p verifierParams) *Verifier {
	return NewVerifier(
		WithKeys(p.Keys),
		WithIssuer(p.Issuer),
		WithDenylist(p.Denylist),
	)
}

type denylistParams struct {
	fx.In

	Checker DenylistChecker
}

// newDenylistCache wraps the sqlite-backed DenylistChecker (provided by
// state/sqlite via fx.As) in the verifier-side read-through cache.
// DefaultDenylistTTL governs how stale a hot-path "active" answer can be.
func newDenylistCache(p denylistParams) *DenylistCache {
	return NewDenylistCache(WithDenylistChecker(p.Checker))
}

// Fx wires *Keys plus the *Signer, *Verifier, and verifier-side
// *DenylistCache over it into the composition root. The KeyStore and
// DenylistChecker dependencies are both satisfied by state/sqlite via
// fx.Annotate(..., fx.As(...)); oidc_issuer is contributed by config.
func Fx() fx.Option {
	return fx.Options(
		fx.Provide(newFx),
		fx.Provide(newSigner),
		fx.Provide(newDenylistCache),
		fx.Provide(newVerifier),
	)
}
