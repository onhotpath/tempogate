package keys

import (
	"context"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/suite"
)

type SignerSuite struct {
	suite.Suite

	ctx    context.Context
	store  *fakeKeyStore
	keys   *Keys
	now    time.Time
	signer *Signer
}

func TestSignerSuite(t *testing.T) {
	suite.Run(t, new(SignerSuite))
}

func (s *SignerSuite) SetupTest() {
	s.ctx = context.Background()
	s.store = &fakeKeyStore{}
	// Clearly-past so a verifier running at wall-clock time never trips nbf.
	s.now = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	s.keys = New(WithStore(s.store), WithClock(s.kpClock()), withFastRSA())
	s.Require().NoError(s.keys.Init(s.ctx))

	s.signer = NewSigner(
		WithKeys(s.keys),
		WithIssuer("https://tempogate.test"),
		WithAudience("temporal"),
		WithTokenClock(s.tokenClock()),
	)
}

// kpClock advances per call so rotated keypairs get distinct CreatedAt.
func (s *SignerSuite) kpClock() func() time.Time {
	tick := 0
	return func() time.Time {
		t := s.now.Add(time.Duration(tick) * time.Second)
		tick++
		return t
	}
}

// tokenClock is fixed: token timestamps must be deterministic for assertions.
func (s *SignerSuite) tokenClock() func() time.Time {
	return func() time.Time { return s.now }
}

func (s *SignerSuite) req() MintRequest {
	return MintRequest{
		Subject:     "user:operator",
		Permissions: []string{"default:read", "system:admin"},
		TTL:         time.Hour,
		Email:       "operator@example.test",
	}
}

func (s *SignerSuite) parseWithLatestPublicKey(signed string) jwt.Token {
	kp, err := s.keys.Latest()
	s.Require().NoError(err)
	pub, err := jwk.ParseKey(kp.PublicPEM, jwk.WithX509(true))
	s.Require().NoError(err)

	tok, err := jwt.Parse([]byte(signed),
		jwt.WithKey(jwa.RS256(), pub),
		jwt.WithClock(jwt.ClockFunc(func() time.Time { return s.now.Add(time.Minute) })),
	)
	s.Require().NoError(err)
	return tok
}

func (s *SignerSuite) toStrings(v any) []string {
	raw, ok := v.([]any)
	s.Require().True(ok, "permissions claim should decode to []any, got %T", v)
	out := make([]string, len(raw))
	for i, e := range raw {
		str, ok := e.(string)
		s.Require().True(ok)
		out[i] = str
	}
	return out
}

func (s *SignerSuite) TestMintStampsKidHeader() {
	signed, _, err := s.signer.Mint(s.ctx, s.req())
	s.Require().NoError(err)

	msg, err := jws.Parse([]byte(signed))
	s.Require().NoError(err)
	s.Require().Len(msg.Signatures(), 1)

	kid, ok := msg.Signatures()[0].ProtectedHeaders().KeyID()
	s.Require().True(ok, "kid header must be present")

	latest, err := s.keys.Latest()
	s.Require().NoError(err)
	s.Equal(latest.Kid, kid)
}

func (s *SignerSuite) TestMintClaimsRoundTrip() {
	signed, jti, err := s.signer.Mint(s.ctx, s.req())
	s.Require().NoError(err)
	s.Require().NotEmpty(jti)

	tok := s.parseWithLatestPublicKey(signed)

	iss, ok := tok.Issuer()
	s.Require().True(ok)
	s.Equal("https://tempogate.test", iss)

	aud, ok := tok.Audience()
	s.Require().True(ok)
	s.Equal([]string{"temporal"}, aud)

	sub, ok := tok.Subject()
	s.Require().True(ok)
	s.Equal("user:operator", sub)

	iat, ok := tok.IssuedAt()
	s.Require().True(ok)
	s.True(iat.Equal(s.now), "iat should be the signer clock instant")

	nbf, ok := tok.NotBefore()
	s.Require().True(ok)
	s.True(nbf.Equal(s.now))

	exp, ok := tok.Expiration()
	s.Require().True(ok)
	s.True(exp.Equal(s.now.Add(time.Hour)))

	gotJTI, ok := tok.JwtID()
	s.Require().True(ok)
	s.Equal(jti, gotJTI, "returned jti must match the jti claim")

	perms, ok := tok.Field("permissions")
	s.Require().True(ok)
	s.Equal([]string{"default:read", "system:admin"}, s.toStrings(perms))

	email, err := jwt.Get[string](tok, "email")
	s.Require().NoError(err)
	s.Equal("operator@example.test", email)
}

func (s *SignerSuite) TestJTIIsUUIDv7AndUnique() {
	_, jti1, err := s.signer.Mint(s.ctx, s.req())
	s.Require().NoError(err)
	_, jti2, err := s.signer.Mint(s.ctx, s.req())
	s.Require().NoError(err)

	s.NotEqual(jti1, jti2)
	// UUIDv7: version nibble is '7' at index 14 of the canonical string.
	s.Require().Len(jti1, 36)
	s.Equal(byte('7'), jti1[14])
}

func (s *SignerSuite) TestMintZeroTTLOmitsExp() {
	r := s.req()
	r.TTL = 0
	signed, _, err := s.signer.Mint(s.ctx, r)
	s.Require().NoError(err)

	tok := s.parseWithLatestPublicKey(signed)

	s.False(tok.Has("exp"), "zero TTL must not stamp an exp claim")
	_, ok := tok.Expiration()
	s.False(ok)
}

func (s *SignerSuite) TestMintOmitsEmailWhenEmpty() {
	r := s.req()
	r.Email = ""
	signed, _, err := s.signer.Mint(s.ctx, r)
	s.Require().NoError(err)

	tok := s.parseWithLatestPublicKey(signed)
	s.False(tok.Has("email"))
}

// TestMintStampsIDPOnlyForPeople: a person's tokens name the connector they
// signed in through; an integration key is not an identity provider and
// carries none.
func (s *SignerSuite) TestMintStampsIDPOnlyForPeople() {
	r := s.req()
	r.IDP = "google"
	signed, _, err := s.signer.Mint(s.ctx, r)
	s.Require().NoError(err)
	idp, err := jwt.Get[string](s.parseWithLatestPublicKey(signed), "idp")
	s.Require().NoError(err)
	s.Equal("google", idp)

	signed, _, err = s.signer.Mint(s.ctx, s.req())
	s.Require().NoError(err)
	s.False(s.parseWithLatestPublicKey(signed).Has("idp"))
}

// TestMintIsAnAccessToken: Mint produces access tokens only. They are
// explicitly typed (RFC 9068 §2.1, RFC 8725 §3.11) so no verifier can mistake
// one for an ID token or vice versa, carry the Signer's audience (the Temporal
// audience), and name the client they were issued to when there is one.
func (s *SignerSuite) TestMintIsAnAccessToken() {
	r := s.req()
	r.ClientID = "tempogate-cli"
	signed, _, err := s.signer.Mint(s.ctx, r)
	s.Require().NoError(err)

	s.Equal(AccessTokenType, s.typ(signed))
	tok := s.parseWithLatestPublicKey(signed)
	aud, ok := tok.Audience()
	s.Require().True(ok)
	s.Equal([]string{"temporal"}, aud)
	clientID, err := jwt.Get[string](tok, "client_id")
	s.Require().NoError(err)
	s.Equal("tempogate-cli", clientID)
	s.False(tok.Has("nonce"), "an access token never carries the OIDC nonce")

	// Integration keys have no client: the claim is omitted, not empty.
	signed, _, err = s.signer.Mint(s.ctx, s.req())
	s.Require().NoError(err)
	s.False(s.parseWithLatestPublicKey(signed).Has("client_id"))
}

// TestMintIDTokenCarriesIdentityOnly: the ID token is for the relying party's
// login and nothing else. Its aud is the client (OIDC Core §2), it carries
// the identity claims, and it has no permissions, so Temporal's default
// ClaimMapper grants it nothing if it is presented as a bearer.
func (s *SignerSuite) TestMintIDTokenCarriesIdentityOnly() {
	authTime := s.now.Add(-time.Minute)
	signed, err := s.signer.MintIDToken(s.ctx, IDTokenRequest{
		Subject:  "alice@example.com",
		Email:    "alice@example.com",
		IDP:      "google",
		Audience: "temporal-ui",
		Nonce:    "rp-nonce",
		AuthTime: authTime,
		TTL:      5 * time.Minute,
	})
	s.Require().NoError(err)

	s.Equal("JWT", s.typ(signed))
	tok := s.parseWithLatestPublicKey(signed)
	iss, _ := tok.Issuer()
	s.Equal("https://tempogate.test", iss)
	aud, _ := tok.Audience()
	s.Equal([]string{"temporal-ui"}, aud, "the ID token's aud is the client, never the Signer's audience")
	sub, _ := tok.Subject()
	s.Equal("alice@example.com", sub)
	exp, _ := tok.Expiration()
	s.Equal(s.now.Add(5*time.Minute), exp)
	s.False(tok.Has("permissions"), "an ID token must grant nothing")
	s.False(tok.Has("client_id"))

	email, err := jwt.Get[string](tok, "email")
	s.Require().NoError(err)
	s.Equal("alice@example.com", email)
	verified, err := jwt.Get[bool](tok, "email_verified")
	s.Require().NoError(err)
	s.True(verified)
	nonce, err := jwt.Get[string](tok, "nonce")
	s.Require().NoError(err)
	s.Equal("rp-nonce", nonce)
	idp, err := jwt.Get[string](tok, "idp")
	s.Require().NoError(err)
	s.Equal("google", idp)
	at, err := jwt.Get[float64](tok, "auth_time")
	s.Require().NoError(err)
	s.Equal(float64(authTime.Unix()), at)

	// No nonce requested (the refresh path): none echoed.
	signed, err = s.signer.MintIDToken(s.ctx, IDTokenRequest{
		Subject: "alice@example.com", Audience: "temporal-ui", AuthTime: authTime, TTL: time.Hour,
	})
	s.Require().NoError(err)
	s.False(s.parseWithLatestPublicKey(signed).Has("nonce"))
	s.False(s.parseWithLatestPublicKey(signed).Has("idp"))
}

func (s *SignerSuite) TestMintIDTokenRequiresAudience() {
	_, err := s.signer.MintIDToken(s.ctx, IDTokenRequest{Subject: "alice@example.com", TTL: time.Minute})
	s.Require().Error(err)
}

func (s *SignerSuite) TestMintIDTokenWithoutKeysReturnsError() {
	_, err := NewSigner().MintIDToken(s.ctx, IDTokenRequest{Subject: "a", Audience: "c", TTL: time.Minute})
	s.Require().ErrorIs(err, ErrNoSigningKeys)
}

// TestVerifierAcceptsAccessTokensOnly: the Verifier serves resource-server
// checks (/userinfo), so a validly signed ID token is still refused.
func (s *SignerSuite) TestVerifierAcceptsAccessTokensOnly() {
	idToken, err := s.signer.MintIDToken(s.ctx, IDTokenRequest{
		Subject: "alice@example.com", Audience: "temporal", TTL: time.Hour,
	})
	s.Require().NoError(err)

	v := NewVerifier(
		WithKeys(s.keys),
		WithIssuer("https://tempogate.test"),
		WithAudience("temporal"),
		WithTokenClock(func() time.Time { return s.now.Add(time.Minute) }),
	)
	_, err = v.Verify(s.ctx, idToken)
	s.Require().ErrorIs(err, ErrNotAccessToken, "aud matches, but an ID token is not an access token")
}

// typ reads the JWS protected header's typ.
func (s *SignerSuite) typ(signed string) string {
	msg, err := jws.Parse([]byte(signed))
	s.Require().NoError(err)
	typ, _ := msg.Signatures()[0].ProtectedHeaders().Type()
	return typ
}

func (s *SignerSuite) TestMintWithoutKeysReturnsError() {
	_, _, err := NewSigner().Mint(s.ctx, s.req())
	s.Require().ErrorIs(err, ErrNoSigningKeys)
}

func (s *SignerSuite) TestMintBeforeInitReturnsErrNoKeypair() {
	uninit := New(WithStore(&fakeKeyStore{}))
	signer := NewSigner(WithKeys(uninit), WithTokenClock(s.tokenClock()))
	_, _, err := signer.Mint(s.ctx, s.req())
	s.Require().ErrorIs(err, ErrNoKeypair)
}

func (s *SignerSuite) TestVerifierRoundTrip() {
	signed, jti, err := s.signer.Mint(s.ctx, s.req())
	s.Require().NoError(err)

	v := NewVerifier(
		WithKeys(s.keys),
		WithIssuer("https://tempogate.test"),
		WithAudience("temporal"),
		WithTokenClock(func() time.Time { return s.now.Add(time.Minute) }),
	)
	tok, err := v.Verify(s.ctx, signed)
	s.Require().NoError(err)

	sub, ok := tok.Subject()
	s.Require().True(ok)
	s.Equal("user:operator", sub)

	gotJTI, ok := tok.JwtID()
	s.Require().True(ok)
	s.Equal(jti, gotJTI)
}

func (s *SignerSuite) TestVerifierRejectsWrongIssuer() {
	signed, _, err := s.signer.Mint(s.ctx, s.req())
	s.Require().NoError(err)

	v := NewVerifier(
		WithKeys(s.keys),
		WithIssuer("https://attacker.test"),
		WithTokenClock(func() time.Time { return s.now.Add(time.Minute) }),
	)
	_, err = v.Verify(s.ctx, signed)
	s.Require().Error(err)
}

func (s *SignerSuite) TestVerifierRejectsExpiredToken() {
	r := s.req()
	r.TTL = time.Minute
	signed, _, err := s.signer.Mint(s.ctx, r)
	s.Require().NoError(err)

	v := NewVerifier(
		WithKeys(s.keys),
		WithIssuer("https://tempogate.test"),
		WithTokenClock(func() time.Time { return s.now.Add(time.Hour) }),
	)
	_, err = v.Verify(s.ctx, signed)
	s.Require().Error(err)
}

func (s *SignerSuite) TestVerifierRejectsTamperedToken() {
	signed, _, err := s.signer.Mint(s.ctx, s.req())
	s.Require().NoError(err)

	v := NewVerifier(
		WithKeys(s.keys),
		WithIssuer("https://tempogate.test"),
		WithTokenClock(func() time.Time { return s.now.Add(time.Minute) }),
	)
	_, err = v.Verify(s.ctx, signed+"tampered")
	s.Require().Error(err)
}

// TestVerifierVerifiesAcrossRotation proves the kid-matched key set keeps a
// token minted before a --force rotation verifiable while its key is retained.
func (s *SignerSuite) TestVerifierVerifiesAcrossRotation() {
	signed, _, err := s.signer.Mint(s.ctx, s.req())
	s.Require().NoError(err)
	oldKid, err := s.keys.Latest()
	s.Require().NoError(err)

	rotated, err := s.keys.Generate(s.ctx, true)
	s.Require().NoError(err)
	s.Require().NotEqual(oldKid.Kid, rotated.Kid)

	v := NewVerifier(
		WithKeys(s.keys),
		WithIssuer("https://tempogate.test"),
		WithAudience("temporal"),
		WithTokenClock(func() time.Time { return s.now.Add(time.Minute) }),
	)
	tok, err := v.Verify(s.ctx, signed)
	s.Require().NoError(err)
	sub, ok := tok.Subject()
	s.Require().True(ok)
	s.Equal("user:operator", sub)
}

func (s *SignerSuite) TestVerifierWithoutKeysReturnsError() {
	_, err := NewVerifier().Verify(s.ctx, "x.y.z")
	s.Require().ErrorIs(err, ErrNoVerificationKeys)
}

// keysWith returns an initialised *Keys whose store is preloaded with kp.
// Init loads (and does not validate) the keypair, so callers can inject a
// deliberately malformed PEM to exercise the parse-error paths.
func (s *SignerSuite) keysWith(kp Keypair) *Keys {
	store := &fakeKeyStore{}
	s.Require().NoError(store.SaveKeypair(s.ctx, kp))
	k := New(WithStore(store))
	s.Require().NoError(k.Init(s.ctx))
	return k
}

// TestMintDefaultClockAndNoIssuerAudience exercises the default (unset) clock
// and the issuer/audience-omitted branches: a Signer with only WithKeys must
// stamp real-time iat and emit neither iss nor aud.
func (s *SignerSuite) TestMintDefaultClockAndNoIssuerAudience() {
	signer := NewSigner(WithKeys(s.keys))
	signed, _, err := signer.Mint(s.ctx, s.req())
	s.Require().NoError(err)

	kp, err := s.keys.Latest()
	s.Require().NoError(err)
	pub, err := jwk.ParseKey(kp.PublicPEM, jwk.WithX509(true))
	s.Require().NoError(err)
	tok, err := jwt.Parse([]byte(signed), jwt.WithKey(jwa.RS256(), pub))
	s.Require().NoError(err)

	_, ok := tok.Issuer()
	s.False(ok, "iss must be absent when issuer is unconfigured")
	_, ok = tok.Audience()
	s.False(ok, "aud must be absent when audience is unconfigured")

	iat, ok := tok.IssuedAt()
	s.Require().True(ok)
	s.WithinDuration(time.Now(), iat, 30*time.Second, "default clock should stamp real time")
}

func (s *SignerSuite) TestMintParsePrivateKeyError() {
	keys := s.keysWith(Keypair{
		Kid:        "bad-priv",
		Alg:        AlgRS256,
		PrivatePEM: []byte("-----BEGIN RSA PRIVATE KEY-----\nnot-a-key\n-----END RSA PRIVATE KEY-----"),
		PublicPEM:  []byte("ignored"),
		CreatedAt:  s.now,
	})
	signer := NewSigner(WithKeys(keys), WithTokenClock(s.tokenClock()))

	_, _, err := signer.Mint(s.ctx, s.req())
	s.Require().Error(err)
	s.Contains(err.Error(), "parse private key")
}

// TestMintSignError injects a keypair whose PrivatePEM is actually a valid RSA
// *public* key: parsing succeeds but RS256 signing with a public key fails,
// reaching the sign-error path.
func (s *SignerSuite) TestMintSignError() {
	helper, err := GenerateKeypair(WithRSABits(2048))
	s.Require().NoError(err)

	keys := s.keysWith(Keypair{
		Kid:        "pub-as-priv",
		Alg:        AlgRS256,
		PrivatePEM: helper.PublicPEM,
		PublicPEM:  helper.PublicPEM,
		CreatedAt:  s.now,
	})
	signer := NewSigner(WithKeys(keys), WithTokenClock(s.tokenClock()))

	_, _, err = signer.Mint(s.ctx, s.req())
	s.Require().Error(err)
	s.Contains(err.Error(), "sign token")
}

func (s *SignerSuite) TestVerifierParsePublicKeyError() {
	keys := s.keysWith(Keypair{
		Kid:        "bad-pub",
		Alg:        AlgRS256,
		PrivatePEM: []byte("ignored"),
		PublicPEM:  []byte("-----BEGIN PUBLIC KEY-----\nnot-a-key\n-----END PUBLIC KEY-----"),
		CreatedAt:  s.now,
	})
	v := NewVerifier(WithKeys(keys), WithTokenClock(s.tokenClock()))

	_, err := v.Verify(s.ctx, "x.y.z")
	s.Require().Error(err)
	s.Contains(err.Error(), "parse public key")
}

// TestVerifierNoLoadedKeys covers the empty-key-set guard: the aggregate is
// non-nil but was never initialised, so it holds no keys.
func (s *SignerSuite) TestVerifierNoLoadedKeys() {
	v := NewVerifier(WithKeys(New(WithStore(&fakeKeyStore{}))), WithTokenClock(s.tokenClock()))
	_, err := v.Verify(s.ctx, "x.y.z")
	s.Require().ErrorIs(err, ErrNoVerificationKeys)
}
