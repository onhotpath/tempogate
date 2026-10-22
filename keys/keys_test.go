package keys

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/suite"
)

type KeysSuite struct {
	suite.Suite

	ctx   context.Context
	store *fakeKeyStore
	keys  *Keys
	now   time.Time
}

func TestKeysSuite(t *testing.T) {
	suite.Run(t, new(KeysSuite))
}

func (s *KeysSuite) SetupTest() {
	s.ctx = context.Background()
	s.store = &fakeKeyStore{}
	// Use a clearly-past timestamp so jwt.Parse's default iat/exp checks
	// don't reject tokens whose IssuedAt is "in the future" relative to
	// the wall clock when this suite is run on a machine slightly behind.
	s.now = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	s.keys = New(WithStore(s.store), WithClock(s.clock()))
}

// clock returns a monotonically advancing fake clock so generated keypairs
// have distinct CreatedAt values per call.
func (s *KeysSuite) clock() func() time.Time {
	tick := 0
	return func() time.Time {
		t := s.now.Add(time.Duration(tick) * time.Second)
		tick++
		return t
	}
}

func (s *KeysSuite) TestGenerateKeypairProducesUsableRSA() {
	kp, err := GenerateKeypair(WithRSABits(2048), WithNow(s.clock()))
	s.Require().NoError(err)
	s.Equal(AlgRS256, kp.Alg)
	s.NotEmpty(kp.Kid)
	s.NotEmpty(kp.PrivatePEM)
	s.NotEmpty(kp.PublicPEM)

	// Public PEM round-trips via jwx and matches the kid we baked in.
	pubKey, err := jwk.ParseKey(kp.PublicPEM, jwk.WithX509(true))
	s.Require().NoError(err)

	thumb, err := pubKey.Thumbprint(crypto.SHA256)
	s.Require().NoError(err)
	s.Equal(base64.RawURLEncoding.EncodeToString(thumb), kp.Kid)

	// Public PEM parses as a *rsa.PublicKey at the stdlib layer too.
	block, _ := pem.Decode(kp.PublicPEM)
	s.Require().NotNil(block)
	_, err = x509.ParsePKIXPublicKey(block.Bytes)
	s.Require().NoError(err)
}

func (s *KeysSuite) TestGenerateKeypairRejectsUnknownAlgorithm() {
	_, err := GenerateKeypair(WithGenAlgorithm("ES999"))
	s.Require().ErrorIs(err, ErrUnsupportedAlgorithm)
}

func (s *KeysSuite) TestInitOnEmptyStoreGenerates() {
	s.keys = New(WithStore(s.store), WithClock(s.clock()), withFastRSA())

	s.Require().NoError(s.keys.Init(s.ctx))

	saved, _ := s.store.LoadKeypairs(s.ctx)
	s.Require().Len(saved, 1, "init should have persisted exactly one keypair")

	latest, err := s.keys.Latest()
	s.Require().NoError(err)
	s.Equal(saved[0].Kid, latest.Kid)
	s.Len(s.keys.All(), 1)
}

func (s *KeysSuite) TestInitOnNonEmptyStoreLoadsLatest() {
	// Both predate the clock by more than the publish delay, so the newer
	// one is past it and signs.
	older := Keypair{Kid: "older", Alg: AlgRS256, CreatedAt: s.now.Add(-2 * time.Hour)}
	newer := Keypair{Kid: "newer", Alg: AlgRS256, CreatedAt: s.now.Add(-time.Hour)}
	// Insert in reverse-chronological order to prove Init re-sorts.
	s.Require().NoError(s.store.SaveKeypair(s.ctx, newer))
	s.Require().NoError(s.store.SaveKeypair(s.ctx, older))

	s.Require().NoError(s.keys.Init(s.ctx))

	saved, _ := s.store.LoadKeypairs(s.ctx)
	s.Require().Len(saved, 2, "init should not save again when store is non-empty")

	latest, err := s.keys.Latest()
	s.Require().NoError(err)
	s.Equal("newer", latest.Kid)

	all := s.keys.All()
	s.Require().Len(all, 2)
	s.Equal("older", all[0].Kid)
	s.Equal("newer", all[1].Kid)
}

func (s *KeysSuite) TestGenerateRefusesDuplicateWithoutForce() {
	s.keys = New(WithStore(s.store), WithClock(s.clock()), withFastRSA())
	s.Require().NoError(s.keys.Init(s.ctx))
	firstKid := s.mustLatest().Kid

	_, err := s.keys.Generate(s.ctx, false)
	s.Require().ErrorIs(err, ErrKeypairExists)
	s.Contains(err.Error(), firstKid)

	saved, _ := s.store.LoadKeypairs(s.ctx)
	s.Len(saved, 1, "store must be untouched on refusal")
}

func (s *KeysSuite) TestGenerateForceRotatesAndRetainsOld() {
	// No publish delay: this test is about rotation, PublishSuite covers the
	// delay.
	s.keys = New(WithStore(s.store), WithClock(s.clock()), WithPublishDelay(0), withFastRSA())
	s.Require().NoError(s.keys.Init(s.ctx))
	oldKid := s.mustLatest().Kid

	newKp, err := s.keys.Generate(s.ctx, true)
	s.Require().NoError(err)
	s.NotEqual(oldKid, newKp.Kid, "--force must produce a fresh kid")

	saved, _ := s.store.LoadKeypairs(s.ctx)
	s.Require().Len(saved, 2, "old keypair must be retained")

	all := s.keys.All()
	s.Require().Len(all, 2)
	s.Equal(oldKid, all[0].Kid)
	s.Equal(newKp.Kid, all[1].Kid)
	s.Equal(newKp.Kid, s.mustLatest().Kid)
}

// TestSignVerifyRoundTrip is the acceptance-criterion test:
// generate → reload via Init into a fresh *Keys → sign a JWT with the
// loaded private PEM → verify it with the loaded public PEM.
func (s *KeysSuite) TestSignVerifyRoundTrip() {
	gen := New(WithStore(s.store), WithClock(s.clock()), withFastRSA())
	s.Require().NoError(gen.Init(s.ctx))

	// Fresh Keys with the same store — proves PEMs survive a round-trip
	// through the store, not just the in-memory cache.
	loader := New(WithStore(s.store))
	s.Require().NoError(loader.Init(s.ctx))
	kp, err := loader.Latest()
	s.Require().NoError(err)

	privKey, err := jwk.ParseKey(kp.PrivatePEM, jwk.WithX509(true))
	s.Require().NoError(err)
	pubKey, err := jwk.ParseKey(kp.PublicPEM, jwk.WithX509(true))
	s.Require().NoError(err)

	token, err := jwt.NewBuilder().
		Issuer("tempogate").
		Subject("operator").
		IssuedAt(s.now).
		Expiration(s.now.Add(time.Hour)).
		Build()
	s.Require().NoError(err)

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), privKey))
	s.Require().NoError(err)

	clock := jwt.ClockFunc(func() time.Time { return s.now.Add(time.Minute) })
	parsed, err := jwt.Parse(signed,
		jwt.WithKey(jwa.RS256(), pubKey),
		jwt.WithClock(clock),
	)
	s.Require().NoError(err)
	iss, ok := parsed.Issuer()
	s.Require().True(ok)
	s.Equal("tempogate", iss)
	sub, ok := parsed.Subject()
	s.Require().True(ok)
	s.Equal("operator", sub)

	// Verify mismatched key fails — guards against any silent same-key
	// shortcut in jwt.Parse.
	otherKp, err := GenerateKeypair(WithRSABits(2048))
	s.Require().NoError(err)
	otherPub, err := jwk.ParseKey(otherKp.PublicPEM, jwk.WithX509(true))
	s.Require().NoError(err)
	_, err = jwt.Parse(signed,
		jwt.WithKey(jwa.RS256(), otherPub),
		jwt.WithClock(clock),
	)
	s.Require().Error(err)
}

func (s *KeysSuite) mustLatest() Keypair {
	kp, err := s.keys.Latest()
	s.Require().NoError(err)
	return kp
}

// withFastRSA shrinks the RSA modulus for tests so a multi-case suite doesn't
// burn minutes generating 4096-bit keys. Production callers don't touch this.
func withFastRSA() Option {
	return WithGenerateOptions(WithRSABits(2048))
}

// Sanity check that ErrNoKeypair is returned before any Init/Generate.
func (s *KeysSuite) TestLatestBeforeInitReturnsErrNoKeypair() {
	_, err := New(WithStore(s.store)).Latest()
	s.Require().True(errors.Is(err, ErrNoKeypair))
}
