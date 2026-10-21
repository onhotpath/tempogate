package keys

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/suite"
)

// manualClock is a settable clock so a test can step past a retirement grace
// window without sleeping.
type manualClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *manualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *manualClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type RetireSuite struct {
	suite.Suite

	ctx   context.Context
	store *fakeKeyStore
	clock *manualClock
	grace time.Duration
	keys  *Keys
}

func TestRetireSuite(t *testing.T) {
	suite.Run(t, new(RetireSuite))
}

func (s *RetireSuite) SetupTest() {
	s.ctx = context.Background()
	s.store = &fakeKeyStore{}
	s.clock = &manualClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	s.grace = 4 * time.Hour
	s.keys = s.newKeys()
}

func (s *RetireSuite) newKeys() *Keys {
	return New(
		WithStore(s.store),
		WithClock(s.clock.Now),
		WithRetirementGrace(s.grace),
		withFastRSA(),
	)
}

// generate persists a fresh keypair one second after the previous one so
// CreatedAt ordering is deterministic.
func (s *RetireSuite) generate() Keypair {
	s.clock.Advance(time.Second)
	kp, err := s.keys.Generate(s.ctx, true)
	s.Require().NoError(err)
	return kp
}

func (s *RetireSuite) kids(kps []Keypair) []string {
	out := make([]string, 0, len(kps))
	for _, kp := range kps {
		out = append(out, kp.Kid)
	}
	return out
}

func (s *RetireSuite) TestRetireRefusesUnknownKid() {
	s.generate()
	_, err := s.keys.Retire(s.ctx, "no-such-kid")
	s.Require().ErrorIs(err, ErrKeypairNotFound)
}

func (s *RetireSuite) TestRetireRefusesOnlyActiveKey() {
	only := s.generate()
	_, err := s.keys.Retire(s.ctx, only.Kid)
	s.Require().ErrorIs(err, ErrLastActiveKeypair)

	latest, err := s.keys.Latest()
	s.Require().NoError(err)
	s.Equal(only.Kid, latest.Kid, "a refused retire must leave the signer's key in place")
}

func (s *RetireSuite) TestRetireNewestFallsBackToPreviousActiveKey() {
	older := s.generate()
	newer := s.generate()

	got, err := s.keys.Retire(s.ctx, newer.Kid)
	s.Require().NoError(err)
	s.Require().NotNil(got.RetiredAt)
	s.True(got.RetiredAt.Equal(s.clock.Now()))

	latest, err := s.keys.Latest()
	s.Require().NoError(err)
	s.Equal(older.Kid, latest.Kid, "the newest non-retired key signs once the newest is retired")
}

func (s *RetireSuite) TestRetireIsIdempotent() {
	old := s.generate()
	s.generate()

	first, err := s.keys.Retire(s.ctx, old.Kid)
	s.Require().NoError(err)
	s.clock.Advance(time.Hour)
	second, err := s.keys.Retire(s.ctx, old.Kid)
	s.Require().NoError(err)
	s.True(second.RetiredAt.Equal(*first.RetiredAt), "a repeat retire must not restart the grace window")
}

func (s *RetireSuite) TestRetiredKeyLeavesJWKSAfterGrace() {
	old := s.generate()
	current := s.generate()
	_, err := s.keys.Retire(s.ctx, old.Kid)
	s.Require().NoError(err)

	set, err := s.keys.PublicJWKS()
	s.Require().NoError(err)
	s.Equal([]string{old.Kid, current.Kid}, s.jwkKids(set), "a retired key stays published during its grace")

	s.clock.Advance(s.grace - time.Second)
	set, err = s.keys.PublicJWKS()
	s.Require().NoError(err)
	s.Contains(s.jwkKids(set), old.Kid)

	s.clock.Advance(time.Second)
	set, err = s.keys.PublicJWKS()
	s.Require().NoError(err)
	s.Equal([]string{current.Kid}, s.jwkKids(set), "a retired key leaves JWKS once its grace has elapsed")
	s.Equal([]string{current.Kid}, s.kids(s.keys.Published()))
	s.Len(s.keys.All(), 2, "retirement unpublishes a key; it never deletes it")
}

func (s *RetireSuite) TestZeroGraceUnpublishesImmediately() {
	s.grace = 0
	s.keys = s.newKeys()
	old := s.generate()
	current := s.generate()

	_, err := s.keys.Retire(s.ctx, old.Kid)
	s.Require().NoError(err)
	s.Equal([]string{current.Kid}, s.kids(s.keys.Published()))
}

func (s *RetireSuite) TestVerifierRejectsTokensFromKidPastGrace() {
	old := s.generate()
	signer := NewSigner(WithKeys(s.keys), WithTokenClock(s.clock.Now))
	raw, _, err := signer.Mint(s.ctx, MintRequest{Subject: "svc", TTL: 30 * 24 * time.Hour})
	s.Require().NoError(err)

	s.generate()
	_, err = s.keys.Retire(s.ctx, old.Kid)
	s.Require().NoError(err)

	verifier := NewVerifier(WithKeys(s.keys), WithTokenClock(s.clock.Now))
	_, err = verifier.Verify(s.ctx, raw)
	s.Require().NoError(err, "tokens from a retired kid still verify during grace")

	s.clock.Advance(s.grace)
	_, err = verifier.Verify(s.ctx, raw)
	s.Require().Error(err, "tokens from a kid past grace must stop verifying, exp notwithstanding")
}

func (s *RetireSuite) TestSignerNeverSignsWithRetiredKey() {
	old := s.generate()
	current := s.generate()
	// Retiring the newest leaves the older key active; retiring that one
	// next is refused, so the signer always has a non-retired key.
	_, err := s.keys.Retire(s.ctx, current.Kid)
	s.Require().NoError(err)

	signer := NewSigner(WithKeys(s.keys), WithTokenClock(s.clock.Now))
	raw, _, err := signer.Mint(s.ctx, MintRequest{Subject: "svc", TTL: time.Hour})
	s.Require().NoError(err)
	s.Equal(old.Kid, headerKid(s.T(), raw))
}

func (s *RetireSuite) TestReloadPicksUpAnotherProcessesChanges() {
	first := s.generate()

	// A second *Keys over the same store stands in for `tempogate keys`
	// running in another process.
	other := s.newKeys()
	s.clock.Advance(time.Second)
	rotated, err := other.Generate(s.ctx, true)
	s.Require().NoError(err)
	_, err = other.Retire(s.ctx, first.Kid)
	s.Require().NoError(err)

	latest, err := s.keys.Latest()
	s.Require().NoError(err)
	s.Equal(first.Kid, latest.Kid, "the cache is stale until reloaded")

	s.Require().NoError(s.keys.Reload(s.ctx))
	latest, err = s.keys.Latest()
	s.Require().NoError(err)
	s.Equal(rotated.Kid, latest.Kid)
	s.Require().NotNil(s.keys.All()[0].RetiredAt, "retirement from another process is visible after reload")
}

func (s *RetireSuite) TestKeypairsReadsThroughToTheStore() {
	first := s.generate()
	other := s.newKeys()
	s.clock.Advance(time.Second)
	rotated, err := other.Generate(s.ctx, true)
	s.Require().NoError(err)

	got, err := s.keys.Keypairs(s.ctx)
	s.Require().NoError(err)
	s.Equal([]string{first.Kid, rotated.Kid}, s.kids(got))
}

func (s *RetireSuite) TestReloadErrorKeepsCurrentSet() {
	kp := s.generate()
	s.store.loadErr = errors.New("disk on fire")

	s.Require().ErrorContains(s.keys.Reload(s.ctx), "disk on fire")
	latest, err := s.keys.Latest()
	s.Require().NoError(err)
	s.Equal(kp.Kid, latest.Kid, "a failed reload must not drop the loaded keys")
}

func (s *RetireSuite) TestWatchReloadsUntilCancelled() {
	first := s.generate()
	ctx, cancel := context.WithCancel(s.ctx)
	done := make(chan error, 1)
	go func() { done <- s.keys.Watch(ctx, 5*time.Millisecond, func(error) {}) }()

	other := s.newKeys()
	s.clock.Advance(time.Second)
	rotated, err := other.Generate(s.ctx, true)
	s.Require().NoError(err)

	s.Eventually(func() bool {
		latest, err := s.keys.Latest()
		return err == nil && latest.Kid == rotated.Kid
	}, 2*time.Second, 5*time.Millisecond, "Watch must pick up a key generated elsewhere")
	s.NotEqual(first.Kid, rotated.Kid)

	cancel()
	select {
	case err := <-done:
		s.NoError(err)
	case <-time.After(2 * time.Second):
		s.Fail("Watch must return once its context is cancelled")
	}
}

func (s *RetireSuite) TestWatchReportsReloadErrors() {
	s.generate()
	s.store.mu.Lock()
	s.store.loadErr = errors.New("locked")
	s.store.mu.Unlock()

	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel()
	errs := make(chan error, 1)
	go func() {
		_ = s.keys.Watch(ctx, 5*time.Millisecond, func(err error) {
			select {
			case errs <- err:
			default:
			}
		})
	}()

	select {
	case err := <-errs:
		s.ErrorContains(err, "locked")
	case <-time.After(2 * time.Second):
		s.Fail("Watch must report a failed reload")
	}
}

func (s *RetireSuite) TestInitGeneratesWhenEveryKeyIsRetired() {
	retired := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	s.Require().NoError(s.store.SaveKeypair(s.ctx, Keypair{
		Kid: "hand-retired", Alg: AlgRS256, CreatedAt: retired, RetiredAt: &retired,
	}))

	s.Require().NoError(s.keys.Init(s.ctx))
	latest, err := s.keys.Latest()
	s.Require().NoError(err)
	s.NotEqual("hand-retired", latest.Kid, "serve must not start without a key it can sign with")
}

func (s *RetireSuite) TestNegativeGraceIsRejected() {
	s.Require().Panics(func() { WithRetirementGrace(-time.Second) })
}

func (s *RetireSuite) jwkKids(set []JWK) []string {
	out := make([]string, 0, len(set))
	for _, j := range set {
		out = append(out, j.Kid)
	}
	return out
}

func headerKid(t *testing.T, raw string) string {
	t.Helper()
	msg, err := jws.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("parse jws: %v", err)
	}
	kid, ok := msg.Signatures()[0].ProtectedHeaders().KeyID()
	if !ok {
		t.Fatal("token has no kid header")
	}
	return kid
}

func (s *RetireSuite) TestKeypairsAndRetireSurfaceReloadErrors() {
	old := s.generate()
	s.generate()
	s.store.loadErr = errors.New("disk on fire")

	_, err := s.keys.Keypairs(s.ctx)
	s.Require().ErrorContains(err, "disk on fire")

	_, err = s.keys.Retire(s.ctx, old.Kid)
	s.Require().ErrorContains(err, "disk on fire", "a retire whose reload fails must not report success")
}
