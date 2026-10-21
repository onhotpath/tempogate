package keys

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

// PublishSuite covers KEYS_PUBLISH_DELAY: a new keypair is published in JWKS
// at once but only signs once relying parties have had time to fetch it.
type PublishSuite struct {
	suite.Suite

	ctx   context.Context
	store *fakeKeyStore
	clock *manualClock
	delay time.Duration
	keys  *Keys
}

func TestPublishSuite(t *testing.T) {
	suite.Run(t, new(PublishSuite))
}

func (s *PublishSuite) SetupTest() {
	s.ctx = context.Background()
	s.store = &fakeKeyStore{}
	s.clock = &manualClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	s.delay = 5 * time.Minute
	s.keys = New(
		WithStore(s.store),
		WithClock(s.clock.Now),
		WithPublishDelay(s.delay),
		withFastRSA(),
	)
}

func (s *PublishSuite) generate() Keypair {
	s.clock.Advance(time.Second)
	kp, err := s.keys.Generate(s.ctx, true)
	s.Require().NoError(err)
	return kp
}

func (s *PublishSuite) signingKid() string {
	kp, err := s.keys.Latest()
	s.Require().NoError(err)
	return kp.Kid
}

func (s *PublishSuite) mintKid() string {
	signer := NewSigner(WithKeys(s.keys), WithTokenClock(s.clock.Now))
	raw, _, err := signer.Mint(s.ctx, MintRequest{Subject: "svc", TTL: time.Hour})
	s.Require().NoError(err)
	return headerKid(s.T(), raw)
}

func (s *PublishSuite) TestFreshInstallSignsImmediately() {
	s.Require().NoError(s.keys.Init(s.ctx))
	only := s.keys.All()[0]
	s.Equal(only.Kid, s.mintKid(), "with no other key the first key must sign at once")
}

func (s *PublishSuite) TestPendingKeyIsPublishedButDoesNotSignBeforeDelay() {
	old := s.generate()
	s.clock.Advance(time.Hour)
	pending := s.generate()

	set, err := s.keys.PublicJWKS()
	s.Require().NoError(err)
	s.Equal([]string{old.Kid, pending.Kid}, kidsOf(set), "a new key is published at once")
	s.Equal(old.Kid, s.mintKid(), "the previous key keeps signing while the new one is pending")

	s.clock.Advance(s.delay - time.Second)
	s.Equal(old.Kid, s.signingKid(), "still pending one second before the delay elapses")

	s.clock.Advance(time.Second)
	s.Equal(pending.Kid, s.mintKid(), "the new key signs once created_at + delay has passed")
}

func (s *PublishSuite) TestPendingKeySignsWhenNoOtherKeyIsUsable() {
	old := s.generate()
	retired := s.clock.Now()
	s.store.mu.Lock()
	s.store.kps[0].RetiredAt = &retired
	s.store.mu.Unlock()

	recovery := s.generate()
	s.Require().NoError(s.keys.Reload(s.ctx))
	s.NotEqual(old.Kid, recovery.Kid)
	s.Equal(recovery.Kid, s.mintKid(), "with every other key retired the new key signs at once")
}

func (s *PublishSuite) TestOldestPendingKeySignsWhenNoKeyHasMatured() {
	first := s.generate()
	s.generate()
	s.Equal(first.Kid, s.signingKid(),
		"with nothing past its delay, the key relying parties have had longest to fetch signs")
}

func (s *PublishSuite) TestStatusesShowSignerAndPendingActivation() {
	old := s.generate()
	s.clock.Advance(time.Hour)
	pending := s.generate()

	sts, err := s.keys.Statuses(s.ctx)
	s.Require().NoError(err)
	s.Require().Len(sts, 2)
	s.Equal(old.Kid, sts[0].Kid)
	s.True(sts[0].Signing)
	s.Nil(sts[0].ActivatesAt, "the signing key has no pending activation")
	s.Equal(pending.Kid, sts[1].Kid)
	s.False(sts[1].Signing)
	s.Require().NotNil(sts[1].ActivatesAt)
	s.True(sts[1].ActivatesAt.Equal(pending.CreatedAt.Add(s.delay)))

	s.clock.Advance(s.delay)
	sts, err = s.keys.Statuses(s.ctx)
	s.Require().NoError(err)
	s.False(sts[0].Signing)
	s.Nil(sts[0].ActivatesAt, "a superseded key is merely published")
	s.True(sts[1].Signing)
	s.Nil(sts[1].ActivatesAt, "a key past its delay is no longer pending")
}

func (s *PublishSuite) TestRetireRefusesSignerWhileReplacementIsPending() {
	old := s.generate()
	s.clock.Advance(time.Hour)
	pending := s.generate()

	_, err := s.keys.Retire(s.ctx, old.Kid)
	s.Require().ErrorIs(err, ErrReplacementPending)
	s.Contains(err.Error(), pending.Kid)
	s.Contains(err.Error(), "KEYS_PUBLISH_DELAY")
	s.Equal(old.Kid, s.signingKid(), "a refused retire leaves the signer in place")

	s.clock.Advance(s.delay)
	_, err = s.keys.Retire(s.ctx, old.Kid)
	s.Require().NoError(err, "once the replacement has activated the old key retires normally")
	s.Equal(pending.Kid, s.signingKid())
}

func (s *PublishSuite) TestForcedRetireSwitchesToPendingReplacement() {
	old := s.generate()
	s.clock.Advance(time.Hour)
	pending := s.generate()

	got, err := s.keys.Retire(s.ctx, old.Kid, RetireForce())
	s.Require().NoError(err)
	s.NotNil(got.RetiredAt)
	s.Equal(pending.Kid, s.signingKid(), "a forced retire falls back to the pending key at once")
}

func (s *PublishSuite) TestRetirePendingKeyIsAllowed() {
	old := s.generate()
	s.clock.Advance(time.Hour)
	pending := s.generate()

	_, err := s.keys.Retire(s.ctx, pending.Kid)
	s.Require().NoError(err, "dropping a pending key never changes the signer")
	s.Equal(old.Kid, s.signingKid())
}

func (s *PublishSuite) TestRetireStillRefusesTheOnlyKey() {
	only := s.generate()
	_, err := s.keys.Retire(s.ctx, only.Kid, RetireForce())
	s.Require().ErrorIs(err, ErrLastActiveKeypair, "force never retires the only key that can sign")
}

func (s *PublishSuite) TestNegativeDelayIsRejected() {
	s.Require().Panics(func() { WithPublishDelay(-time.Second) })
}

func kidsOf(set []JWK) []string {
	out := make([]string, 0, len(set))
	for _, j := range set {
		out = append(out, j.Kid)
	}
	return out
}
