package keys

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

// KeyCacheSuite pins the Signer's and Verifier's parsed-key caches to the
// keypair lifecycle: a cached key is reused only while its kid is the one
// Keys says to sign with (or is still published), so hot reload, retirement
// grace and publish-delay activation all take effect on a warm cache.
type KeyCacheSuite struct {
	suite.Suite

	ctx      context.Context
	store    *fakeKeyStore
	clock    *manualClock
	keys     *Keys
	signer   *Signer
	verifier *Verifier
}

func TestKeyCacheSuite(t *testing.T) {
	suite.Run(t, new(KeyCacheSuite))
}

const (
	cacheSuiteGrace = 4 * time.Hour
	cacheSuiteDelay = 5 * time.Minute
)

func (s *KeyCacheSuite) SetupTest() {
	s.ctx = context.Background()
	s.store = &fakeKeyStore{}
	s.clock = &manualClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	s.keys = s.newKeys()
	s.Require().NoError(s.keys.Init(s.ctx))
	s.signer = NewSigner(WithKeys(s.keys), WithTokenClock(s.clock.Now))
	s.verifier = NewVerifier(WithKeys(s.keys), WithTokenClock(s.clock.Now))
}

// newKeys builds an aggregate over the suite's store, standing in for either
// this process or another `tempogate keys ...` process sharing the database.
func (s *KeyCacheSuite) newKeys() *Keys {
	return New(
		WithStore(s.store),
		WithClock(s.clock.Now),
		WithRetirementGrace(cacheSuiteGrace),
		WithPublishDelay(cacheSuiteDelay),
		withFastRSA(),
	)
}

func (s *KeyCacheSuite) mint() (string, string) {
	raw, _, err := s.signer.Mint(s.ctx, MintRequest{Subject: "svc", TTL: 24 * time.Hour})
	s.Require().NoError(err)
	return raw, headerKid(s.T(), raw)
}

// rotateElsewhere generates a keypair through a second aggregate, as the
// `keys generate --force` CLI would, then hot-reloads this process.
func (s *KeyCacheSuite) rotateElsewhere() Keypair {
	s.clock.Advance(time.Second)
	kp, err := s.newKeys().Generate(s.ctx, true)
	s.Require().NoError(err)
	s.Require().NoError(s.keys.Reload(s.ctx))
	return kp
}

// corruptStoredPEMs overwrites kid's stored key material with garbage and
// hot-reloads. Key material is immutable per kid (kid is its thumbprint), so
// a cache keyed by kid must keep serving the parsed key; a re-parse fails.
func (s *KeyCacheSuite) corruptStoredPEMs(kid string) {
	s.store.mu.Lock()
	for i := range s.store.kps {
		if s.store.kps[i].Kid == kid {
			s.store.kps[i].PrivatePEM = []byte("-----BEGIN RSA PRIVATE KEY-----\nbad\n-----END RSA PRIVATE KEY-----")
			s.store.kps[i].PublicPEM = []byte("-----BEGIN PUBLIC KEY-----\nbad\n-----END PUBLIC KEY-----")
		}
	}
	s.store.mu.Unlock()
	s.Require().NoError(s.keys.Reload(s.ctx))
}

func (s *KeyCacheSuite) TestSignerParsesThePrivateKeyOncePerKid() {
	_, kid := s.mint()
	s.corruptStoredPEMs(kid)

	_, again := s.mint()
	s.Equal(kid, again, "a warm signer must not re-parse the same kid's private key")
}

// TestIDTokensShareTheSignerCache: MintIDToken signs through the same cached
// key as Mint, so an ID token never re-parses the PEM either.
func (s *KeyCacheSuite) TestIDTokensShareTheSignerCache() {
	_, kid := s.mint()
	s.corruptStoredPEMs(kid)

	raw, err := s.signer.MintIDToken(s.ctx, IDTokenRequest{Subject: "alice", Audience: "temporal-ui", TTL: time.Hour})
	s.Require().NoError(err, "a warm signer must not re-parse the private key for an ID token")
	s.Equal(kid, headerKid(s.T(), raw))
}

func (s *KeyCacheSuite) TestVerifierParsesPublicKeysOncePerKeySet() {
	raw, kid := s.mint()
	_, err := s.verifier.Verify(s.ctx, raw)
	s.Require().NoError(err)
	s.corruptStoredPEMs(kid)

	_, err = s.verifier.Verify(s.ctx, raw)
	s.Require().NoError(err, "a warm verifier must not re-parse an unchanged published key set")
}

func (s *KeyCacheSuite) TestSignerSwitchesKeyWhenThePublishDelayElapses() {
	_, oldKid := s.mint()
	next := s.rotateElsewhere()

	_, kid := s.mint()
	s.Equal(oldKid, kid, "inside the publish delay the old key keeps signing")

	s.clock.Advance(cacheSuiteDelay)
	raw, kid := s.mint()
	s.Equal(next.Kid, kid, "once the delay elapses the warm signer switches to the new key")
	_, err := s.verifier.Verify(s.ctx, raw)
	s.Require().NoError(err)
}

func (s *KeyCacheSuite) TestSignerStopsUsingAKeyRetiredByAnotherProcess() {
	_, oldKid := s.mint()
	next := s.rotateElsewhere()
	s.clock.Advance(cacheSuiteDelay)
	_, err := s.newKeys().Retire(s.ctx, oldKid)
	s.Require().NoError(err)
	s.Require().NoError(s.keys.Reload(s.ctx))

	_, kid := s.mint()
	s.Equal(next.Kid, kid)
}

func (s *KeyCacheSuite) TestVerifierPicksUpAKeyAddedByHotReload() {
	raw, _ := s.mint()
	_, err := s.verifier.Verify(s.ctx, raw)
	s.Require().NoError(err)

	next := s.rotateElsewhere()
	s.clock.Advance(cacheSuiteDelay)
	raw, kid := s.mint()
	s.Require().Equal(next.Kid, kid)
	_, err = s.verifier.Verify(s.ctx, raw)
	s.Require().NoError(err, "a key published after the cache warmed must verify")
}

func (s *KeyCacheSuite) TestVerifierNeverAcceptsAKeyRetiredPastGraceFromCache() {
	oldRaw, oldKid := s.mint()
	_, err := s.verifier.Verify(s.ctx, oldRaw)
	s.Require().NoError(err)

	s.rotateElsewhere()
	s.clock.Advance(cacheSuiteDelay)
	_, err = s.keys.Retire(s.ctx, oldKid)
	s.Require().NoError(err)

	_, err = s.verifier.Verify(s.ctx, oldRaw)
	s.Require().NoError(err, "inside the grace the retired key still verifies")

	s.clock.Advance(cacheSuiteGrace)
	_, err = s.verifier.Verify(s.ctx, oldRaw)
	s.Require().Error(err, "past the grace a warm verifier must reject the retired key")

	newRaw, _ := s.mint()
	_, err = s.verifier.Verify(s.ctx, newRaw)
	s.Require().NoError(err)
}

// TestConcurrentMintVerifyAcrossRotation is meant for -race: minting and
// verifying on many goroutines while another goroutine rotates and reloads.
func (s *KeyCacheSuite) TestConcurrentMintVerifyAcrossRotation() {
	var wg sync.WaitGroup
	done := make(chan struct{})
	for range 8 {
		wg.Go(func() {
			for {
				select {
				case <-done:
					return
				default:
				}
				raw, _, err := s.signer.Mint(s.ctx, MintRequest{Subject: "svc", TTL: 24 * time.Hour})
				if err != nil {
					s.T().Error(err)
					return
				}
				if _, err := s.verifier.Verify(s.ctx, raw); err != nil {
					s.T().Error(err)
					return
				}
			}
		})
	}
	for range 3 {
		kp, err := s.newKeys().Generate(s.ctx, true)
		s.Require().NoError(err)
		s.Require().NoError(s.keys.Reload(s.ctx))
		s.clock.Advance(cacheSuiteDelay + time.Second)
		s.Require().NoError(s.keys.Reload(s.ctx))
		s.Require().NotEmpty(kp.Kid)
	}
	close(done)
	wg.Wait()
}

// TestVerifierRebuildsWhenAKidIsSwappedAtTheSameSetSize covers a rotation and
// a grace expiry landing between two verifications: the published set keeps
// its size but not its kids, and the warm cache must not mistake it for the
// set it already holds.
func (s *KeyCacheSuite) TestVerifierRebuildsWhenAKidIsSwappedAtTheSameSetSize() {
	oldRaw, oldKid := s.mint()
	s.rotateElsewhere()
	s.clock.Advance(cacheSuiteDelay)
	_, err := s.keys.Retire(s.ctx, oldKid)
	s.Require().NoError(err)
	_, err = s.verifier.Verify(s.ctx, oldRaw)
	s.Require().NoError(err, "warm the cache with {old, next}")

	s.clock.Advance(cacheSuiteGrace)
	latest := s.rotateElsewhere()
	s.Require().Len(s.keys.Published(), 2, "{next, latest}: same size, different kids")

	_, err = s.verifier.Verify(s.ctx, oldRaw)
	s.Require().Error(err)
	s.clock.Advance(cacheSuiteDelay)
	raw, kid := s.mint()
	s.Require().Equal(latest.Kid, kid)
	_, err = s.verifier.Verify(s.ctx, raw)
	s.Require().NoError(err)
}

func (s *KeyCacheSuite) TestVerifierWithAnEmptyCachedSetStillRefuses() {
	v := NewVerifier(WithKeys(New(WithStore(&fakeKeyStore{}))), WithTokenClock(s.clock.Now))
	for range 2 {
		_, err := v.Verify(s.ctx, "x.y.z")
		s.Require().ErrorIs(err, ErrNoVerificationKeys)
	}
}
