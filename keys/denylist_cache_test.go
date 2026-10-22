package keys

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

// denylistCacheSuite exercises the read-through cache against a counting,
// scriptable stub so the suite can assert exactly how many round-trips the
// hot path makes. Time is virtual: WithDenylistClock lets the suite advance
// past TTL without sleeping.
type denylistCacheSuite struct {
	suite.Suite

	ctx     context.Context
	now     time.Time
	checker *countingChecker
	cache   *DenylistCache
}

func TestDenylistCacheSuite(t *testing.T) {
	suite.Run(t, new(denylistCacheSuite))
}

func (s *denylistCacheSuite) SetupTest() {
	s.ctx = context.Background()
	s.now = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s.checker = &countingChecker{revoked: map[string]bool{}}
	s.cache = NewDenylistCache(
		WithDenylistChecker(s.checker),
		WithDenylistTTL(30*time.Second),
		WithDenylistClock(func() time.Time { return s.now }),
	)
}

func (s *denylistCacheSuite) advance(d time.Duration) {
	s.now = s.now.Add(d)
}

func (s *denylistCacheSuite) TestMissThenHitDoesNotReRoundTrip() {
	s.checker.revoked["jti-1"] = true

	got, err := s.cache.IsRevoked(s.ctx, "jti-1")
	s.Require().NoError(err)
	s.True(got)
	s.Equal(int64(1), s.checker.calls.Load())

	for range 5 {
		got, err := s.cache.IsRevoked(s.ctx, "jti-1")
		s.Require().NoError(err)
		s.True(got)
	}
	s.Equal(int64(1), s.checker.calls.Load(), "subsequent hits within TTL must not re-query")
}

func (s *denylistCacheSuite) TestNegativeLookupAlsoCaches() {
	got, err := s.cache.IsRevoked(s.ctx, "jti-active")
	s.Require().NoError(err)
	s.False(got)
	s.Equal(int64(1), s.checker.calls.Load())

	got, err = s.cache.IsRevoked(s.ctx, "jti-active")
	s.Require().NoError(err)
	s.False(got)
	s.Equal(int64(1), s.checker.calls.Load(), "negative result must also be memoized")
}

func (s *denylistCacheSuite) TestTTLExpiryRefetches() {
	s.checker.revoked["jti-2"] = false

	_, err := s.cache.IsRevoked(s.ctx, "jti-2")
	s.Require().NoError(err)
	s.Equal(int64(1), s.checker.calls.Load())

	// Within TTL → cached
	s.advance(29 * time.Second)
	_, err = s.cache.IsRevoked(s.ctx, "jti-2")
	s.Require().NoError(err)
	s.Equal(int64(1), s.checker.calls.Load())

	// Past TTL → refetch; storage now reports revoked, cache mirrors that
	s.advance(2 * time.Second)
	s.checker.revoked["jti-2"] = true
	got, err := s.cache.IsRevoked(s.ctx, "jti-2")
	s.Require().NoError(err)
	s.True(got, "cache must reflect storage change after TTL expiry")
	s.Equal(int64(2), s.checker.calls.Load())
}

func (s *denylistCacheSuite) TestHydrateMakesRevokedImmediately() {
	// First lookup primes the cache with "active" (false).
	got, err := s.cache.IsRevoked(s.ctx, "jti-3")
	s.Require().NoError(err)
	s.False(got)
	s.Equal(int64(1), s.checker.calls.Load())

	// Hydrate flips the cached entry to revoked without touching storage,
	// matching what the admin DELETE handler does after a successful revoke.
	s.cache.Hydrate("jti-3")

	got, err = s.cache.IsRevoked(s.ctx, "jti-3")
	s.Require().NoError(err)
	s.True(got, "Hydrate must override a cached active entry without round-tripping")
	s.Equal(int64(1), s.checker.calls.Load(), "Hydrate must not consult the checker")
}

func (s *denylistCacheSuite) TestHydrateEmptyIsNoop() {
	// Hydrating "" must not poison the cache so a JWT with no jti claim
	// (which the verifier should skip) doesn't accidentally turn into a
	// blanket "revoked" sentinel.
	s.cache.Hydrate("")
	got, err := s.cache.IsRevoked(s.ctx, "")
	s.Require().NoError(err)
	s.False(got)
}

func (s *denylistCacheSuite) TestNilCheckerNeverRevokes() {
	c := NewDenylistCache()
	got, err := c.IsRevoked(s.ctx, "anything")
	s.Require().NoError(err)
	s.False(got, "no checker configured → cache must answer not-revoked")
}

func (s *denylistCacheSuite) TestCheckerErrorIsSurfaced() {
	boom := errors.New("storage on fire")
	c := NewDenylistCache(WithDenylistChecker(&errorChecker{err: boom}))
	_, err := c.IsRevoked(s.ctx, "j")
	s.Require().ErrorIs(err, boom)
}

func (s *denylistCacheSuite) TestDefaultsAreSane() {
	c := NewDenylistCache()
	s.Equal(DefaultDenylistTTL, c.ttl)
	s.Equal(DefaultDenylistMaxEntries, c.maxEntries)
	s.NotNil(c.now)
	s.Equal(DefaultDenylistMaxEntries, NewDenylistCache(WithDenylistMaxEntries(0)).maxEntries,
		"a non-positive cap keeps the default rather than disabling the cache")
}

// countingChecker satisfies DenylistChecker with a deterministic in-memory
// map and an atomic counter so the suite can assert exactly how many times
// the cache fell through to storage.
type countingChecker struct {
	revoked map[string]bool
	calls   atomic.Int64
}

func (c *countingChecker) IsRevoked(_ context.Context, jti string) (bool, error) {
	c.calls.Add(1)
	return c.revoked[jti], nil
}

// errorChecker always fails so the error-surface test can assert ErrorIs
// without depending on a particular storage backend.
type errorChecker struct{ err error }

func (e *errorChecker) IsRevoked(_ context.Context, _ string) (bool, error) {
	return false, e.err
}

func (s *denylistCacheSuite) size() int {
	s.cache.mu.Lock()
	defer s.cache.mu.Unlock()
	return len(s.cache.entries)
}

func (s *denylistCacheSuite) TestExpiredEntriesAreSwept() {
	// One fresh jti per second for well over the TTL: without a sweep every
	// verified jti would stay in memory for the life of the process.
	for i := range 1000 {
		_, err := s.cache.IsRevoked(s.ctx, fmt.Sprintf("jti-%d", i))
		s.Require().NoError(err)
		s.advance(time.Second)
	}
	s.LessOrEqual(s.size(), 61, "only entries from the last two TTL windows may remain")
}

func (s *denylistCacheSuite) TestSizeCapIsHard() {
	c := NewDenylistCache(
		WithDenylistChecker(s.checker),
		WithDenylistClock(func() time.Time { return s.now }),
		WithDenylistMaxEntries(4),
	)
	s.cache = c
	for i := range 100 {
		_, err := c.IsRevoked(s.ctx, fmt.Sprintf("jti-%d", i))
		s.Require().NoError(err)
	}
	s.LessOrEqual(s.size(), 4, "a burst of distinct jtis inside one TTL must not exceed the cap")
}

func (s *denylistCacheSuite) TestCapEvictsActiveEntriesBeforeRevoked() {
	c := NewDenylistCache(
		WithDenylistChecker(s.checker),
		WithDenylistClock(func() time.Time { return s.now }),
		WithDenylistMaxEntries(3),
	)
	s.cache = c
	c.Hydrate("jti-revoked")
	for i := range 10 {
		_, err := c.IsRevoked(s.ctx, fmt.Sprintf("jti-active-%d", i))
		s.Require().NoError(err)
	}
	calls := s.checker.calls.Load()

	got, err := c.IsRevoked(s.ctx, "jti-revoked")
	s.Require().NoError(err)
	s.True(got)
	s.Equal(calls, s.checker.calls.Load(), "the revoked entry must survive eviction pressure from active ones")
}

func (s *denylistCacheSuite) TestEvictedRevokedJtiIsStillRejected() {
	c := NewDenylistCache(
		WithDenylistChecker(s.checker),
		WithDenylistClock(func() time.Time { return s.now }),
		WithDenylistMaxEntries(2),
	)
	s.cache = c
	for i := range 5 {
		jti := fmt.Sprintf("jti-revoked-%d", i)
		s.checker.revoked[jti] = true
		got, err := c.IsRevoked(s.ctx, jti)
		s.Require().NoError(err)
		s.True(got)
	}
	s.advance(time.Hour)
	for i := range 5 {
		got, err := c.IsRevoked(s.ctx, fmt.Sprintf("jti-revoked-%d", i))
		s.Require().NoError(err)
		s.True(got, "eviction only drops the memo; the store still answers revoked")
	}
}
