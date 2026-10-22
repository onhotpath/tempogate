package keys

import (
	"context"
	"sync"
	"time"
)

// DefaultDenylistTTL bounds how long a positive *or* negative denylist lookup
// stays cached. 30 seconds matches the issue's stated tempogate-side revoke
// lag — a freshly-revoked token verifies for at most this long on hot paths
// like /userinfo before the next lookup pulls the updated state from sqlite.
// The refresh-token grant does not consult the denylist: refresh tokens are
// opaque, and their lifecycle (absolute lifetime, domain re-check, reuse
// detection, `tempogate sessions revoke`) lives in the oidc package.
const DefaultDenylistTTL = 30 * time.Second

// DenylistCache is the verifier's hot-path read-through cache over a
// DenylistChecker. It memoizes both positive ("revoked") and negative
// ("active") lookups for DefaultDenylistTTL so the steady-state cost of a
// JWT verification is an in-memory map probe, not a sqlite round-trip.
//
// Cache invalidation is one of three: TTL expiry, an explicit Hydrate call
// from the admin DELETE handler that marks a jti revoked immediately, or
// process restart. Multi-process deployments rely on TTL alone — the cache
// is in-process and never coordinated across instances; v1 accepts that
// bounded staleness.
type DenylistCache struct {
	checker DenylistChecker
	ttl     time.Duration
	now     func() time.Time

	mu      sync.Mutex
	entries map[string]cacheEntry
}

type cacheEntry struct {
	revoked bool
	expires time.Time
}

// DenylistCacheOption configures the cache. WithDenylistChecker is the only
// required option in practice; the rest carry test-friendly defaults.
type DenylistCacheOption func(*DenylistCache)

// WithDenylistChecker supplies the backing storage the cache consults on a
// miss. A nil checker yields a cache that treats every jti as not revoked —
// the verifier defaults to "no denylist configured ⇒ never reject".
func WithDenylistChecker(c DenylistChecker) DenylistCacheOption {
	return func(d *DenylistCache) { d.checker = c }
}

// WithDenylistTTL overrides DefaultDenylistTTL. Intended for tests that need
// to observe expiry without sleeping.
func WithDenylistTTL(d time.Duration) DenylistCacheOption {
	return func(c *DenylistCache) { c.ttl = d }
}

// WithDenylistClock swaps the clock the cache reads to age entries. Intended
// for tests.
func WithDenylistClock(now func() time.Time) DenylistCacheOption {
	return func(c *DenylistCache) { c.now = now }
}

// NewDenylistCache builds a cache with DefaultDenylistTTL and wall-clock
// expiry. The returned cache satisfies keys.DenylistChecker, so it can be
// passed to WithDenylist on a Verifier.
func NewDenylistCache(opts ...DenylistCacheOption) *DenylistCache {
	c := &DenylistCache{
		ttl:     DefaultDenylistTTL,
		now:     func() time.Time { return time.Now().UTC() },
		entries: map[string]cacheEntry{},
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// IsRevoked answers from the in-memory cache when the entry is fresh,
// otherwise round-trips to the backing checker and memoizes the result for
// the cache's TTL. A nil checker short-circuits to (false, nil).
func (c *DenylistCache) IsRevoked(ctx context.Context, jti string) (bool, error) {
	c.mu.Lock()
	if e, ok := c.entries[jti]; ok && c.now().Before(e.expires) {
		c.mu.Unlock()
		return e.revoked, nil
	}
	c.mu.Unlock()

	if c.checker == nil {
		return false, nil
	}

	revoked, err := c.checker.IsRevoked(ctx, jti)
	if err != nil {
		return false, err
	}

	c.mu.Lock()
	c.entries[jti] = cacheEntry{revoked: revoked, expires: c.now().Add(c.ttl)}
	c.mu.Unlock()
	return revoked, nil
}

// Hydrate marks jti as revoked in the cache without consulting the backing
// checker. The admin DELETE handler calls this after a successful revoke so
// the in-process Verifier rejects the freshly-revoked token immediately —
// without it, a previously-cached "not revoked" entry could keep accepting
// the token for up to TTL seconds.
func (c *DenylistCache) Hydrate(jti string) {
	if jti == "" {
		return
	}
	c.mu.Lock()
	c.entries[jti] = cacheEntry{revoked: true, expires: c.now().Add(c.ttl)}
	c.mu.Unlock()
}
