package ratelimit_test

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/onhotpath/tempogate/ratelimit"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newClock() *fakeClock { return &fakeClock{now: time.Unix(1700000000, 0)} }

func TestAllowSpendsTheBurstThenRefuses(t *testing.T) {
	clock := newClock()
	l := ratelimit.New(ratelimit.WithLimit(3, time.Minute), ratelimit.WithClock(clock.Now))
	for i := range 3 {
		assert.Truef(t, l.Allow("a"), "attempt %d inside the burst", i)
	}
	assert.False(t, l.Allow("a"))
	assert.True(t, l.Allow("b"), "keys are independent")
}

func TestTokensRefillOverTime(t *testing.T) {
	clock := newClock()
	l := ratelimit.New(ratelimit.WithLimit(3, time.Minute), ratelimit.WithClock(clock.Now))
	for range 3 {
		require.True(t, l.Allow("a"))
	}
	require.False(t, l.Allow("a"))

	clock.Advance(20 * time.Second) // one token per 20 s
	assert.True(t, l.Allow("a"))
	assert.False(t, l.Allow("a"))

	clock.Advance(time.Hour) // refill is capped at the burst
	for range 3 {
		assert.True(t, l.Allow("a"))
	}
	assert.False(t, l.Allow("a"))
}

func TestRefundReturnsOneToken(t *testing.T) {
	clock := newClock()
	l := ratelimit.New(ratelimit.WithLimit(2, time.Minute), ratelimit.WithClock(clock.Now))
	require.True(t, l.Allow("a"))
	require.True(t, l.Allow("a"))
	require.False(t, l.Allow("a"))

	l.Refund("a")
	assert.True(t, l.Allow("a"))
	assert.False(t, l.Allow("a"))

	// A refund never lifts a key above its burst, and refunding an unknown
	// key is a no-op.
	l.Refund("fresh")
	l.Refund("fresh")
	assert.True(t, l.Allow("fresh"))
	assert.True(t, l.Allow("fresh"))
	assert.False(t, l.Allow("fresh"))
}

func TestMaxKeysEvictsLeastRecentlyUsed(t *testing.T) {
	clock := newClock()
	l := ratelimit.New(ratelimit.WithLimit(1, time.Hour), ratelimit.WithMaxKeys(2), ratelimit.WithClock(clock.Now))
	require.True(t, l.Allow("a"))
	require.True(t, l.Allow("b"))
	require.False(t, l.Allow("a")) // touch a so b is least recently used

	require.True(t, l.Allow("c")) // evicts b
	assert.Equal(t, 2, l.Len())
	assert.False(t, l.Allow("a"), "a was kept")
	assert.True(t, l.Allow("b"), "b was evicted and starts fresh")
}

func TestConcurrentAllowNeverOverspends(t *testing.T) {
	l := ratelimit.New(ratelimit.WithLimit(10, time.Hour))
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		granted int
	)
	for range 100 {
		wg.Go(func() {
			if l.Allow("k") {
				mu.Lock()
				granted++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	assert.Equal(t, 10, granted)
}

func TestInvalidOptionsFallBackToDefaults(t *testing.T) {
	l := ratelimit.New(ratelimit.WithLimit(0, 0), ratelimit.WithMaxKeys(0))
	assert.True(t, l.Allow("k"))
}

func TestClientKey(t *testing.T) {
	cases := map[string]string{
		"203.0.113.7:51234":                 "203.0.113.7",
		"203.0.113.7":                       "203.0.113.7",
		"[::ffff:203.0.113.7]:443":          "203.0.113.7",
		"[2001:db8:1:2:3:4:5:6]:443":        "2001:db8:1:2::/64",
		"[2001:db8:1:2:ffff:ffff:ffff:1]:1": "2001:db8:1:2::/64",
		"not-an-ip:80":                      "not-an-ip",
		"":                                  "",
	}
	for in, want := range cases {
		assert.Equalf(t, want, ratelimit.ClientKey(in), "ClientKey(%q)", in)
	}
}
