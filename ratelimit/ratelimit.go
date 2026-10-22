// Package ratelimit is a small in-process, per-key token-bucket limiter with
// bounded memory. It backs throttles that only need to hold on a single
// replica (brute-force guards on human-facing forms); it is not a
// distributed quota.
package ratelimit

import (
	"container/list"
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	defaultLimit   = 10
	defaultPer     = time.Minute
	defaultMaxKeys = 10000
)

// Limiter holds one token bucket per key. Each bucket starts full at the
// burst size and refills continuously at burst/per. Memory is capped by
// MaxKeys: past it the least recently used bucket is dropped, which at worst
// hands that key a fresh budget. A bucket idle long enough to refill is
// indistinguishable from a fresh one, so the eviction normally loses nothing.
type Limiter struct {
	mu      sync.Mutex
	burst   float64
	rate    float64 // tokens per second
	maxKeys int
	now     func() time.Time
	order   *list.List // front = most recently used
	buckets map[string]*list.Element
}

type bucket struct {
	key    string
	tokens float64
	last   time.Time
}

// Option configures a Limiter.
type Option func(*Limiter)

// WithLimit allows n attempts per window per key, as a burst of n that
// refills evenly over per. Non-positive values keep the default.
func WithLimit(n int, per time.Duration) Option {
	return func(l *Limiter) {
		if n > 0 && per > 0 {
			l.burst = float64(n)
			l.rate = float64(n) / per.Seconds()
		}
	}
}

// WithMaxKeys caps how many keys are tracked at once. Non-positive keeps the
// default.
func WithMaxKeys(n int) Option {
	return func(l *Limiter) {
		if n > 0 {
			l.maxKeys = n
		}
	}
}

// WithClock swaps the clock. For tests.
func WithClock(now func() time.Time) Option {
	return func(l *Limiter) { l.now = now }
}

// New builds a Limiter; by default 10 attempts per minute per key, tracking
// at most 10000 keys.
func New(opts ...Option) *Limiter {
	l := &Limiter{
		maxKeys: defaultMaxKeys,
		now:     time.Now,
		order:   list.New(),
		buckets: map[string]*list.Element{},
	}
	WithLimit(defaultLimit, defaultPer)(l)
	for _, o := range opts {
		o(l)
	}
	return l
}

// Allow spends one token for key and reports whether one was available.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.bucket(key)
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Refund gives back one token previously spent by Allow, never beyond the
// burst. Callers that only want to count failed attempts spend a token up
// front (so parallel requests cannot all slip past a check) and refund it
// once the attempt turns out to be legitimate.
func (l *Limiter) Refund(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.buckets[key]
	if !ok {
		return
	}
	b := e.Value.(*bucket)
	b.tokens = min(b.tokens+1, l.burst)
}

// Len reports how many keys are currently tracked.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// bucket returns key's bucket, refilled to now, creating it (and evicting
// the least recently used one past maxKeys) when absent. Caller holds mu.
func (l *Limiter) bucket(key string) *bucket {
	now := l.now()
	if e, ok := l.buckets[key]; ok {
		l.order.MoveToFront(e)
		b := e.Value.(*bucket)
		if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
			b.tokens = min(b.tokens+elapsed*l.rate, l.burst)
		}
		b.last = now
		return b
	}
	for len(l.buckets) >= l.maxKeys {
		oldest := l.order.Back()
		l.order.Remove(oldest)
		delete(l.buckets, oldest.Value.(*bucket).key)
	}
	b := &bucket{key: key, tokens: l.burst, last: now}
	l.buckets[key] = l.order.PushFront(b)
	return b
}

// ClientKey turns an http.Request RemoteAddr ("host:port") into a limiter
// key. IPv4 (and IPv4-mapped IPv6) addresses key on the address; IPv6 keys
// on the /64, since a single client routinely holds a whole /64 and could
// otherwise rotate through it. Unparseable input is returned as the host
// part verbatim so it still gets a bucket of its own.
func ClientKey(remoteAddr string) string {
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return addr.String()
	}
	return netip.PrefixFrom(addr, 64).Masked().String()
}
