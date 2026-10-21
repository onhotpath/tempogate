package oidc

import (
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/onhotpath/tempogate/ratelimit"
)

// RateLimits is how many requests per minute one client address may send to
// each throttled endpoint. These are the unauthenticated endpoints that
// write a row per request or check a credential; 0 leaves one unthrottled.
type RateLimits struct {
	Authorize           int
	DeviceAuthorization int
	// DeviceVerification is POST /device, the user_code entry form.
	DeviceVerification int
	Token              int
}

// Validate rejects negative limits, which have no meaning.
func (l RateLimits) Validate() error {
	for name, n := range map[string]int{
		"authorize":            l.Authorize,
		"device_authorization": l.DeviceAuthorization,
		"device_verification":  l.DeviceVerification,
		"token":                l.Token,
	} {
		if n < 0 {
			return fmt.Errorf("oidc: rate limit for %s must not be negative, got %d", name, n)
		}
	}
	return nil
}

// endpointLimit is one throttled operation's limiter. html marks the
// browser-facing form, which gets a readable body instead of OAuth JSON.
// label names the endpoint to the RateLimitObserver.
type endpointLimit struct {
	limiter    *ratelimit.Limiter
	retryAfter string
	html       bool
	label      string
}

// RateLimiter is a Huma middleware that throttles the operations named in
// RateLimits per client address. Its state is in-process: with several
// replicas each enforces its own budget.
type RateLimiter struct {
	limits         RateLimits
	trustedProxies []netip.Prefix
	now            func() time.Time
	observer       RateLimitObserver
	endpoints      map[string]endpointLimit // by Huma operation ID
}

type RateLimiterOption func(*RateLimiter)

// WithRateLimits sets the per-endpoint budgets. Without it nothing is
// throttled.
func WithRateLimits(l RateLimits) RateLimiterOption {
	return func(r *RateLimiter) { r.limits = l }
}

// WithTrustedProxies names the reverse proxies whose X-Forwarded-For is
// believed (see ParseTrustedProxies).
func WithTrustedProxies(p []netip.Prefix) RateLimiterOption {
	return func(r *RateLimiter) { r.trustedProxies = p }
}

// WithRateLimiterClock swaps the clock. For tests.
func WithRateLimiterClock(now func() time.Time) RateLimiterOption {
	return func(r *RateLimiter) { r.now = now }
}

// WithRateLimitObserver reports every rejected request to o, e.g. the
// Prometheus metrics. Nil keeps the no-op default.
func WithRateLimitObserver(o RateLimitObserver) RateLimiterOption {
	return func(r *RateLimiter) {
		if o != nil {
			r.observer = o
		}
	}
}

func NewRateLimiter(opts ...RateLimiterOption) *RateLimiter {
	r := &RateLimiter{now: time.Now, observer: nopObserver{}}
	for _, o := range opts {
		o(r)
	}
	r.endpoints = map[string]endpointLimit{}
	for id, l := range map[string]struct {
		perMinute int
		html      bool
		label     string
	}{
		"authorize":            {r.limits.Authorize, false, "authorize"},
		"device-authorization": {r.limits.DeviceAuthorization, false, "device_authorization"},
		"device-ui-submit":     {r.limits.DeviceVerification, true, "device_verification"},
		"token":                {r.limits.Token, false, "token"},
	} {
		if l.perMinute <= 0 {
			continue
		}
		r.endpoints[id] = endpointLimit{
			limiter: ratelimit.New(
				ratelimit.WithLimit(l.perMinute, time.Minute),
				ratelimit.WithClock(r.now),
			),
			// The limiter does not expose a bucket's wait, so advertise
			// the time one token takes to refill: exact for a caller that
			// just ran dry, which is the one being told to wait.
			retryAfter: strconv.Itoa(max(1, int(math.Ceil(60/float64(l.perMinute))))),
			html:       l.html,
			label:      l.label,
		}
	}
	return r
}

// Middleware rejects a request over its client's budget with 429 and
// Retry-After before the body is read or the handler runs.
func (r *RateLimiter) Middleware(ctx huma.Context, next func(huma.Context)) {
	op := ctx.Operation()
	if op == nil {
		next(ctx)
		return
	}
	e, ok := r.endpoints[op.OperationID]
	if !ok || e.limiter.Allow(r.clientKey(ctx.RemoteAddr(), forwardedFor(ctx))) {
		next(ctx)
		return
	}

	r.observer.ObserveRateLimited(e.label)
	ctx.SetHeader("Retry-After", e.retryAfter)
	ctx.SetHeader("Cache-Control", "no-store")
	var body []byte
	if e.html {
		ctx.SetHeader("Content-Type", "text/plain; charset=utf-8")
		body = []byte("Too many attempts from your network. Wait a minute and try again.\n")
	} else {
		ctx.SetHeader("Content-Type", "application/json")
		// RFC 6749 has no rate-limit error code; temporarily_unavailable
		// (§4.1.2.1) is the registered one closest in meaning.
		body, _ = json.Marshal(oauthErr(http.StatusTooManyRequests, "temporarily_unavailable",
			"too many requests from this address; retry after "+e.retryAfter+" seconds"))
	}
	ctx.SetStatus(http.StatusTooManyRequests)
	_, _ = ctx.BodyWriter().Write(body)
}

// clientKey picks the address a request is budgeted under. A peer that is
// not a trusted proxy is the client, whatever headers it sends. Behind
// trusted proxies the client is the rightmost X-Forwarded-For entry that
// is not itself a trusted proxy: every proxy appends the address it saw,
// so entries left of that are client-controlled and cannot be believed.
func (r *RateLimiter) clientKey(remoteAddr, forwardedFor string) string {
	peer := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		peer = h
	}
	if !r.trusted(peer) || forwardedFor == "" {
		return ratelimit.ClientKey(peer)
	}

	client := peer
	hops := strings.Split(forwardedFor, ",")
	for i := len(hops) - 1; i >= 0; i-- {
		addr, ok := parseForwardedAddr(hops[i])
		if !ok {
			// Garbage cannot have come from a trusted proxy; stop at the
			// last address one vouched for.
			break
		}
		client = addr.String()
		if !r.trusted(client) {
			break
		}
	}
	return ratelimit.ClientKey(client)
}

func (r *RateLimiter) trusted(host string) bool {
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, p := range r.trustedProxies {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// forwardedFor joins every X-Forwarded-For header into one list: a proxy
// may add its own header line rather than extend the existing one.
func forwardedFor(ctx huma.Context) string {
	var hops []string
	ctx.EachHeader(func(name, value string) {
		if strings.EqualFold(name, "X-Forwarded-For") {
			hops = append(hops, value)
		}
	})
	return strings.Join(hops, ",")
}

// parseForwardedAddr reads one X-Forwarded-For entry, which some proxies
// write with a port ("203.0.113.7:51234", "[2001:db8::1]:443").
func parseForwardedAddr(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.Unmap(), true
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap(), true
	}
	return netip.Addr{}, false
}

// ParseTrustedProxies parses HTTP_TRUSTED_PROXIES: comma-separated CIDRs or
// bare addresses (a single host). Empty trusts no proxy.
func ParseTrustedProxies(v string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, raw := range strings.Split(v, ",") {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if strings.Contains(s, "/") {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				return nil, fmt.Errorf("oidc: trusted proxy %q: %w", s, err)
			}
			out = append(out, p.Masked())
			continue
		}
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("oidc: trusted proxy %q is not an address or CIDR: %w", s, err)
		}
		addr = addr.Unmap()
		out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return out, nil
}
