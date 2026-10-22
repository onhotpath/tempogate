// Package google is the concrete Google leg of the OIDC flow. It wraps
// golang.org/x/oauth2 (code → id_token) and coreos/go-oidc (id_token
// signature + claims verification) and structurally satisfies
// oidc.Upstream, the consumer-side interface defined in package oidc — the
// same provider/consumer split state/sqlite uses, so package oidc never has
// to import oauth2 or go-oidc.
package google

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	coreosoidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	xgoogle "golang.org/x/oauth2/google"

	"github.com/onhotpath/tempogate/oidc"
)

const (
	scopes = "openid email"

	// Discovery retry spacing. The first retry comes quickly so a blip on
	// the first callback after boot costs one failed login, not many; the
	// cap keeps recovery from a long outage within half a minute while a
	// down IdP sees at most one discovery request per window.
	discoveryInitialBackoff = time.Second
	discoveryMaxBackoff     = 30 * time.Second

	// upstreamTimeout bounds each call to Google: discovery, the code
	// exchange, and id_token verification including a JWKS fetch. Without
	// it the only bound is the browser hanging up, so a stalled Google held
	// /callback/google handlers open indefinitely. Google answers in well
	// under a second; 10s leaves room for a slow network while still
	// failing a login before a user gives up on it. A constant, not a
	// config key: the upstream is always Google, so there is no endpoint
	// that needs a different budget, and a key can be added if one ever does.
	upstreamTimeout = 10 * time.Second

	// Connection setup gets a smaller share of the budget, so an
	// unreachable or black-holed endpoint fails fast and is not mistaken for
	// a slow response.
	upstreamDialTimeout         = 5 * time.Second
	upstreamTLSHandshakeTimeout = 5 * time.Second
)

// Client exchanges a Google authorization code for a verified identity. The
// OIDC provider is resolved lazily on first use: discovery is a network call
// we must not make at fx graph-construction time.
type Client struct {
	oauth      *oauth2.Config
	issuerURL  string
	clientID   string
	now        func() time.Time
	observer   Observer
	timeout    time.Duration
	httpClient *http.Client

	// mu guards the discovery state below and serialises discovery itself,
	// so concurrent callbacks during an outage share one attempt instead of
	// each dialling the IdP.
	mu       sync.Mutex
	verifier *coreosoidc.IDTokenVerifier
	lastErr  error
	retryAt  time.Time
	backoff  time.Duration
}

// Observer is told the latency and outcome of every call tempogate makes to
// Google, by operation. A failure is always an *oidc.UpstreamError, whose
// Timeout flag tells a call that ran out of time from one Google answered.
// The operations are "discovery" (on first use and on each retry after a
// failure, never for a cached failure), "code_exchange" and
// "verify_id_token" (which includes the JWKS fetch on a key-cache miss). The
// metrics package satisfies it; this package never imports Prometheus.
type Observer interface {
	ObserveUpstream(op string, took time.Duration, err error)
}

type nopObserver struct{}

func (nopObserver) ObserveUpstream(string, time.Duration, error) {}

// Option configures a Client.
type Option func(*Client)

// WithObserver reports upstream call latency and errors to o. Nil keeps the
// no-op default.
func WithObserver(o Observer) Option {
	return func(c *Client) {
		if o != nil {
			c.observer = o
		}
	}
}

// WithTimeout replaces the per-call upstream timeout (upstreamTimeout by
// default). For tests, which cannot wait 10s for a stalled mock.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) { c.timeout = d }
}

// WithClock swaps the clock that spaces discovery retries. For tests.
func WithClock(now func() time.Time) Option {
	return func(c *Client) { c.now = now }
}

// New builds the production client. tokenEndpoint and issuerURL are injected
// (not hardcoded to Google) so the end-to-end test can substitute a mock; in
// production they default to Google's real endpoints via config defaults.
// redirectURL must equal the redirect_uri sent at /authorize, or Google
// rejects the exchange.
func New(clientID, clientSecret, tokenEndpoint, redirectURL, issuerURL string, opts ...Option) *Client {
	c := &Client{
		oauth: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint: oauth2.Endpoint{
				AuthURL:   xgoogle.Endpoint.AuthURL,
				TokenURL:  tokenEndpoint,
				AuthStyle: oauth2.AuthStyleInParams,
			},
			RedirectURL: redirectURL,
			Scopes:      strings.Fields(scopes),
		},
		issuerURL: strings.TrimRight(issuerURL, "/"),
		clientID:  clientID,
		now:       time.Now,
		observer:  nopObserver{},
		timeout:   upstreamTimeout,
	}
	for _, o := range opts {
		o(c)
	}
	c.httpClient = newUpstreamHTTPClient(c.timeout)
	return c
}

// newUpstreamHTTPClient is the client every call to Google goes through, in
// place of http.DefaultClient, which has no timeout at all. The overall
// Timeout also covers reading the body, which ResponseHeaderTimeout alone
// would not bound against an endpoint that trickles it.
func newUpstreamHTTPClient(timeout time.Duration) *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.DialContext = (&net.Dialer{Timeout: min(upstreamDialTimeout, timeout), KeepAlive: 30 * time.Second}).DialContext
	t.TLSHandshakeTimeout = min(upstreamTLSHandshakeTimeout, timeout)
	t.ResponseHeaderTimeout = timeout
	return &http.Client{Transport: t, Timeout: timeout}
}

// callContext bounds one upstream call. It carries the upstream client under
// oauth2.HTTPClient, the key both oauth2 and go-oidc read it from, and a
// deadline that bounds the call even where a library does not use that
// client for every wait (go-oidc's Verify waits on a JWKS fetch it runs in
// the background).
func (c *Client) callContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(coreosoidc.ClientContext(ctx, c.httpClient), c.timeout)
}

// timedOut reports whether a call made under callCtx failed because it ran
// out of time. go-oidc flattens some errors with %v, so a call that failed
// once its deadline had passed counts as timed out whatever the error says:
// the client's own timer can fire a moment before the context's.
func timedOut(callCtx context.Context, err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	if dl, ok := callCtx.Deadline(); ok && !time.Now().Before(dl) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// ExchangeAndVerify swaps a Google authorization code for an id_token,
// presenting the PKCE codeVerifier, verifies its signature and claims against
// Google's JWKS, requires its nonce to equal nonce, and returns the identity
// it asserts: the stable `sub`, the email with its `email_verified` flag, and
// the Workspace hosted domain (`hd`, empty for consumer accounts). The gates
// on those claims are the callback's job, not this client's. Every failure is
// an *oidc.UpstreamError.
func (c *Client) ExchangeAndVerify(ctx context.Context, code, codeVerifier, nonce string) (oidc.UpstreamIdentity, error) {
	// Discover first: without a verifier the code could not be checked, so
	// there is no point redeeming it.
	verifier, err := c.idVerifier(ctx)
	if err != nil {
		return oidc.UpstreamIdentity{}, err
	}

	tok, err := c.exchange(ctx, code, codeVerifier)
	if err != nil {
		return oidc.UpstreamIdentity{}, err
	}

	rawID, ok := tok.Extra("id_token").(string)
	if !ok || rawID == "" {
		return oidc.UpstreamIdentity{}, upstreamErr(oidc.UpstreamReasonIDToken, errors.New("google: token response missing id_token"))
	}

	idToken, err := c.verify(ctx, verifier, rawID)
	if err != nil {
		return oidc.UpstreamIdentity{}, err
	}
	// go-oidc leaves the nonce to the caller. A missing or different nonce
	// means the id_token was minted for some other authorization request.
	if nonce == "" || subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(nonce)) != 1 {
		return oidc.UpstreamIdentity{}, upstreamErr(oidc.UpstreamReasonNonce, errors.New("google: id_token nonce does not match the request"))
	}

	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		HostedDomain  string `json:"hd"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return oidc.UpstreamIdentity{}, upstreamErr(oidc.UpstreamReasonIDToken, fmt.Errorf("google: decode id_token claims: %w", err))
	}
	if idToken.Subject == "" {
		return oidc.UpstreamIdentity{}, upstreamErr(oidc.UpstreamReasonClaims, errors.New("google: id_token has no sub claim"))
	}
	if claims.Email == "" {
		return oidc.UpstreamIdentity{}, upstreamErr(oidc.UpstreamReasonClaims, errors.New("google: id_token has no email claim"))
	}
	return oidc.UpstreamIdentity{
		Subject:       idToken.Subject,
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
		HostedDomain:  claims.HostedDomain,
	}, nil
}

func (c *Client) exchange(ctx context.Context, code, codeVerifier string) (*oauth2.Token, error) {
	callCtx, cancel := c.callContext(ctx)
	defer cancel()
	start := time.Now()
	tok, err := c.oauth.Exchange(callCtx, code, oauth2.VerifierOption(codeVerifier))
	if err == nil {
		c.observer.ObserveUpstream("code_exchange", time.Since(start), nil)
		return tok, nil
	}
	ue := c.callErr(callCtx, oidc.UpstreamReasonExchange, fmt.Errorf("google: code exchange: %w", err))
	var re *oauth2.RetrieveError
	if errors.As(err, &re) {
		ue.OAuthError = re.ErrorCode
	}
	c.observer.ObserveUpstream("code_exchange", time.Since(start), ue)
	return nil, ue
}

func (c *Client) verify(ctx context.Context, verifier *coreosoidc.IDTokenVerifier, rawID string) (*coreosoidc.IDToken, error) {
	callCtx, cancel := c.callContext(ctx)
	defer cancel()
	start := time.Now()
	idToken, err := verifier.Verify(callCtx, rawID)
	if err == nil {
		c.observer.ObserveUpstream("verify_id_token", time.Since(start), nil)
		return idToken, nil
	}
	ue := c.callErr(callCtx, oidc.UpstreamReasonIDToken, fmt.Errorf("google: verify id_token: %w", err))
	c.observer.ObserveUpstream("verify_id_token", time.Since(start), ue)
	return nil, ue
}

// callErr classifies the failure of a call made under callCtx.
func (c *Client) callErr(callCtx context.Context, reason string, err error) *oidc.UpstreamError {
	ue := upstreamErr(reason, err)
	ue.Timeout = timedOut(callCtx, err)
	return ue
}

// idVerifier lazily performs OIDC discovery against issuerURL. Only success
// is cached: a failure is remembered just until a backoff window (doubling
// up to discoveryMaxBackoff) elapses, so a transient outage on the first
// callback after boot heals by itself while a hard outage costs the IdP at
// most one discovery request per window.
func (c *Client) idVerifier(ctx context.Context) (*coreosoidc.IDTokenVerifier, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.verifier != nil {
		return c.verifier, nil
	}
	now := c.now()
	if c.lastErr != nil && now.Before(c.retryAt) {
		return nil, c.lastErr
	}

	// The provider keeps this context (minus its deadline) for the JWKS
	// fetches it makes later, so those go through the upstream client too.
	callCtx, cancel := c.callContext(ctx)
	defer cancel()
	start := time.Now()
	provider, err := coreosoidc.NewProvider(callCtx, c.issuerURL)
	if err != nil {
		// A timeout is backed off like any other failure and, like any
		// other failure, never cached past the backoff window.
		ue := c.callErr(callCtx, oidc.UpstreamReasonDiscovery, fmt.Errorf("google: discovery (%s): %w", c.issuerURL, err))
		c.observer.ObserveUpstream("discovery", time.Since(start), ue)
		c.backoff = min(max(2*c.backoff, discoveryInitialBackoff), discoveryMaxBackoff)
		c.retryAt = now.Add(c.backoff)
		c.lastErr = ue
		return nil, c.lastErr
	}
	c.observer.ObserveUpstream("discovery", time.Since(start), nil)
	c.verifier = provider.Verifier(&coreosoidc.Config{ClientID: c.clientID})
	c.lastErr, c.backoff = nil, 0
	return c.verifier, nil
}

func upstreamErr(reason string, err error) *oidc.UpstreamError {
	return &oidc.UpstreamError{Reason: reason, Err: err}
}
