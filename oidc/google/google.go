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
)

// Client exchanges a Google authorization code for a verified identity. The
// OIDC provider is resolved lazily on first use: discovery is a network call
// we must not make at fx graph-construction time.
type Client struct {
	oauth     *oauth2.Config
	issuerURL string
	clientID  string
	now       func() time.Time
	observer  Observer

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
// Google, by operation: "discovery" (on first use and on each retry after a
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
	}
	for _, o := range opts {
		o(c)
	}
	return c
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

	start := time.Now()
	tok, err := c.oauth.Exchange(ctx, code, oauth2.VerifierOption(codeVerifier))
	c.observer.ObserveUpstream("code_exchange", time.Since(start), err)
	if err != nil {
		ue := &oidc.UpstreamError{Reason: oidc.UpstreamReasonExchange, Err: fmt.Errorf("google: code exchange: %w", err)}
		var re *oauth2.RetrieveError
		if errors.As(err, &re) {
			ue.OAuthError = re.ErrorCode
		}
		return oidc.UpstreamIdentity{}, ue
	}

	rawID, ok := tok.Extra("id_token").(string)
	if !ok || rawID == "" {
		return oidc.UpstreamIdentity{}, upstreamErr(oidc.UpstreamReasonIDToken, errors.New("google: token response missing id_token"))
	}

	start = time.Now()
	idToken, err := verifier.Verify(ctx, rawID)
	c.observer.ObserveUpstream("verify_id_token", time.Since(start), err)
	if err != nil {
		return oidc.UpstreamIdentity{}, upstreamErr(oidc.UpstreamReasonIDToken, fmt.Errorf("google: verify id_token: %w", err))
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

	start := time.Now()
	provider, err := coreosoidc.NewProvider(ctx, c.issuerURL)
	c.observer.ObserveUpstream("discovery", time.Since(start), err)
	if err != nil {
		c.backoff = min(max(2*c.backoff, discoveryInitialBackoff), discoveryMaxBackoff)
		c.retryAt = now.Add(c.backoff)
		c.lastErr = upstreamErr(oidc.UpstreamReasonDiscovery, fmt.Errorf("google: discovery (%s): %w", c.issuerURL, err))
		return nil, c.lastErr
	}
	c.verifier = provider.Verifier(&coreosoidc.Config{ClientID: c.clientID})
	c.lastErr, c.backoff = nil, 0
	return c.verifier, nil
}

func upstreamErr(reason string, err error) *oidc.UpstreamError {
	return &oidc.UpstreamError{Reason: reason, Err: err}
}
