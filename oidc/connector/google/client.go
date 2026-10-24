// Package google is the Google connector: the upstream leg of a login, behind
// oidc.Connector. It wraps golang.org/x/oauth2 (code → id_token) and
// coreos/go-oidc (id_token signature + claims verification), so package oidc
// never has to import either, and the lean CLI never links them.
package google

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	coreosoidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	xgoogle "golang.org/x/oauth2/google"

	"github.com/onhotpath/tempogate/oidc"
	"github.com/onhotpath/tempogate/oidc/connector/upstreamhttp"
)

const (
	// scopes is the upstream scope set. `email` is required so the server
	// can run the domain allowlist check.
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
	oauth      *oauth2.Config
	issuerURL  string
	clientID   string
	now        func() time.Time
	telemetry  *oidc.Telemetry
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

// Option configures a Client.
type Option func(*Client)

// WithTelemetry records upstream call latency and errors, by operation:
// "discovery" (on first use and on each retry after a failure, never for a
// cached failure), "code_exchange" and "verify_id_token" (which includes the
// JWKS fetch on a key-cache miss). Nil keeps recording nothing.
func WithTelemetry(t *oidc.Telemetry) Option {
	return func(c *Client) {
		if t != nil {
			c.telemetry = t
		}
	}
}

// WithTimeout replaces the per-call upstream timeout
// (upstreamhttp.DefaultTimeout by default). For tests, which cannot wait 10s for a stalled mock.
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
func New(clientID, clientSecret, tokenEndpoint, issuerURL string, opts ...Option) *Client {
	c := &Client{
		oauth: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint: oauth2.Endpoint{
				AuthURL:   xgoogle.Endpoint.AuthURL,
				TokenURL:  tokenEndpoint,
				AuthStyle: oauth2.AuthStyleInParams,
			},
			Scopes: strings.Fields(scopes),
		},
		issuerURL: strings.TrimRight(issuerURL, "/"),
		clientID:  clientID,
		now:       time.Now,
		telemetry: &oidc.Telemetry{},
		timeout:   upstreamhttp.DefaultTimeout,
	}
	for _, o := range opts {
		o(c)
	}
	c.httpClient = upstreamhttp.NewClient(c.timeout)
	return c
}

// callContext bounds one upstream call. It carries the upstream client under
// oauth2.HTTPClient, the key both oauth2 and go-oidc read it from, and a
// deadline that bounds the call even where a library does not use that
// client for every wait (go-oidc's Verify waits on a JWKS fetch it runs in
// the background).
func (c *Client) callContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(coreosoidc.ClientContext(ctx, c.httpClient), c.timeout)
}

// ExchangeAndVerify swaps a Google authorization code for an id_token,
// presenting the PKCE codeVerifier and the redirectURI the code was issued
// for, verifies its signature and claims against Google's JWKS, requires its
// nonce to equal nonce, and returns the identity it asserts: the stable
// `sub`, the email with its `email_verified` flag, and the Workspace hosted
// domain (`hd`, empty for consumer accounts). The gates on those claims are
// the Connector's and the server's job, not this client's. Every failure is
// an *oidc.UpstreamError.
func (c *Client) ExchangeAndVerify(ctx context.Context, code, redirectURI, codeVerifier, nonce string) (Identity, error) {
	// Discover first: without a verifier the code could not be checked, so
	// there is no point redeeming it.
	verifier, err := c.idVerifier(ctx)
	if err != nil {
		return Identity{}, err
	}

	tok, err := c.exchange(ctx, code, redirectURI, codeVerifier)
	if err != nil {
		return Identity{}, err
	}

	rawID, ok := tok.Extra("id_token").(string)
	if !ok || rawID == "" {
		return Identity{}, upstreamErr(oidc.UpstreamReasonIDToken, errors.New("google: token response missing id_token"))
	}

	idToken, err := c.verify(ctx, verifier, rawID)
	if err != nil {
		return Identity{}, err
	}
	// go-oidc leaves the nonce to the caller. A missing or different nonce
	// means the id_token was minted for some other authorization request.
	if nonce == "" || subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(nonce)) != 1 {
		return Identity{}, upstreamErr(oidc.UpstreamReasonNonce, errors.New("google: id_token nonce does not match the request"))
	}

	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		HostedDomain  string `json:"hd"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return Identity{}, upstreamErr(oidc.UpstreamReasonIDToken, fmt.Errorf("google: decode id_token claims: %w", err))
	}
	if idToken.Subject == "" {
		return Identity{}, upstreamErr(oidc.UpstreamReasonClaims, errors.New("google: id_token has no sub claim"))
	}
	if claims.Email == "" {
		return Identity{}, upstreamErr(oidc.UpstreamReasonClaims, errors.New("google: id_token has no email claim"))
	}
	return Identity{
		Subject:       idToken.Subject,
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
		HostedDomain:  claims.HostedDomain,
	}, nil
}

func (c *Client) exchange(ctx context.Context, code, redirectURI, codeVerifier string) (*oauth2.Token, error) {
	ctx, done := c.telemetry.StartUpstream(ctx, "code_exchange")
	callCtx, cancel := c.callContext(ctx)
	defer cancel()
	tok, err := c.oauth.Exchange(callCtx, code,
		oauth2.SetAuthURLParam("redirect_uri", redirectURI),
		oauth2.VerifierOption(codeVerifier))
	if err == nil {
		done(nil)
		return tok, nil
	}
	ue := c.callErr(callCtx, oidc.UpstreamReasonExchange, fmt.Errorf("google: code exchange: %w", err))
	var re *oauth2.RetrieveError
	if errors.As(err, &re) {
		ue.OAuthError = re.ErrorCode
	}
	done(ue)
	return nil, ue
}

func (c *Client) verify(ctx context.Context, verifier *coreosoidc.IDTokenVerifier, rawID string) (*coreosoidc.IDToken, error) {
	ctx, done := c.telemetry.StartUpstream(ctx, "verify_id_token")
	callCtx, cancel := c.callContext(ctx)
	defer cancel()
	idToken, err := verifier.Verify(callCtx, rawID)
	if err == nil {
		done(nil)
		return idToken, nil
	}
	ue := c.callErr(callCtx, oidc.UpstreamReasonIDToken, fmt.Errorf("google: verify id_token: %w", err))
	done(ue)
	return nil, ue
}

// callErr classifies the failure of a call made under callCtx.
func (c *Client) callErr(callCtx context.Context, reason string, err error) *oidc.UpstreamError {
	ue := upstreamErr(reason, err)
	ue.Timeout = upstreamhttp.TimedOut(callCtx, err)
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

	// The provider keeps the HTTP client this context carries (not the
	// context itself) for the JWKS fetches it makes later, so those go
	// through the upstream client too.
	ctx, done := c.telemetry.StartUpstream(ctx, "discovery")
	callCtx, cancel := c.callContext(ctx)
	defer cancel()
	provider, err := coreosoidc.NewProvider(callCtx, c.issuerURL)
	if err != nil {
		// A timeout is backed off like any other failure and, like any
		// other failure, never cached past the backoff window.
		ue := c.callErr(callCtx, oidc.UpstreamReasonDiscovery, fmt.Errorf("google: discovery (%s): %w", c.issuerURL, err))
		done(ue)
		c.backoff = min(max(2*c.backoff, discoveryInitialBackoff), discoveryMaxBackoff)
		c.retryAt = now.Add(c.backoff)
		c.lastErr = ue
		return nil, c.lastErr
	}
	done(nil)
	c.verifier = provider.Verifier(&coreosoidc.Config{ClientID: c.clientID})
	c.lastErr, c.backoff = nil, 0
	return c.verifier, nil
}

func upstreamErr(reason string, err error) *oidc.UpstreamError {
	return &oidc.UpstreamError{Reason: reason, Err: err}
}
