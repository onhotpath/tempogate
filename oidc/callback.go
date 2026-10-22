package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
)

const (
	// authCodeTTL bounds the window between this redirect and the downstream
	// /token call. The code travels machine-to-machine right after the
	// browser hop, so it can be short.
	authCodeTTL = 1 * time.Minute

	codeEntropyBytes = 32

	logOpGoogleCallback = "oidc.callback"
)

type callbackInput struct {
	Code   string `query:"code"`
	State  string `query:"state"`
	Cookie string `header:"Cookie"`

	// Google may redirect back with error/error_description instead of a
	// code (e.g. the user declined consent). We forward that to the
	// downstream client rather than dead-ending the browser.
	UpstreamError       string `query:"error"`
	UpstreamErrorReason string `query:"error_description"`
}

// callbackOutput expresses three mutually exclusive responses with one struct:
// a 302 (Location set, no body), a 403 page (Content-Type + Body, no
// Location), or — for protocol errors — an *oauthError returned instead.
// Huma skips empty-string headers, so the unused fields cost nothing on the
// wire. SetCookie drops the state-binding cookie once the state is used.
type callbackOutput struct {
	Status      int
	Location    string `header:"Location"`
	SetCookie   string `header:"Set-Cookie"`
	ContentType string `header:"Content-Type"`
	Body        []byte
}

// UpstreamIdentity is what the Google id_token asserts once its signature
// and standard claims verify. Subject is Google's `sub`. HostedDomain is the
// `hd` claim: Google sets it only for accounts managed by a Google Workspace
// or Cloud organization, so it is empty for consumer accounts, including one
// created for an address at an allowed domain.
type UpstreamIdentity struct {
	Subject       string
	Email         string
	EmailVerified bool
	HostedDomain  string
}

// Reasons an UpstreamError carries. They are what the callback logs about a
// failed Google sign-in: the error text itself is never logged, because a
// token endpoint's error body or a verifier message could echo a code or
// token.
const (
	UpstreamReasonDiscovery = "discovery_unavailable"
	UpstreamReasonExchange  = "code_exchange_failed"
	UpstreamReasonIDToken   = "id_token_invalid"
	UpstreamReasonNonce     = "nonce_mismatch"
	UpstreamReasonClaims    = "claims_incomplete"
)

// UpstreamError classifies an ExchangeAndVerify failure. OAuthError is the
// RFC 6749 §5.2 error code the token endpoint answered with (e.g.
// invalid_grant, invalid_client), when there is one; it is a fixed token,
// safe to log, and the quickest way to tell a bad client secret from a
// replayed code. Timeout marks a call that got no answer in time, which
// points at Google or the network rather than at the login.
type UpstreamError struct {
	Reason     string
	OAuthError string
	Timeout    bool
	Err        error
}

func (e *UpstreamError) Error() string { return e.Err.Error() }

func (e *UpstreamError) Unwrap() error { return e.Err }

// Upstream is the Google leg of the flow, kept behind an interface so this
// package never imports oauth2/go-oidc: the concrete implementation lives in
// the oidc/google provider package and is injected via fx.As, the same
// consumer-defines-the-interface split state/sqlite uses. The handler can
// thus be unit-tested with a fake, and the integration test points the real
// implementation at a mock IdP.
type Upstream interface {
	// ExchangeAndVerify swaps a Google authorization code for an id_token,
	// proving possession of the PKCE codeVerifier, verifies its signature
	// and claims against Google's JWKS, requires its nonce claim to equal
	// nonce, and returns the identity it asserts. Failures should be
	// *UpstreamError so the callback can log why. The domain gates are the
	// callback's concern.
	ExchangeAndVerify(ctx context.Context, code, codeVerifier, nonce string) (UpstreamIdentity, error)
}

// Callback serves GET /callback/google: it completes the upstream half of the
// flow - browser binding check, code exchange, domain allowlist gate, and
// minting our own authorization code - then redirects the browser back to the
// downstream client.
type Callback struct {
	issuer         string
	store          CallbackStore
	upstream       Upstream
	binding        *UpstreamBinding
	logger         *slog.Logger
	allowedDomains map[string]struct{}
	hostedDomains  map[string]struct{}
	now            func() time.Time
	newCode        func() (string, error)
	logins         LoginObserver
}

type CallbackOption func(*Callback)

// WithCallbackClock swaps the clock used for code timestamps and the auth
// request expiry check. For tests.
func WithCallbackClock(now func() time.Time) CallbackOption {
	return func(c *Callback) { c.now = now }
}

// WithCallbackIssuer sets the iss parameter added to every authorization
// response (RFC 9207). It must be the issuer the discovery document
// advertises.
func WithCallbackIssuer(issuer string) CallbackOption {
	return func(c *Callback) { c.issuer = strings.TrimRight(issuer, "/") }
}

// WithAllowedHostedDomains turns on Workspace mode: the comma-separated
// hosted domains the id_token's `hd` claim must match (case-insensitively),
// on top of email_verified and the email-domain allowlist. An email domain
// alone proves nothing about who controls the Google account (anyone can
// create a consumer account for an address they receive mail at), so `hd` is
// the claim Google documents for restricting access to an organization.
// Empty leaves Workspace mode off.
func WithAllowedHostedDomains(raw string) CallbackOption {
	return func(c *Callback) { c.hostedDomains = parseDomains(raw) }
}

// WithCodeGenerator swaps the authorization-code token generator. For tests.
func WithCodeGenerator(fn func() (string, error)) CallbackOption {
	return func(c *Callback) { c.newCode = fn }
}

// WithCallbackLogger sets the operator-facing log sink, so a failed Google
// sign-in (which the user only sees as a generic 502) leaves a reason in the
// logs. Defaults to a discarding logger.
func WithCallbackLogger(l *slog.Logger) CallbackOption {
	return func(c *Callback) { c.logger = l }
}

// WithLoginObserver reports every callback outcome (success or the failure
// reason) to o, e.g. the Prometheus metrics. Nil keeps the no-op default.
func WithLoginObserver(o LoginObserver) CallbackOption {
	return func(c *Callback) {
		if o != nil {
			c.logins = o
		}
	}
}

func NewCallback(
	store CallbackStore,
	upstream Upstream,
	binding *UpstreamBinding,
	allowedDomains string,
	opts ...CallbackOption,
) *Callback {
	c := &Callback{
		store:          store,
		upstream:       upstream,
		binding:        binding,
		logger:         slog.New(slog.DiscardHandler),
		allowedDomains: parseDomains(allowedDomains),
		now:            func() time.Time { return time.Now().UTC() },
		newCode:        randomCode,
		logins:         nopObserver{},
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

func (c *Callback) Register(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID:   "callback-google",
		Method:        http.MethodGet,
		Path:          CallbackPath,
		Summary:       "Google OAuth2 callback (code exchange + domain allowlist + mint auth code)",
		Tags:          []string{"oidc"},
		DefaultStatus: http.StatusFound,
	}, func(ctx context.Context, in *callbackInput) (*callbackOutput, error) {
		return c.handle(ctx, in)
	})
}

func (c *Callback) handle(ctx context.Context, in *callbackInput) (*callbackOutput, error) {
	out, reason, err := c.complete(ctx, in)
	result := loginFailure
	if reason == reasonNone {
		result = loginSuccess
	}
	c.logins.ObserveLogin(result, reason)
	return out, err
}

// complete runs the callback and also returns why it ended the way it did
// (reasonNone on success), so every exit path is observed exactly once.
func (c *Callback) complete(ctx context.Context, in *callbackInput) (*callbackOutput, string, error) {
	if in.State == "" {
		return nil, reasonMissingState, oauthErr(http.StatusBadRequest, "invalid_request", "missing state")
	}

	// Checked before the state is consumed: a request from another browser
	// (a forged callback URL carrying the attacker's own state and code) must
	// not be able to burn the victim's pending login either.
	if !c.binding.boundToBrowser(in.Cookie, in.State) {
		c.logger.WarnContext(ctx, "google callback rejected: state not bound to this browser",
			"op", logOpGoogleCallback,
			"cause", "state_not_bound_to_browser",
		)
		return nil, reasonStateNotBound, oauthErr(http.StatusBadRequest, "invalid_request", "sign-in was not started in this browser")
	}

	ar, err := c.store.ConsumeAuthRequest(ctx, in.State)
	if errors.Is(err, ErrAuthRequestNotFound) {
		return nil, reasonUnknownState, oauthErr(http.StatusBadRequest, "invalid_request", "unknown or already-used state")
	}
	if err != nil {
		return nil, reasonInternal, fmt.Errorf("oidc: consume auth request: %w", err)
	}
	if c.now().After(ar.ExpiresAt) {
		return nil, reasonExpiredRequest, oauthErr(http.StatusBadRequest, "invalid_request", "auth request expired")
	}

	clearBinding := c.binding.clearCookie(in.State).String()

	if in.UpstreamError != "" {
		out, err := c.redirect(ar, clearBinding, url.Values{
			"error":             {in.UpstreamError},
			"error_description": {in.UpstreamErrorReason},
		})
		return out, reasonUpstreamDenied, err
	}

	if in.Code == "" {
		return nil, reasonMissingCode, oauthErr(http.StatusBadRequest, "invalid_request", "missing code")
	}

	id, err := c.upstream.ExchangeAndVerify(ctx, in.Code, c.binding.codeVerifier(in.State), c.binding.nonce(in.State))
	if err == nil && id.Subject == "" {
		err = &UpstreamError{Reason: UpstreamReasonClaims, Err: errors.New("oidc: upstream identity has no subject")}
	}
	if err != nil {
		c.logUpstreamFailure(ctx, err)
		return nil, reasonUpstreamError, oauthErr(http.StatusBadGateway, "upstream_error", "could not complete Google sign-in")
	}

	if refused := c.refusal(id); refused != "" {
		page := forbiddenPage(id.Email)
		page.SetCookie = clearBinding
		return page, refused, nil
	}

	code, err := c.newCode()
	if err != nil {
		return nil, reasonInternal, fmt.Errorf("oidc: generate auth code: %w", err)
	}

	now := c.now()
	if err := c.store.SaveAuthCode(ctx, AuthCode{
		Code:                code,
		ClientID:            ar.ClientID,
		RedirectURI:         ar.RedirectURI,
		Subject:             id.Subject,
		Email:               id.Email,
		Scope:               ar.Scope,
		CodeChallenge:       ar.CodeChallenge,
		CodeChallengeMethod: ar.CodeChallengeMethod,
		Nonce:               ar.Nonce,
		CreatedAt:           now,
		ExpiresAt:           now.Add(authCodeTTL),
	}); err != nil {
		return nil, reasonInternal, fmt.Errorf("oidc: persist auth code: %w", err)
	}

	out, err := c.redirect(ar, clearBinding, url.Values{"code": {code}})
	if err != nil {
		return nil, reasonInternal, err
	}
	return out, reasonNone, nil
}

// refusal names the gate an upstream identity failed, or "" when every gate
// admits it.
func (c *Callback) refusal(id UpstreamIdentity) string {
	switch {
	case !id.EmailVerified:
		return reasonEmailUnverified
	case !emailDomainAllowed(c.allowedDomains, id.Email):
		return reasonDomainNotAllowed
	case !c.hostedDomainAllowed(id.HostedDomain):
		return reasonHostedDomainNotAllowed
	}
	return ""
}

// logUpstreamFailure records why a Google sign-in failed: a warning, since
// the usual causes (an expired or replayed code, a transient Google outage)
// resolve on retry, but a sustained rate means misconfiguration. Only the
// reason category and the OAuth error code are logged, never the error text.
func (c *Callback) logUpstreamFailure(ctx context.Context, err error) {
	cause, oauthCode, timeout := "unknown", "", false
	var ue *UpstreamError
	if errors.As(err, &ue) {
		cause, oauthCode, timeout = ue.Reason, ue.OAuthError, ue.Timeout
	}
	attrs := []any{"op", logOpGoogleCallback, "cause", cause}
	if oauthCode != "" {
		attrs = append(attrs, "oauth_error", oauthCode)
	}
	if timeout {
		attrs = append(attrs, "timeout", true)
	}
	c.logger.WarnContext(ctx, "google sign-in failed", attrs...)
}

// emailDomainAllowed is the OIDC_ALLOWED_DOMAINS gate, shared by the
// callback (at sign-in) and the refresh grant (on every renewal) so the two
// cannot disagree about who is admitted.
func emailDomainAllowed(allowed map[string]struct{}, email string) bool {
	at := strings.LastIndexByte(email, '@')
	if at < 0 || at == len(email)-1 {
		return false
	}
	_, ok := allowed[strings.ToLower(email[at+1:])]
	return ok
}

// hostedDomainAllowed is the Workspace-mode gate. With no hosted domains
// configured it admits everyone (the email allowlist alone decides);
// otherwise the `hd` claim must be present and listed.
func (c *Callback) hostedDomainAllowed(hd string) bool {
	if len(c.hostedDomains) == 0 {
		return true
	}
	_, ok := c.hostedDomains[strings.ToLower(hd)]
	return ok
}

// redirect sends the authorization response back to the client that made
// the request, clearing the browser-binding cookie (setCookie) on the way.
func (c *Callback) redirect(ar AuthRequest, setCookie string, params url.Values) (*callbackOutput, error) {
	loc, err := authorizationResponse(ar.RedirectURI, c.issuer, ar.ClientState, params)
	if err != nil {
		return nil, err
	}
	return &callbackOutput{Status: http.StatusFound, Location: loc, SetCookie: setCookie}, nil
}

func forbiddenPage(email string) *callbackOutput {
	body := `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">` +
		`<title>Access denied</title></head><body>` +
		`<h1>Access denied</h1><p>` + html.EscapeString(email) +
		` is not in an allowed domain for this service.</p></body></html>`
	return &callbackOutput{
		Status:      http.StatusForbidden,
		ContentType: "text/html; charset=utf-8",
		Body:        []byte(body),
	}
}

// parseDomains turns the comma-separated allowlist into a lowercased set. An
// empty config yields an empty set: the gate then fails closed (no email is
// admitted) rather than open.
func parseDomains(raw string) map[string]struct{} {
	set := map[string]struct{}{}
	for _, d := range strings.Split(raw, ",") {
		d = strings.ToLower(strings.TrimSpace(d))
		if d != "" {
			set[d] = struct{}{}
		}
	}
	return set
}

func randomCode() (string, error) {
	b := make([]byte, codeEntropyBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
