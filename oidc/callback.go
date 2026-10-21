package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
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
)

type callbackInput struct {
	Code  string `query:"code"`
	State string `query:"state"`

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
// wire.
type callbackOutput struct {
	Status      int
	Location    string `header:"Location"`
	ContentType string `header:"Content-Type"`
	Body        []byte
}

// Upstream is the Google leg of the flow, kept behind an interface so this
// package never imports oauth2/go-oidc: the concrete implementation lives in
// the oidc/google provider package and is injected via fx.As, the same
// consumer-defines-the-interface split state/sqlite uses. The handler can
// thus be unit-tested with a fake, and the integration test points the real
// implementation at a mock IdP.
type Upstream interface {
	// ExchangeAndVerify swaps a Google authorization code for an id_token,
	// verifies its signature and claims against Google's JWKS, and returns
	// the email it asserts. emailVerified reflects the token's
	// `email_verified` claim — an unverified email must not be trusted by
	// the domain gate even if the domain matches.
	ExchangeAndVerify(ctx context.Context, code string) (email string, emailVerified bool, err error)
}

// Callback serves GET /callback/google: it completes the upstream half of the
// flow — code exchange, domain allowlist gate, and minting our own
// authorization code — then redirects the browser back to the downstream
// client.
type Callback struct {
	store          CallbackStore
	upstream       Upstream
	allowedDomains map[string]struct{}
	now            func() time.Time
	newCode        func() (string, error)
}

type CallbackOption func(*Callback)

// WithCallbackClock swaps the clock used for code timestamps and the auth
// request expiry check. For tests.
func WithCallbackClock(now func() time.Time) CallbackOption {
	return func(c *Callback) { c.now = now }
}

// WithCodeGenerator swaps the authorization-code token generator. For tests.
func WithCodeGenerator(fn func() (string, error)) CallbackOption {
	return func(c *Callback) { c.newCode = fn }
}

func NewCallback(store CallbackStore, upstream Upstream, allowedDomains string, opts ...CallbackOption) *Callback {
	c := &Callback{
		store:          store,
		upstream:       upstream,
		allowedDomains: parseDomains(allowedDomains),
		now:            func() time.Time { return time.Now().UTC() },
		newCode:        randomCode,
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
	if in.State == "" {
		return nil, oauthErr(http.StatusBadRequest, "invalid_request", "missing state")
	}

	ar, err := c.store.ConsumeAuthRequest(ctx, in.State)
	if errors.Is(err, ErrAuthRequestNotFound) {
		return nil, oauthErr(http.StatusBadRequest, "invalid_request", "unknown or already-used state")
	}
	if err != nil {
		return nil, fmt.Errorf("oidc: consume auth request: %w", err)
	}
	if c.now().After(ar.ExpiresAt) {
		return nil, oauthErr(http.StatusBadRequest, "invalid_request", "auth request expired")
	}

	if in.UpstreamError != "" {
		return redirectTo(ar.RedirectURI, url.Values{
			"error":             {in.UpstreamError},
			"error_description": {in.UpstreamErrorReason},
			"state":             {ar.ClientState},
		})
	}

	if in.Code == "" {
		return nil, oauthErr(http.StatusBadRequest, "invalid_request", "missing code")
	}

	email, verified, err := c.upstream.ExchangeAndVerify(ctx, in.Code)
	if err != nil {
		return nil, oauthErr(http.StatusBadGateway, "upstream_error", "could not complete Google sign-in")
	}

	if !verified || !emailDomainAllowed(c.allowedDomains, email) {
		return forbiddenPage(email), nil
	}

	code, err := c.newCode()
	if err != nil {
		return nil, fmt.Errorf("oidc: generate auth code: %w", err)
	}

	now := c.now()
	if err := c.store.SaveAuthCode(ctx, AuthCode{
		Code:                code,
		ClientID:            ar.ClientID,
		RedirectURI:         ar.RedirectURI,
		Email:               email,
		Scope:               ar.Scope,
		CodeChallenge:       ar.CodeChallenge,
		CodeChallengeMethod: ar.CodeChallengeMethod,
		Nonce:               ar.Nonce,
		CreatedAt:           now,
		ExpiresAt:           now.Add(authCodeTTL),
	}); err != nil {
		return nil, fmt.Errorf("oidc: persist auth code: %w", err)
	}

	return redirectTo(ar.RedirectURI, url.Values{
		"code":  {code},
		"state": {ar.ClientState},
	})
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

// redirectTo merges params into the client's redirect URI and returns a 302.
// The URI was matched exactly against the client's registration at
// /authorize; the Location is rebuilt from the parsed url.URL with the query
// set through url.Values rather than by string concatenation, so a parameter
// value can never change the scheme, host or path the browser is sent to.
func redirectTo(redirectURI string, params url.Values) (*callbackOutput, error) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return nil, fmt.Errorf("oidc: parse redirect_uri: %w", err)
	}
	q := u.Query()
	for k, vs := range params {
		q.Set(k, vs[0])
	}
	u.RawQuery = q.Encode()
	return &callbackOutput{Status: http.StatusFound, Location: u.String()}, nil
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
