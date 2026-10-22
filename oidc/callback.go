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

	"github.com/onhotpath/tempogate/internal/clock"
)

const (
	// authCodeTTL bounds the window between this redirect and the downstream
	// /token call. The code travels machine-to-machine right after the
	// browser hop, so it can be short.
	authCodeTTL = 1 * time.Minute

	// completeTimeout bounds a connector's whole Complete, however many
	// upstream calls it makes, below the server's 30s WriteTimeout: a
	// stalled upstream then gets the user a 502 rather than a reset
	// connection.
	completeTimeout = 25 * time.Second

	codeEntropyBytes = 32

	logOpCallback = "oidc.callback"
)

// callbackInput takes the connector's response parameters whole (Resolve):
// which ones matter is the connector's business, not the route's.
type callbackInput struct {
	Connector string `path:"connector"`
	Cookie    string `header:"Cookie"`

	params url.Values
}

func (in *callbackInput) Resolve(ctx huma.Context) []error {
	u := ctx.URL()
	in.params = u.Query()
	return nil
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

// Callback serves GET /callback/{connector}: it completes the upstream half
// of the flow - browser binding check, the connector's verification of the
// upstream response, the shared admission gates, and minting our own
// authorization code - then redirects the browser back to the downstream
// client.
type Callback struct {
	issuer          string
	store           CallbackStore
	connectors      *Connectors
	binding         *UpstreamBinding
	logger          *slog.Logger
	allowedDomains  map[string]struct{}
	now             func() time.Time
	newCode         func() (string, error)
	completeTimeout time.Duration
	logins          LoginObserver
	authorizer      PermissionResolver
	authz           AuthzObserver
}

type CallbackOption func(*Callback)

// WithCallbackClock swaps the clock used for code timestamps and the auth
// request expiry check. For tests.
func WithCallbackClock(now func() time.Time) CallbackOption {
	return func(c *Callback) { c.now = now }
}

// WithCallbackIssuer sets the iss parameter added to every authorization
// response (RFC 9207) and the base of each connector's redirect URI. It must
// be the issuer the discovery document advertises.
func WithCallbackIssuer(issuer string) CallbackOption {
	return func(c *Callback) { c.issuer = strings.TrimRight(issuer, "/") }
}

// WithCodeGenerator swaps the authorization-code token generator. For tests.
func WithCodeGenerator(fn func() (string, error)) CallbackOption {
	return func(c *Callback) { c.newCode = fn }
}

// WithCompleteTimeout replaces the overall bound on a connector's Complete
// (25s by default). For tests.
func WithCompleteTimeout(d time.Duration) CallbackOption {
	return func(c *Callback) { c.completeTimeout = d }
}

// WithCallbackLogger sets the operator-facing log sink, so a failed upstream
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

// WithCallbackPermissionResolver sets the resolver consulted once every admission
// gate has passed: a person it grants nothing is sent back to the client
// with access_denied and no code is minted. Without it nobody gets a code
// (fail closed).
func WithCallbackPermissionResolver(a PermissionResolver) CallbackOption {
	return func(c *Callback) {
		if a != nil {
			c.authorizer = a
		}
	}
}

// WithCallbackAuthzObserver reports every sign-in refused because the
// resolver granted nothing. Nil keeps the no-op default.
func WithCallbackAuthzObserver(o AuthzObserver) CallbackOption {
	return func(c *Callback) {
		if o != nil {
			c.authz = o
		}
	}
}

func NewCallback(
	store CallbackStore,
	connectors *Connectors,
	binding *UpstreamBinding,
	allowedDomains string,
	opts ...CallbackOption,
) *Callback {
	c := &Callback{
		store:           store,
		connectors:      connectors,
		binding:         binding,
		logger:          slog.New(slog.DiscardHandler),
		allowedDomains:  ParseDomains(allowedDomains),
		now:             clock.Now,
		newCode:         randomCode,
		completeTimeout: completeTimeout,
		logins:          nopObserver{},
		authorizer:      denyAll{},
		authz:           nopObserver{},
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Register serves every connector's callback from one route. Only GET is
// registered: a connector whose upstream answers with a POST (SAML) needs a
// binding cookie a cross-site POST carries, which is not built yet, so
// NewConnectors refuses one.
func (c *Callback) Register(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID:   "callback",
		Method:        http.MethodGet,
		Path:          CallbackPathPrefix + "{connector}",
		Summary:       "Upstream sign-in callback (verify the upstream response + admission gates + mint auth code)",
		Tags:          []string{"oidc"},
		DefaultStatus: http.StatusFound,
	}, func(ctx context.Context, in *callbackInput) (*callbackOutput, error) {
		return c.handle(ctx, in)
	})
}

func (c *Callback) handle(ctx context.Context, in *callbackInput) (*callbackOutput, error) {
	conn, ok := c.connectors.Lookup(in.Connector)
	if !ok {
		// Not a sign-in at all, as for any unknown route: nothing observed.
		return nil, huma.Error404NotFound("no such connector")
	}
	out, reason, err := c.complete(ctx, conn, in)
	result := loginFailure
	if reason == reasonNone {
		result = loginSuccess
	}
	c.logins.ObserveLogin(result, reason)
	return out, err
}

// complete runs the callback and also returns why it ended the way it did
// (reasonNone on success), so every exit path is observed exactly once.
func (c *Callback) complete(ctx context.Context, conn Connector, in *callbackInput) (*callbackOutput, string, error) {
	id := conn.ID()
	state := in.params.Get(conn.Flow().StateParam)
	if state == "" {
		return nil, reasonMissingState, oauthErr(http.StatusBadRequest, "invalid_request", "missing state")
	}

	// Checked before the state is consumed: a request from another browser
	// (a forged callback URL carrying the attacker's own state and code) must
	// not be able to burn the victim's pending login either. The binding is
	// derived with the connector id, so a state minted for another connector
	// fails here too, before this connector's upstream is ever called.
	if !c.binding.boundToBrowser(in.Cookie, id, state) {
		c.logger.WarnContext(ctx, id+" callback rejected: state not bound to this browser",
			"op", logOpCallback,
			"connector", id,
			"cause", "state_not_bound_to_browser",
		)
		return nil, reasonStateNotBound, oauthErr(http.StatusBadRequest, "invalid_request", "sign-in was not started in this browser")
	}

	ar, err := c.store.ConsumeAuthRequest(ctx, state)
	if errors.Is(err, ErrAuthRequestNotFound) {
		return nil, reasonUnknownState, oauthErr(http.StatusBadRequest, "invalid_request", "unknown or already-used state")
	}
	if err != nil {
		return nil, reasonInternal, fmt.Errorf("oidc: consume auth request: %w", err)
	}
	if c.now().After(ar.ExpiresAt) {
		return nil, reasonExpiredRequest, oauthErr(http.StatusBadRequest, "invalid_request", "auth request expired")
	}
	// Defence in depth behind the binding check. A store without the
	// connector_id column (before migration 0015) hands back an empty id.
	if ar.ConnectorID != "" && ar.ConnectorID != id {
		return nil, reasonConnectorMismatch, oauthErr(http.StatusBadRequest, "invalid_request", "state was issued for another sign-in method")
	}

	clearBinding := c.binding.clearCookie(id, state).String()

	completion, err := c.completeUpstream(ctx, conn, in.params, state)
	var denied *UpstreamDenied
	switch {
	case errors.As(err, &denied):
		out, err := c.redirect(ar, clearBinding, url.Values{
			"error":             {denied.Code},
			"error_description": {denied.Description},
		})
		return out, reasonUpstreamDenied, err
	case errors.Is(err, ErrMissingResponse):
		return nil, reasonMissingCode, oauthErr(http.StatusBadRequest, "invalid_request", "missing code")
	case err != nil:
		return nil, reasonUpstreamError, oauthErr(http.StatusBadGateway, "upstream_error", "could not complete "+conn.DisplayName()+" sign-in")
	}
	identity := completion.Identity

	if refused := c.refusal(identity, completion.Refusal); refused != "" {
		page := forbiddenPage(identity.Email)
		page.SetCookie = clearBinding
		return page, refused, nil
	}

	// Admitted, but possibly granted nothing: refuse here, before a code
	// exists, with the RFC 6749 §4.1.2.1 error the client can show (the CLI
	// prints it and exits; the device page denies the device code).
	_, ok, err := permitted(ctx, c.authorizer, identity.Email)
	if err != nil {
		return nil, reasonInternal, fmt.Errorf("oidc: resolve permissions: %w", err)
	}
	if !ok {
		c.authz.ObserveAuthzDenied(authzStageLogin)
		c.logger.InfoContext(ctx, id+" sign-in refused: no authorization rule grants this account any Temporal permissions",
			"op", logOpCallback,
			"connector", id,
			"cause", reasonAuthzDenied,
			"client_id", ar.ClientID,
			"email", identity.Email,
		)
		out, err := c.redirect(ar, clearBinding, url.Values{
			"error":             {"access_denied"},
			"error_description": {msgNoAccess},
		})
		return out, reasonAuthzDenied, err
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
		Subject:             identity.Subject,
		Email:               identity.Email,
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

// completeUpstream hands the response to the connector under the overall
// deadline, with the binding values Begin was given for the same state. A
// failure other than the user-facing ones is logged here, once.
func (c *Callback) completeUpstream(ctx context.Context, conn Connector, params url.Values, state string) (Completion, error) {
	id := conn.ID()
	cctx, cancel := context.WithTimeout(ctx, c.completeTimeout)
	defer cancel()
	completion, err := conn.Complete(cctx, CompleteParams{
		RedirectURI:  c.issuer + CallbackPath(id),
		Params:       params,
		CodeVerifier: c.binding.codeVerifier(id, state),
		Nonce:        c.binding.nonce(id, state),
		RequestID:    c.binding.requestID(id, state),
	})
	if err == nil && completion.Identity.Subject == "" {
		err = &UpstreamError{Reason: UpstreamReasonClaims, Err: errors.New("oidc: upstream identity has no subject")}
	}
	var denied *UpstreamDenied
	if err != nil && !errors.As(err, &denied) && !errors.Is(err, ErrMissingResponse) {
		c.logUpstreamFailure(ctx, id, err, errors.Is(cctx.Err(), context.DeadlineExceeded))
	}
	return completion, err
}

// refusal names the gate an upstream identity failed, or "" when every gate
// admits it: the shared gates first, then the connector's own verdict. An
// email the upstream could not prove is never admitted.
func (c *Callback) refusal(id UpstreamIdentity, connectorRefusal string) string {
	switch {
	case !id.EmailVerified:
		return reasonEmailUnverified
	case !emailDomainAllowed(c.allowedDomains, id.Email):
		return reasonDomainNotAllowed
	}
	return connectorRefusal
}

// logUpstreamFailure records why an upstream sign-in failed: a warning,
// since the usual causes (an expired or replayed code, a transient outage)
// resolve on retry, but a sustained rate means misconfiguration. Only the
// reason category and the OAuth error code are logged, never the error text.
// overBudget marks a Complete that ran out of its overall deadline, whatever
// the connector made of that.
func (c *Callback) logUpstreamFailure(ctx context.Context, connectorID string, err error, overBudget bool) {
	cause, oauthCode, timeout := "unknown", "", overBudget
	var ue *UpstreamError
	if errors.As(err, &ue) {
		cause, oauthCode, timeout = ue.Reason, ue.OAuthError, ue.Timeout || overBudget
	}
	attrs := []any{"op", logOpCallback, "connector", connectorID, "cause", cause}
	if oauthCode != "" {
		attrs = append(attrs, "oauth_error", oauthCode)
	}
	if timeout {
		attrs = append(attrs, "timeout", true)
	}
	c.logger.WarnContext(ctx, connectorID+" sign-in failed", attrs...)
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

// ParseDomains turns a comma-separated domain list into a lowercased set. An
// empty config yields an empty set: an allowlist built from it then fails
// closed (no email is admitted) rather than open.
func ParseDomains(raw string) map[string]struct{} {
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
