package oidc

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/onhotpath/tempogate/ratelimit"
)

const (
	// DevicePathSegment is the verification-page path tempogate's own
	// /device_authorization response advertises (see DevicePath). The UI
	// handlers below share the same base so a single embedded HTML form can
	// post back to itself without re-deriving the URL.
	DevicePathSegment = DevicePath

	// DeviceSSOCallbackPath is the loopback redirect_uri the internal
	// tempogate-device-ui client registers under. It must match the value
	// operators configure for that client in OIDC_CLIENTS; NewDeviceUI
	// rejects a registry where <issuer>+DeviceSSOCallbackPath is not an
	// allowed redirect URI, so a drifted deployment fails at startup.
	DeviceSSOCallbackPath = DevicePath + "/sso-callback"

	// DeviceConfirmPath renders the approve/deny prompt after the session
	// cookie has been issued. Reached either directly (when a session is
	// already present) or via DeviceSSOCallbackPath (when one had to be
	// minted through the upstream IdP bounce).
	DeviceConfirmPath = DevicePath + "/confirm"

	// DeviceApprovePath and DeviceDenyPath are the CSRF-protected POST
	// targets the confirm-page form submits to.
	DeviceApprovePath = DevicePath + "/approve"
	DeviceDenyPath    = DevicePath + "/deny"

	// DefaultInternalDeviceUIClientID is the client_id tempogate registers
	// for its own verification-UI side. It is operator-configured in
	// OIDC_CLIENTS / OIDC_CLIENT_SECRETS rather than auto-injected so
	// active verification sessions survive a rolling restart.
	DefaultInternalDeviceUIClientID = "tempogate-device-ui"

	// deviceStateTTL bounds how long the signed bounce state remains
	// honoured after a /idp/device POST. Short enough that an abandoned
	// Google round-trip cannot be resumed much later; longer than the
	// upstream session_ttl so a slow but live SSO completion is not
	// rejected by the wrong clock.
	deviceStateTTL = 10 * time.Minute

	// deviceStateNonceBytes is the entropy carried in the bounce state so
	// two concurrent device flows can never produce identical signed states
	// (the HMAC alone would collide for identical {user_code, exp} pairs).
	deviceStateNonceBytes = 16

	// logOpSSOCallback is the "op" attribute on every structured log line
	// the SSO callback emits. Stable on purpose so an operator can grep or
	// build a dashboard panel on it without re-deriving the string from
	// log content.
	logOpSSOCallback = "device.sso_callback"

	// User-code attempt budgets (RFC 8628 §5.1). A user_code has ~36.6 bits
	// of entropy and lives for minutes, so a handful of attempts per minute
	// leaves brute force hopeless while a typo or two never trips them. Only
	// failed lookups spend the budget, so a NAT full of honest users is not
	// throttled by its own successful sign-ins.
	defaultUserCodeAttemptsPerSession = 5
	defaultUserCodeAttemptsPerIP      = 20
	userCodeAttemptWindow             = time.Minute

	// msgUnusableUserCode is the single answer for a code that is unknown,
	// expired or already decided. Distinct messages would tell a guesser
	// which codes are real.
	msgUnusableUserCode = "That code is not valid. Check the code on your device and try again, or restart the sign-in from your device."

	// msgTooManyAttempts is the answer once a client or session has spent
	// its user-code attempt budget, whatever the code it submitted.
	msgTooManyAttempts = "Too many attempts. Wait a minute, then try again."
)

// clientKeyCtxKey carries the requesting client's rate-limit key from the
// per-operation middleware into the typed handlers, which only see a
// context.Context.
type clientKeyCtxKey struct{}

//go:embed templates/*.html
var deviceUITemplatesFS embed.FS

// inlineStylePattern finds the one inline <style> block in base.html, whose
// hash the page CSP allows.
var inlineStylePattern = regexp.MustCompile(`(?s)<style>(.*?)</style>`)

// devicePages enumerates the template files that compose each rendered page.
// Each set is loaded as base.html plus the page-specific child; the child
// supplies `title` and `content` blocks that the base layout pulls in.
var devicePages = map[string]string{
	"enter":    "device_enter.html",
	"confirm":  "device_confirm.html",
	"approved": "device_approved.html",
	"denied":   "device_denied.html",
	"error":    "device_error.html",
}

// ErrInternalDeviceUIClientMissing is returned by NewDeviceUI when the
// operator-managed tempogate-device-ui client is not present in the
// ClientRegistry. The registrar wraps it into an actionable graph-time
// failure so a deployment never silently lands the verification UI on top
// of an unconfigured internal client.
var ErrInternalDeviceUIClientMissing = errors.New("oidc: internal device-ui client not registered in OIDC_CLIENTS")

// ErrInternalDeviceUIClientNotConfidential is returned by NewDeviceUI when
// the internal client is registered without a secret. The verification
// bounce authenticates the client at /token via that secret, so a public
// registration would silently break the round-trip.
var ErrInternalDeviceUIClientNotConfidential = errors.New("oidc: internal device-ui client must be confidential (set its secret in OIDC_CLIENT_SECRETS)")

// ErrInvalidUpstreamIDPOrigin is returned by NewDeviceUI when a non-empty
// upstream IdP authorization endpoint URL fails to parse into a CSP form-
// action source (scheme + host). An empty value is permitted — it just
// keeps form-action at 'self', which is correct for deployments whose
// upstream IdP shares the issuer's origin.
var ErrInvalidUpstreamIDPOrigin = errors.New("oidc: upstream IdP authorization endpoint must be an absolute URL with scheme and host")

// ErrInternalDeviceUIClientRedirectMismatch is returned by NewDeviceUI when
// the internal client is not registered for <issuer>/device/sso-callback.
// /authorize would reject every verification bounce with that mismatch, so
// it is caught at construction instead of on the first user form-submit.
var ErrInternalDeviceUIClientRedirectMismatch = errors.New("oidc: internal device-ui client must be registered in OIDC_CLIENTS with redirect URI <issuer>" + DeviceSSOCallbackPath)

// ErrNilAuthCodeRedeemer is returned by NewDeviceUI when no redeemer is
// passed. The SSO callback cannot complete without one, and a nil seam
// would surface only at the first user form-submit; fail at construction
// instead.
var ErrNilAuthCodeRedeemer = errors.New("oidc: device-ui requires a non-nil AuthCodeRedeemer")

// AuthCodeRedeemer is the narrow seam DeviceUI uses to turn the
// upstream-IdP-bounced authorization code into the consumed AuthCode's
// claims. *Token satisfies it structurally, and that is the production
// wiring — the SSO callback runs the same single-use consumption + proof
// check that the public /token endpoint runs, just without an HTTPS
// round-trip back through the issuer URL. Declared on the consumer side
// so DeviceUI's compile-time view of its Token dependency is just this
// one method (no access to id-token minting, refresh tokens, or the
// device-code grant).
type AuthCodeRedeemer interface {
	RedeemAuthorizationCode(ctx context.Context, in AuthCodeRedemptionRequest) (*AuthCodeRedemption, error)
}

// DeviceUI serves the human-side of the RFC 8628 §3.3 verification flow:
// the user_code entry form, the SSO bounce through tempogate's own
// /idp/authorize chain (acting as the internal tempogate-device-ui client),
// and the CSRF-protected Approve / Deny prompt that flips the device_codes
// row the CLI is polling.
type DeviceUI struct {
	devices              DeviceCodeStore
	sessions             *SessionManager
	clients              ClientRegistry
	redeemer             AuthCodeRedeemer
	signingKey           []byte
	issuer               string
	issuerURL            *url.URL
	internalClientID     string
	internalClientSecret string
	now                  func() time.Time
	newStateNonce        func() (string, error)
	pages                map[string]*template.Template

	// ipAttempts and sessionAttempts throttle user_code guessing per client
	// IP and per verification session. In-process: each replica keeps its
	// own budget, which still bounds a guesser to a small multiple of it.
	ipAttempts      *ratelimit.Limiter
	sessionAttempts *ratelimit.Limiter

	// rawUpstreamIDPAuthEndpoint is captured by WithUpstreamIDPOrigin and
	// parsed once in NewDeviceUI; the result lives in upstreamFormActionSource.
	rawUpstreamIDPAuthEndpoint string

	// upstreamFormActionSource is the "scheme://host[:port]" origin of the
	// upstream IdP's authorization endpoint, used as an extra source in the
	// device_enter page's CSP form-action directive. Empty when the operator
	// hasn't wired an origin (e.g., tests whose mock IdP shares the issuer).
	upstreamFormActionSource string

	// enterPagePolicy and pagePolicy are the Content-Security-Policy
	// headers for the entry page and for every other page. Only the entry
	// page's form leaves the origin, so only it lists the upstream IdP.
	enterPagePolicy string
	pagePolicy      string

	// logger is the operator-facing structured log sink. Every failure path
	// that the SSO callback collapses into the generic "could not be
	// completed" error page writes one line through this so the cause is
	// recoverable from `kubectl logs` instead of being silently discarded.
	// Defaults to slog.New(slog.DiscardHandler) in NewDeviceUI so tests and
	// direct constructors that don't wire one in produce no noise.
	logger *slog.Logger
}

// DeviceUIOption configures a DeviceUI at construction. Every seam a test
// might want to control — clock, state nonce, internal client id — is
// reachable here so production code stays on the defaults.
type DeviceUIOption func(*DeviceUI)

// WithDeviceUIClock swaps the clock used to stamp signed state expirations
// and ApproveDeviceCode / DenyDeviceCode timestamps. For tests.
func WithDeviceUIClock(now func() time.Time) DeviceUIOption {
	return func(u *DeviceUI) { u.now = now }
}

// WithInternalClientID overrides the default
// DefaultInternalDeviceUIClientID. Operators rarely change this; tests use
// it to exercise the configuration mismatch failure modes.
func WithInternalClientID(id string) DeviceUIOption {
	return func(u *DeviceUI) { u.internalClientID = id }
}

// WithDeviceUIStateNonceGenerator swaps the bounce-state nonce generator.
// For tests — production uses crypto/rand.
func WithDeviceUIStateNonceGenerator(fn func() (string, error)) DeviceUIOption {
	return func(u *DeviceUI) { u.newStateNonce = fn }
}

// WithDeviceUILogger threads the operator-facing structured log sink into
// the verification UI. Wire it in production so every failure path that
// renders the generic "could not be completed" page leaves a recoverable
// trace in `kubectl logs`. Defaults to slog.New(slog.DiscardHandler) in
// NewDeviceUI when omitted, which keeps tests and direct constructors
// quiet without forcing every caller to know about the logger.
func WithDeviceUILogger(l *slog.Logger) DeviceUIOption {
	return func(u *DeviceUI) { u.logger = l }
}

// WithUserCodeRateLimiters swaps the per-client-IP and per-session limiters
// that throttle user_code attempts. For tests; production keeps 20 failed
// attempts per minute per IP and 5 per session.
func WithUserCodeRateLimiters(perIP, perSession *ratelimit.Limiter) DeviceUIOption {
	return func(u *DeviceUI) {
		u.ipAttempts = perIP
		u.sessionAttempts = perSession
	}
}

// WithUpstreamIDPOrigin lets the device_enter page emit a CSP form-action
// directive that whitelists the upstream IdP's origin in addition to 'self'.
// CSP Level 3 enforces form-action across every URL in the navigation chain
// that a form submission produces (the 303 to /authorize plus the 302 to
// the upstream IdP), so a cross-origin upstream silently breaks the device
// flow unless its origin is in the source list.
//
// rawAuthEndpoint is the same value that wires the Authorizer's upstream
// endpoint (OIDC_GOOGLE_AUTH_ENDPOINT) — pass it verbatim, the constructor
// extracts scheme + host. An empty value leaves the directive at 'self',
// which is correct only when the upstream IdP shares the issuer's origin
// (typically integration tests with an in-process mock).
func WithUpstreamIDPOrigin(rawAuthEndpoint string) DeviceUIOption {
	return func(u *DeviceUI) { u.rawUpstreamIDPAuthEndpoint = rawAuthEndpoint }
}

// NewDeviceUI constructs the device-flow verification UI handler. signingKey
// is the same OIDC_SESSION_SIGNING_KEY the SessionManager uses: the bounce
// state is HMAC-signed under it so one operator secret backs the entire
// device-flow surface. The internal tempogate-device-ui client must be
// present in clients and carry a non-empty secret; missing or public
// registrations surface as ErrInternalDeviceUIClient... here so a
// misconfigured deployment fails at construction rather than on the first
// user form-submit. redeemer is the in-process seam that turns the
// upstream-IdP-bounced authorization code into the consumed AuthCode's
// claims — the SSO callback uses it instead of POSTing back to its own
// /token endpoint over the issuer URL, sidestepping the TLS, DNS, and
// ingress failure modes that loopback introduced.
func NewDeviceUI(
	devices DeviceCodeStore,
	sessions *SessionManager,
	clients ClientRegistry,
	redeemer AuthCodeRedeemer,
	signingKey []byte,
	issuer string,
	opts ...DeviceUIOption,
) (*DeviceUI, error) {
	// Catch both the untyped nil and a typed-nil interface value (e.g. a
	// caller that built `var t *Token = nil; NewDeviceUI(..., t, ...)`):
	// `redeemer == nil` only fires on the former, but the latter would
	// still satisfy the interface at compile time and panic on the first
	// SSO callback when RedeemAuthorizationCode dispatches to a nil
	// receiver. Reflect once at construction so the failure surfaces
	// here, not at the first user-visible request.
	if v := reflect.ValueOf(redeemer); !v.IsValid() || (v.Kind() == reflect.Pointer && v.IsNil()) {
		return nil, ErrNilAuthCodeRedeemer
	}
	trimmedIssuer := strings.TrimRight(issuer, "/")
	u := &DeviceUI{
		devices:          devices,
		sessions:         sessions,
		clients:          clients,
		redeemer:         redeemer,
		signingKey:       signingKey,
		issuer:           trimmedIssuer,
		internalClientID: DefaultInternalDeviceUIClientID,
		now:              func() time.Time { return time.Now().UTC() },
		newStateNonce:    randomDeviceStateNonce,
		ipAttempts:       ratelimit.New(ratelimit.WithLimit(defaultUserCodeAttemptsPerIP, userCodeAttemptWindow)),
		sessionAttempts:  ratelimit.New(ratelimit.WithLimit(defaultUserCodeAttemptsPerSession, userCodeAttemptWindow)),
	}
	for _, o := range opts {
		o(u)
	}
	if u.logger == nil {
		u.logger = slog.New(slog.DiscardHandler)
	}

	client, ok := clients[u.internalClientID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrInternalDeviceUIClientMissing, u.internalClientID)
	}
	if client.Secret == "" {
		return nil, fmt.Errorf("%w: %s", ErrInternalDeviceUIClientNotConfidential, u.internalClientID)
	}
	u.internalClientSecret = client.Secret

	iss, err := url.Parse(u.issuer)
	if err != nil || iss.Scheme == "" || iss.Host == "" {
		return nil, fmt.Errorf("%w: issuer %q is not an absolute URL", ErrInternalDeviceUIClientRedirectMismatch, u.issuer)
	}
	u.issuerURL = iss
	if err := clients.Validate(u.internalClientID, u.issuer+DeviceSSOCallbackPath); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInternalDeviceUIClientRedirectMismatch, err)
	}

	if u.rawUpstreamIDPAuthEndpoint != "" {
		source, err := upstreamFormActionSource(u.rawUpstreamIDPAuthEndpoint)
		if err != nil {
			return nil, fmt.Errorf("%w: %q: %s", ErrInvalidUpstreamIDPOrigin, u.rawUpstreamIDPAuthEndpoint, err)
		}
		u.upstreamFormActionSource = source
	}

	pages, err := loadDevicePages()
	if err != nil {
		return nil, fmt.Errorf("oidc: load device-ui templates: %w", err)
	}
	u.pages = pages

	styleSource, err := inlineStyleSource()
	if err != nil {
		return nil, fmt.Errorf("oidc: load device-ui templates: %w", err)
	}
	// CSP3 §6.7.2.5 enforces form-action against every URL in the redirect
	// chain a form submission follows. The entry form POSTs same-origin,
	// which 303s through /authorize and then 302s to the upstream IdP, so
	// the IdP's origin has to be a source or the browser refuses the
	// cross-origin hop and the device flow silently stalls.
	enterFormAction := "'self'"
	if u.upstreamFormActionSource != "" {
		enterFormAction += " " + u.upstreamFormActionSource
	}
	u.enterPagePolicy = devicePagePolicy(styleSource, enterFormAction)
	u.pagePolicy = devicePagePolicy(styleSource, "'self'")

	return u, nil
}

// devicePagePolicy is the CSP for a device-ui page. It is sent as a header,
// not a <meta> tag: browsers ignore frame-ancestors in meta, and the confirm
// page is what a clickjacking page would frame. Styles are allowed by hash
// rather than 'unsafe-inline', so injected markup cannot style itself.
func devicePagePolicy(styleSource, formActionSources string) string {
	return "default-src 'none'; style-src " + styleSource + "; form-action " + formActionSources +
		"; base-uri 'none'; frame-ancestors 'none'"
}

// inlineStyleSource returns the CSP hash source for base.html's inline
// <style> block. Hashing the embedded template at startup keeps the policy
// in step with the CSS without a hand-maintained constant. html/template
// emits literal template text verbatim, so the rendered block hashes the
// same.
func inlineStyleSource() (string, error) {
	base, err := deviceUITemplatesFS.ReadFile("templates/base.html")
	if err != nil {
		return "", err
	}
	return styleHashSource(base)
}

// styleHashSource hashes the single <style> block in tmpl. More than one
// would need one hash each, so it is refused rather than half-allowed.
func styleHashSource(tmpl []byte) (string, error) {
	blocks := inlineStylePattern.FindAllSubmatch(tmpl, -1)
	if len(blocks) != 1 {
		return "", fmt.Errorf("base.html: want exactly one <style> block, found %d", len(blocks))
	}
	sum := sha256.Sum256(blocks[0][1])
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'", nil
}

// upstreamFormActionSource collapses an upstream IdP authorization-endpoint
// URL down to the CSP source it contributes: "scheme://host[:port]". CSP3
// §2.3.1 source expressions accept exactly that shape; a path or query on
// the endpoint URL is irrelevant to the form-action match and would in fact
// make the directive a no-op against the upstream IdP's own authorization
// URL (which carries its own query string).
func upstreamFormActionSource(rawAuthEndpoint string) (string, error) {
	parsed, err := url.Parse(rawAuthEndpoint)
	if err != nil {
		return "", err
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "https" && scheme != "http" {
		return "", fmt.Errorf("scheme must be http or https, got %q", parsed.Scheme)
	}
	if parsed.Host == "" {
		return "", errors.New("missing host")
	}
	return scheme + "://" + parsed.Host, nil
}

func loadDevicePages() (map[string]*template.Template, error) {
	out := make(map[string]*template.Template, len(devicePages))
	for name, file := range devicePages {
		t, err := template.New(name).ParseFS(deviceUITemplatesFS, "templates/base.html", "templates/"+file)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", file, err)
		}
		out[name] = t
	}
	return out, nil
}

// render produces the bytes for one of the device-ui pages. Templates are
// parsed once at construction; this is a pure CPU+memory operation that
// cannot fail under normal operation, but a regression in template data
// shape surfaces as an error here rather than a half-rendered page.
func (u *DeviceUI) render(name string, data any) ([]byte, error) {
	t, ok := u.pages[name]
	if !ok {
		return nil, fmt.Errorf("oidc: unknown device-ui page %q", name)
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "base", data); err != nil {
		return nil, fmt.Errorf("oidc: render %s: %w", name, err)
	}
	return buf.Bytes(), nil
}

func (u *DeviceUI) Register(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "device-ui-enter",
		Method:      http.MethodGet,
		Path:        DevicePath,
		Summary:     "Device-flow verification: show the user_code entry form",
		Tags:        []string{"oidc"},
	}, func(ctx context.Context, in *deviceEnterGetInput) (*htmlOutput, error) {
		return u.handleEnterGet(ctx, in)
	})

	huma.Register(api, huma.Operation{
		OperationID:   "device-ui-submit",
		Method:        http.MethodPost,
		Path:          DevicePath,
		Summary:       "Device-flow verification: accept the user_code and bounce through SSO if no session",
		Tags:          []string{"oidc"},
		Middlewares:   huma.Middlewares{withClientKey},
		DefaultStatus: http.StatusSeeOther,
	}, func(ctx context.Context, in *deviceEnterPostInput) (*deviceRedirectOrPage, error) {
		return u.handleEnterPost(ctx, in)
	})

	huma.Register(api, huma.Operation{
		OperationID:   "device-ui-sso-callback",
		Method:        http.MethodGet,
		Path:          DeviceSSOCallbackPath,
		Summary:       "Device-flow verification: SSO loopback, mint session, route to confirm",
		Tags:          []string{"oidc"},
		DefaultStatus: http.StatusSeeOther,
	}, func(ctx context.Context, in *deviceSSOCallbackInput) (*deviceRedirectOrPage, error) {
		return u.handleSSOCallback(ctx, in)
	})

	huma.Register(api, huma.Operation{
		OperationID: "device-ui-confirm",
		Method:      http.MethodGet,
		Path:        DeviceConfirmPath,
		Summary:     "Device-flow verification: render the approve/deny prompt",
		Tags:        []string{"oidc"},
		Middlewares: huma.Middlewares{withClientKey},
	}, func(ctx context.Context, in *deviceConfirmInput) (*deviceRedirectOrPage, error) {
		return u.handleConfirm(ctx, in)
	})

	huma.Register(api, huma.Operation{
		OperationID: "device-ui-approve",
		Method:      http.MethodPost,
		Path:        DeviceApprovePath,
		Summary:     "Device-flow verification: approve the pending device authorization",
		Tags:        []string{"oidc"},
		Middlewares: huma.Middlewares{withClientKey},
	}, func(ctx context.Context, in *deviceDecisionInput) (*htmlOutput, error) {
		return u.handleDecision(ctx, in, true)
	})

	huma.Register(api, huma.Operation{
		OperationID: "device-ui-deny",
		Method:      http.MethodPost,
		Path:        DeviceDenyPath,
		Summary:     "Device-flow verification: deny the pending device authorization",
		Tags:        []string{"oidc"},
		Middlewares: huma.Middlewares{withClientKey},
	}, func(ctx context.Context, in *deviceDecisionInput) (*htmlOutput, error) {
		return u.handleDecision(ctx, in, false)
	})
}

// htmlOutput is the shared response shape for any device-ui page that just
// renders HTML. Status must be set (huma writes it verbatim); htmlPage
// defaults it to 200. Cache-Control: no-store keeps the user_code and email
// off intermediary caches. ContentSecurityPolicy and ReferrerPolicy replace
// the listener-wide defaults; see htmlPage.
type htmlOutput struct {
	Status                int
	ContentType           string `header:"Content-Type"`
	CacheControl          string `header:"Cache-Control"`
	ContentSecurityPolicy string `header:"Content-Security-Policy"`
	ReferrerPolicy        string `header:"Referrer-Policy"`
	Body                  []byte
}

// deviceRedirectOrPage is the shared response shape for handlers that may
// either redirect (303 + Location + optional Set-Cookie) or render an HTML
// error page (200 + Content-Type + Body). Huma omits empty headers, so the
// unused fields cost nothing on the wire and the two branches stay in one
// typed struct.
type deviceRedirectOrPage struct {
	Status                int
	Location              string `header:"Location"`
	SetCookie             string `header:"Set-Cookie"`
	ContentType           string `header:"Content-Type"`
	CacheControl          string `header:"Cache-Control"`
	ContentSecurityPolicy string `header:"Content-Security-Policy"`
	ReferrerPolicy        string `header:"Referrer-Policy"`
	Body                  []byte
}

type deviceEnterGetInput struct {
	UserCode string `query:"user_code"`
}

type deviceEnterPostInput struct {
	Cookie  string `header:"Cookie"`
	RawBody []byte `contentType:"application/x-www-form-urlencoded"`
}

type deviceSSOCallbackInput struct {
	Code  string `query:"code"`
	State string `query:"state"`
}

type deviceConfirmInput struct {
	UserCode string `query:"user_code"`
	Cookie   string `header:"Cookie"`
}

type deviceDecisionInput struct {
	Cookie  string `header:"Cookie"`
	Origin  string `header:"Origin"`
	Referer string `header:"Referer"`
	RawBody []byte `contentType:"application/x-www-form-urlencoded"`
}

// handleEnterGet renders the user_code entry form. When a verification_uri_complete
// hop pre-fills ?user_code=, the form input is seeded with the dashed
// display form so the user sees what they typed on the device.
func (u *DeviceUI) handleEnterGet(_ context.Context, in *deviceEnterGetInput) (*htmlOutput, error) {
	body, err := u.render("enter", map[string]any{
		"PostURL":           u.publicPath(DevicePath),
		"PrefilledUserCode": formatUserCode(canonicalUserCode(in.UserCode)),
	})
	if err != nil {
		return nil, fmt.Errorf("oidc: device-ui enter render: %w", err)
	}
	out := u.htmlPage(body)
	out.ContentSecurityPolicy = u.enterPagePolicy
	return out, nil
}

// handleEnterPost is the dispatcher: validate the user_code lookup, then
// either bounce through the upstream IdP (no session) or 303 straight to
// the confirm page (session present).
func (u *DeviceUI) handleEnterPost(ctx context.Context, in *deviceEnterPostInput) (*deviceRedirectOrPage, error) {
	form, err := url.ParseQuery(string(in.RawBody))
	if err != nil {
		return u.errorPage("Your submission was malformed. Please return to your device and try again."), nil
	}

	raw := form.Get("user_code")
	canonical := canonicalUserCode(raw)
	if canonical == "" {
		return u.errorPage("Enter the code shown on your device."), nil
	}

	// The session (if any) is resolved before the lookup so its attempt
	// budget applies to signed-in guessers too.
	var sid string
	bs, err := u.sessions.Get(ctx, requestFromCookieHeader(in.Cookie))
	switch {
	case err == nil:
		sid = bs.SID
	case !errors.Is(err, ErrNoSession):
		return nil, fmt.Errorf("oidc: device-ui session lookup: %w", err)
	}

	if !u.spendUserCodeAttempt(ctx, sid) {
		return u.tooManyAttemptsPage(), nil
	}
	usable, err := u.userCodeUsable(ctx, canonical)
	if err != nil {
		return nil, err
	}
	if !usable {
		return u.errorPage(msgUnusableUserCode), nil
	}
	u.refundUserCodeAttempt(ctx, sid)

	if sid != "" {
		return &deviceRedirectOrPage{
			Status:   http.StatusSeeOther,
			Location: u.confirmRedirect(canonical),
		}, nil
	}

	state, err := u.signBounceState(canonical)
	if err != nil {
		return nil, fmt.Errorf("oidc: sign device-ui bounce state: %w", err)
	}
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", u.internalClientID)
	q.Set("redirect_uri", u.issuer+DeviceSSOCallbackPath)
	q.Set("scope", "openid email")
	q.Set("state", state)
	return &deviceRedirectOrPage{
		Status:   http.StatusSeeOther,
		Location: u.issuer + AuthorizePath + "?" + q.Encode(),
	}, nil
}

// handleSSOCallback verifies the bounce state, redeems the auth code at the
// internal /token endpoint to surface the authenticated email, mints the
// signed-cookie session, and 303s onward to the confirm page carrying the
// recovered user_code in the query string. The Set-Cookie travels with the
// 303 so the browser's next GET to /confirm presents the session.
func (u *DeviceUI) handleSSOCallback(ctx context.Context, in *deviceSSOCallbackInput) (*deviceRedirectOrPage, error) {
	if in.Code == "" || in.State == "" {
		// Warn rather than Error: an empty code or state usually means the
		// upstream IdP sent a malformed callback (rare misconfiguration of
		// the upstream client, or a direct hit on the URL without the
		// preceding bounce). Booleans only — neither value carries
		// recoverable secret material, but the actual contents add nothing
		// to the diagnosis either.
		u.logger.WarnContext(ctx, "device-ui sso callback rejected: missing code or state",
			"op", logOpSSOCallback,
			"cause", "missing_code_or_state",
			"code_present", in.Code != "",
			"state_present", in.State != "",
		)
		return u.errorPage("That sign-in could not be completed. Restart the sign-in from your device."), nil
	}

	userCode, err := u.verifyBounceState(in.State)
	if err != nil {
		// Warn: the most common cause is a slow user round-trip that
		// crossed the 10-minute state TTL, or a rolling restart that
		// landed the callback on a pod with a freshly rotated signing
		// key. Both are recoverable by the user re-running the device
		// flow, but the operator wants to see the rate.
		u.logger.WarnContext(ctx, "device-ui sso callback rejected: bounce state verification failed",
			"op", logOpSSOCallback,
			"cause", "verify_bounce_state",
			"err", err,
		)
		return u.errorPage("That sign-in could not be completed. Restart the sign-in from your device."), nil
	}

	id, err := u.redeemAuthCode(ctx, in.Code)
	if err != nil {
		// Error: the loopback /token call is supposed to succeed
		// unconditionally once the upstream bounce completes — so any
		// failure here is an integration issue (wrong client secret,
		// loopback URL unreachable, malformed id_token, /token returning
		// a non-200 we don't recognise). Operator must investigate.
		u.logger.ErrorContext(ctx, "device-ui sso callback failed: auth code redemption failed",
			"op", logOpSSOCallback,
			"cause", "redeem_auth_code",
			"err", err,
		)
		return u.errorPage("That sign-in could not be completed. Restart the sign-in from your device."), nil
	}

	_, cookie, err := u.sessions.IssueCookie(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("oidc: device-ui session issue: %w", err)
	}

	return &deviceRedirectOrPage{
		Status:    http.StatusSeeOther,
		Location:  u.confirmRedirect(userCode),
		SetCookie: cookie.String(),
	}, nil
}

// handleConfirm renders the approve/deny prompt. A missing session sends the
// browser back to the entry form to restart the bounce; a missing or
// already-decided user_code surfaces as an error page rather than a silent
// no-op so an honest mistake still gives feedback.
func (u *DeviceUI) handleConfirm(ctx context.Context, in *deviceConfirmInput) (*deviceRedirectOrPage, error) {
	canonical := canonicalUserCode(in.UserCode)
	if canonical == "" {
		return u.errorPage("That sign-in could not be completed. Restart the sign-in from your device."), nil
	}

	req := requestFromCookieHeader(in.Cookie)
	bs, err := u.sessions.Get(ctx, req)
	if errors.Is(err, ErrNoSession) {
		return &deviceRedirectOrPage{
			Status:   http.StatusSeeOther,
			Location: u.publicPath(DevicePath) + "?user_code=" + url.QueryEscape(formatUserCode(canonical)),
		}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("oidc: device-ui confirm session lookup: %w", err)
	}

	if !u.spendUserCodeAttempt(ctx, bs.SID) {
		return u.tooManyAttemptsPage(), nil
	}
	usable, err := u.userCodeUsable(ctx, canonical)
	if err != nil {
		return nil, err
	}
	if !usable {
		return u.errorPage(msgUnusableUserCode), nil
	}
	u.refundUserCodeAttempt(ctx, bs.SID)

	body, err := u.render("confirm", map[string]any{
		"DisplayUserCode": formatUserCode(canonical),
		"Email":           bs.Email,
		"ApproveURL":      u.publicPath(DeviceApprovePath),
		"DenyURL":         u.publicPath(DeviceDenyPath),
		"CSRFToken":       bs.SID,
	})
	if err != nil {
		return nil, fmt.Errorf("oidc: device-ui confirm render: %w", err)
	}
	return u.redirectOrPage(u.htmlPage(body)), nil
}

// handleDecision is the single funnel for the approve and deny POSTs. The
// approve boolean flips which DeviceCodeStore method runs and which HTML
// page renders on success; everything else — CSRF check, Origin check,
// already-decided handling — is shared so the two paths cannot drift.
func (u *DeviceUI) handleDecision(ctx context.Context, in *deviceDecisionInput, approve bool) (*htmlOutput, error) {
	if !u.originAllowed(in.Origin, in.Referer) {
		return u.errorHTMLPage("That request did not come from the expected page. Restart the sign-in from your device."), nil
	}

	form, err := url.ParseQuery(string(in.RawBody))
	if err != nil {
		return u.errorHTMLPage("Your submission was malformed. Please return to your device and try again."), nil
	}

	req := requestFromCookieHeader(in.Cookie)
	bs, err := u.sessions.Get(ctx, req)
	if errors.Is(err, ErrNoSession) {
		return u.errorHTMLPage("Your sign-in has expired. Restart the sign-in from your device."), nil
	}
	if err != nil {
		return nil, fmt.Errorf("oidc: device-ui decision session lookup: %w", err)
	}

	presented := form.Get("csrf_token")
	if subtle.ConstantTimeCompare([]byte(presented), []byte(bs.SID)) != 1 {
		return u.errorHTMLPage("That submission could not be verified. Restart the sign-in from your device."), nil
	}

	canonical := canonicalUserCode(form.Get("user_code"))
	if canonical == "" {
		return u.errorHTMLPage("That submission was missing the device code. Restart the sign-in from your device."), nil
	}

	if !u.spendUserCodeAttempt(ctx, bs.SID) {
		out := u.errorHTMLPage(msgTooManyAttempts)
		out.Status = http.StatusTooManyRequests
		return out, nil
	}
	now := u.now()
	if approve {
		err = u.devices.ApproveDeviceCode(ctx, canonical, Identity{Subject: bs.Subject, Email: bs.Email}, now)
	} else {
		err = u.devices.DenyDeviceCode(ctx, canonical, now)
	}
	if errors.Is(err, ErrDeviceCodeNotPending) || errors.Is(err, ErrDeviceCodeNotFound) {
		return u.errorHTMLPage(msgUnusableUserCode), nil
	}
	if err != nil {
		return nil, fmt.Errorf("oidc: device-ui decision flip: %w", err)
	}
	u.refundUserCodeAttempt(ctx, bs.SID)

	page := "approved"
	if !approve {
		page = "denied"
	}
	body, err := u.render(page, nil)
	if err != nil {
		return nil, fmt.Errorf("oidc: device-ui %s render: %w", page, err)
	}
	return u.htmlPage(body), nil
}

// redeemAuthCode turns the auth code the upstream callback minted into the
// authenticated identity by running the same single-use consumption + proof check the
// public /token endpoint runs — but in-process, against the shared *Token
// instance. No HTTPS round-trip, no JWT decode dance: the identity comes back
// directly from the consumed AuthCode row. Eliminating the loopback also
// eliminates the TLS-chain, DNS-resolution, and hairpin-routing failure
// surfaces a deployment's ingress would otherwise contribute.
func (u *DeviceUI) redeemAuthCode(ctx context.Context, code string) (Identity, error) {
	r, err := u.redeemer.RedeemAuthorizationCode(ctx, AuthCodeRedemptionRequest{
		Code:         code,
		ClientID:     u.internalClientID,
		ClientSecret: u.internalClientSecret,
		RedirectURI:  u.issuer + DeviceSSOCallbackPath,
	})
	if err != nil {
		return Identity{}, fmt.Errorf("oidc: in-process auth code redemption: %w", err)
	}
	return r.Identity, nil
}

// signBounceState wraps a canonical user_code into the HMAC-signed,
// short-TTL `state` parameter the upstream /authorize redirect carries. It
// is the only state device-ui keeps across the IdP bounce: the user_code is
// recovered verbatim on the other side, and the exp + nonce together rule
// out replay.
func (u *DeviceUI) signBounceState(canonicalUserCode string) (string, error) {
	nonce, err := u.newStateNonce()
	if err != nil {
		return "", err
	}
	payload := deviceBounceState{
		UserCode: canonicalUserCode,
		Nonce:    nonce,
		Exp:      u.now().Add(deviceStateTTL).Unix(),
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw) + "." +
		base64.RawURLEncoding.EncodeToString(labeledMAC(u.signingKey, macLabelDeviceBounceState, raw)), nil
}

func (u *DeviceUI) verifyBounceState(signed string) (string, error) {
	parts := strings.SplitN(signed, ".", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", errors.New("malformed state")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", err
	}
	gotMAC, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	if subtle.ConstantTimeCompare(gotMAC, labeledMAC(u.signingKey, macLabelDeviceBounceState, raw)) != 1 {
		return "", errors.New("bad state mac")
	}
	var payload deviceBounceState
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", err
	}
	if u.now().Unix() > payload.Exp {
		return "", errors.New("state expired")
	}
	if canonicalUserCode(payload.UserCode) == "" {
		return "", errors.New("state has no user_code")
	}
	return canonicalUserCode(payload.UserCode), nil
}

type deviceBounceState struct {
	UserCode string `json:"user_code"`
	Nonce    string `json:"nonce"`
	Exp      int64  `json:"exp"`
}

// originAllowed enforces the same-origin rule for Approve / Deny POSTs:
// Origin, if present, must equal the issuer's scheme+host; otherwise the
// Referer must be a URL on the issuer's scheme and host whose path sits
// under the issuer's path. Either of those is sufficient: a modern browser
// always sends one of the two on a same-origin POST, so the pair forms a
// defence-in-depth check on top of SameSite=Lax.
func (u *DeviceUI) originAllowed(origin, referer string) bool {
	if origin != "" {
		return origin == u.issuerURL.Scheme+"://"+u.issuerURL.Host
	}
	return u.refererAllowed(referer)
}

// refererAllowed parses the Referer rather than prefix-matching the raw
// string, which would accept https://issuer.example.com.evil.com/ or
// https://issuer.example.com@evil.com/. The path must equal the issuer's
// path or continue it after a "/", so a sibling app at /idpevil does not
// pass for an issuer at /idp.
func (u *DeviceUI) refererAllowed(referer string) bool {
	ref, err := url.Parse(referer)
	if err != nil || ref.User != nil {
		return false
	}
	iss := u.issuerURL
	if !strings.EqualFold(ref.Scheme, iss.Scheme) || !strings.EqualFold(ref.Host, iss.Host) {
		return false
	}
	base := strings.TrimRight(iss.EscapedPath(), "/")
	p := ref.EscapedPath()
	return base == "" || p == base || strings.HasPrefix(p, base+"/")
}

// withClientKey stashes the requesting client's rate-limit key in the
// context. It is the TCP peer address: X-Forwarded-For is client-controlled
// unless a trusted proxy rewrites it, and tempogate has no notion of one, so
// behind a reverse proxy every client shares the proxy's key and only the
// per-session budget tells them apart.
func withClientKey(ctx huma.Context, next func(huma.Context)) {
	next(huma.WithValue(ctx, clientKeyCtxKey{}, ratelimit.ClientKey(ctx.RemoteAddr())))
}

func clientKeyFrom(ctx context.Context) string {
	k, _ := ctx.Value(clientKeyCtxKey{}).(string)
	return k
}

// spendUserCodeAttempt takes one attempt from the client IP's budget and,
// when sid is non-empty, from the session's. It reports false once either is
// exhausted; the caller must then answer without looking the code up, so a
// throttled guesser learns nothing even about a live code. A token is spent
// up front and handed back by refundUserCodeAttempt on success, so parallel
// guesses cannot all slip past the check before any failure is recorded.
func (u *DeviceUI) spendUserCodeAttempt(ctx context.Context, sid string) bool {
	ip := clientKeyFrom(ctx)
	if !u.ipAttempts.Allow(ip) {
		return false
	}
	if sid != "" && !u.sessionAttempts.Allow(sid) {
		u.ipAttempts.Refund(ip)
		return false
	}
	return true
}

// refundUserCodeAttempt returns the attempt spent on a code that turned out
// usable: only failed lookups count against the budget.
func (u *DeviceUI) refundUserCodeAttempt(ctx context.Context, sid string) {
	u.ipAttempts.Refund(clientKeyFrom(ctx))
	if sid != "" {
		u.sessionAttempts.Refund(sid)
	}
}

// userCodeUsable reports whether canonical names a pending, unexpired
// device code. Unknown, expired and decided codes all report false so the
// caller answers them with the same msgUnusableUserCode.
func (u *DeviceUI) userCodeUsable(ctx context.Context, canonical string) (bool, error) {
	dc, err := u.devices.LookupDeviceCodeByUserCode(ctx, canonical)
	if errors.Is(err, ErrDeviceCodeNotFound) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("oidc: lookup user_code: %w", err)
	}
	if u.now().After(dc.ExpiresAt) || dc.ApprovedAt != nil || dc.DeniedAt != nil {
		return false, nil
	}
	return true, nil
}

func (u *DeviceUI) tooManyAttemptsPage() *deviceRedirectOrPage {
	page := u.errorPage(msgTooManyAttempts)
	page.Status = http.StatusTooManyRequests
	return page
}

func (u *DeviceUI) confirmRedirect(canonical string) string {
	return u.publicPath(DeviceConfirmPath) + "?user_code=" + url.QueryEscape(formatUserCode(canonical))
}

// publicPath returns the URL path the browser sees for a route registered
// at p. When the api package mounts the OIDC surface under a base path, the
// huma adapter prepends that prefix to the registered Path; the issuer
// already encodes it, so we reuse the issuer's path component here so form
// actions and Location headers resolve to the exact mount the live routes
// listen on.
func (u *DeviceUI) publicPath(p string) string {
	return strings.TrimRight(u.issuerURL.Path, "/") + p
}

// htmlPage wraps a rendered page with its headers. The page policy allows
// the inline stylesheet the listener default would block. Referrer-Policy
// stays same-origin rather than the listener's no-referrer because under
// no-referrer a browser sends "Origin: null" on the Approve/Deny POST, which
// originAllowed rejects.
func (u *DeviceUI) htmlPage(body []byte) *htmlOutput {
	return &htmlOutput{
		Status:                http.StatusOK,
		ContentType:           "text/html; charset=utf-8",
		CacheControl:          "no-store",
		ContentSecurityPolicy: u.pagePolicy,
		ReferrerPolicy:        "same-origin",
		Body:                  body,
	}
}

func (u *DeviceUI) redirectOrPage(p *htmlOutput) *deviceRedirectOrPage {
	return &deviceRedirectOrPage{
		Status:                p.Status,
		ContentType:           p.ContentType,
		CacheControl:          p.CacheControl,
		ContentSecurityPolicy: p.ContentSecurityPolicy,
		ReferrerPolicy:        p.ReferrerPolicy,
		Body:                  p.Body,
	}
}

func (u *DeviceUI) errorPage(reason string) *deviceRedirectOrPage {
	return u.redirectOrPage(u.errorHTMLPage(reason))
}

func (u *DeviceUI) errorHTMLPage(reason string) *htmlOutput {
	body, err := u.render("error", map[string]any{"Reason": reason})
	if err != nil {
		body = []byte("device verification error")
	}
	return u.htmlPage(body)
}

// requestFromCookieHeader builds the minimal http.Request a SessionManager
// needs to read its cookie. Huma exposes the raw Cookie header value as a
// string; rather than reimplement cookie parsing here, we feed it back into
// the stdlib via a synthetic request.
func requestFromCookieHeader(cookieHeader string) *http.Request {
	r := &http.Request{Header: http.Header{}}
	if cookieHeader != "" {
		r.Header.Set("Cookie", cookieHeader)
	}
	return r
}

// canonicalUserCode normalises a user-typed code to the upper-case,
// no-dashes form the store indexes on. Whitespace is also stripped so a
// paste from the device that picked up a stray space is still accepted.
func canonicalUserCode(raw string) string {
	var b strings.Builder
	b.Grow(len(raw))
	for _, r := range raw {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r - 32)
		case (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
		case r == '-' || r == ' ' || r == '\t':
			// strip
		default:
			// strip — keeps the lookup faithful to what the device shows
		}
	}
	return b.String()
}

func randomDeviceStateNonce() (string, error) {
	b := make([]byte, deviceStateNonceBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
