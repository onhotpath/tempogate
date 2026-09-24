// Package cli is the engineer-facing client half of tempogate: it talks to a
// running tempogate issuer over its public OIDC/OAuth2 surface rather than
// sharing any server state. Flow drives the loopback authorization-code
// (RFC 8252) login that `tempogate login` performs on a developer laptop.
package cli

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/onhotpath/tempogate/oidc"
)

const (
	// callbackPath is the loopback redirect path. It is the CLI's own — not
	// tempogate's /callback/google — and only ever bound on 127.0.0.1, so it
	// never needs registering with Google: Google sees tempogate's fixed
	// upstream callback, and the loopback URI is validated solely against
	// tempogate's own client registry prefix (see docs/cli-loopback-login.md).
	callbackPath = "/callback"

	// loginScope is the downstream scope. tempogate's /authorize requires
	// openid; email lets the issuer run its domain allowlist.
	loginScope = "openid email"

	// defaultClientID is the client_id the CLI presents to tempogate. The
	// operator registers it once as "<id>:http://127.0.0.1:" in OIDC_CLIENTS
	// so any ephemeral loopback port is accepted by the prefix match.
	defaultClientID = "tempogate-cli"

	// defaultCallbackTimeout bounds how long Run waits for the browser to come
	// back with a code. Long enough for a human to complete a Google sign-in
	// (incl. MFA), short enough that an abandoned login does not hang a shell.
	defaultCallbackTimeout = 3 * time.Minute

	// pkceVerifierBytes yields a 43-char base64url verifier — the RFC 7636
	// §4.1 minimum, comfortably inside the 43–128 range, and exactly the
	// shape tempogate's /token PKCE check (BASE64URL(SHA256(v))) expects.
	pkceVerifierBytes = 32
	stateBytes        = 32
)

// Flow is one engineer-laptop login round-trip against a tempogate issuer. It
// owns no server state; every option has a usable default so the happy path is
// New(WithIssuer(url)).Run(ctx). Injectable seams (clock, browser opener, HTTP
// client) exist so the whole flow is unit-testable headless.
type Flow struct {
	issuer          string
	port            int
	clientID        string
	scope           string
	callbackTimeout time.Duration

	openBrowser func(rawURL string) error
	now         func() time.Time
	httpClient  *http.Client
	out         io.Writer

	newVerifier func() (string, error)
	newState    func() (string, error)
}

// Option configures a Flow. The set mirrors the package-level options pattern
// used across tempogate (oidc.Option, keys.TokenOption): a no-arg-friendly
// constructor whose defaults are production-safe.
type Option func(*Flow)

// WithIssuer sets the tempogate base URL (e.g. https://tempogate.example.com).
// A trailing slash is trimmed so endpoint paths join cleanly.
func WithIssuer(rawURL string) Option {
	return func(f *Flow) { f.issuer = strings.TrimRight(rawURL, "/") }
}

// WithPort pins the loopback port. Zero (the default) asks the OS for a free
// ephemeral port each run — the recommended mode, since tempogate validates
// the loopback redirect by prefix, not exact port.
func WithPort(port int) Option {
	return func(f *Flow) { f.port = port }
}

// WithClientID overrides the client_id presented to tempogate. Defaults to
// "tempogate-cli"; must match a registered OIDC_CLIENTS entry.
func WithClientID(id string) Option {
	return func(f *Flow) {
		if id != "" {
			f.clientID = id
		}
	}
}

// WithOpenBrowser swaps the system-browser opener. Tests inject a function
// that drives the authorize URL headlessly instead of launching a browser.
func WithOpenBrowser(fn func(rawURL string) error) Option {
	return func(f *Flow) { f.openBrowser = fn }
}

// WithClock swaps the clock used to compute the token's absolute expiry. For
// tests.
func WithClock(now func() time.Time) Option {
	return func(f *Flow) { f.now = now }
}

// WithHTTPClient swaps the client used for the /token exchange. For tests
// (e.g. to point at an httptest server with a custom transport).
func WithHTTPClient(c *http.Client) Option {
	return func(f *Flow) { f.httpClient = c }
}

// WithCallbackTimeout overrides the browser-roundtrip deadline. For tests that
// assert the timeout path without waiting the production three minutes.
func WithCallbackTimeout(d time.Duration) Option {
	return func(f *Flow) { f.callbackTimeout = d }
}

// WithOutput redirects the human-facing "open this URL" / progress text. For
// tests; defaults to stderr so it never contaminates a piped token on stdout.
func WithOutput(w io.Writer) Option {
	return func(f *Flow) { f.out = w }
}

// New builds a Flow with production defaults; pass options to override.
func New(opts ...Option) *Flow {
	f := &Flow{
		clientID:        defaultClientID,
		scope:           loginScope,
		callbackTimeout: defaultCallbackTimeout,
		openBrowser:     openSystemBrowser,
		now:             func() time.Time { return time.Now().UTC() },
		httpClient:      &http.Client{Timeout: 30 * time.Second},
		out:             io.Discard,
		newVerifier:     func() (string, error) { return randomURLSafe(pkceVerifierBytes) },
		newState:        func() (string, error) { return randomURLSafe(stateBytes) },
	}
	for _, o := range opts {
		o(f)
	}
	return f
}

// callbackResult is what the one-shot loopback handler hands back to Run: a
// code on success, or a terminal error (state mismatch, user-declined consent,
// or an upstream error tempogate forwarded from Google).
type callbackResult struct {
	code string
	err  error
}

// Run performs the full loopback authorization-code round-trip and returns the
// Token (access + refresh + absolute expiry). It binds 127.0.0.1 before
// opening the browser so the redirect cannot race the listener, validates the
// state echo, and exchanges the code with the PKCE verifier at /token.
func (f *Flow) Run(ctx context.Context) (Token, error) {
	if f.issuer == "" {
		return Token{}, errors.New("cli: issuer is required (pass --issuer or set TEMPOGATE_ISSUER)")
	}

	verifier, err := f.newVerifier()
	if err != nil {
		return Token{}, fmt.Errorf("cli: generate PKCE verifier: %w", err)
	}
	state, err := f.newState()
	if err != nil {
		return Token{}, fmt.Errorf("cli: generate state: %w", err)
	}

	lis, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", f.port))
	if err != nil {
		return Token{}, fmt.Errorf("cli: bind loopback listener: %w", err)
	}
	defer func() { _ = lis.Close() }()

	redirectURI := fmt.Sprintf("http://%s%s", lis.Addr().String(), callbackPath)

	resultCh := make(chan callbackResult, 1)
	srv := &http.Server{
		Handler:           f.callbackHandler(state, resultCh),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if serveErr := srv.Serve(lis); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			resultCh <- callbackResult{err: fmt.Errorf("cli: loopback server: %w", serveErr)}
		}
	}()
	defer func() { _ = srv.Shutdown(context.Background()) }()

	authURL := f.authorizeURL(redirectURI, verifier, state)
	_, _ = fmt.Fprintf(f.out, "Opening your browser to sign in.\nIf it does not open, visit:\n\n  %s\n\n", authURL)
	if openErr := f.openBrowser(authURL); openErr != nil {
		_, _ = fmt.Fprintf(f.out, "Could not open a browser automatically (%v); open the URL above manually.\n", openErr)
	}

	code, err := f.awaitCode(ctx, resultCh)
	if err != nil {
		return Token{}, err
	}

	return f.exchange(ctx, code, verifier, redirectURI)
}

// awaitCode blocks until the loopback handler reports a result, the caller's
// context is cancelled, or the callback deadline elapses — whichever first.
func (f *Flow) awaitCode(ctx context.Context, resultCh <-chan callbackResult) (string, error) {
	timer := time.NewTimer(f.callbackTimeout)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return "", fmt.Errorf("cli: login cancelled: %w", ctx.Err())
	case <-timer.C:
		return "", fmt.Errorf("cli: no authorization code received within %s; aborting login", f.callbackTimeout)
	case r := <-resultCh:
		if r.err != nil {
			return "", r.err
		}
		return r.code, nil
	}
}

// callbackHandler returns the one-shot handler bound on the loopback listener.
// It answers exactly callbackPath, validates the state echo in constant time,
// surfaces an upstream error (declined consent) as a terminal failure, and
// always writes a human-readable page so the browser tab is not left blank.
func (f *Flow) callbackHandler(wantState string, resultCh chan<- callbackResult) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(callbackPath, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()

		if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(wantState)) != 1 {
			writePage(w, http.StatusBadRequest, "Login failed", "State mismatch — possible request forgery. You can close this tab and retry.")
			resultCh <- callbackResult{err: errors.New("cli: callback state did not match; aborting (possible CSRF)")}
			return
		}

		if upErr := q.Get("error"); upErr != "" {
			desc := q.Get("error_description")
			writePage(w, http.StatusBadRequest, "Login failed", fmt.Sprintf("%s: %s", upErr, desc))
			resultCh <- callbackResult{err: fmt.Errorf("cli: authorization failed: %s: %s", upErr, desc)}
			return
		}

		code := q.Get("code")
		if code == "" {
			writePage(w, http.StatusBadRequest, "Login failed", "No authorization code in the callback. You can close this tab and retry.")
			resultCh <- callbackResult{err: errors.New("cli: callback returned no authorization code")}
			return
		}

		writePage(w, http.StatusOK, "Login successful", "You can close this browser tab and return to your terminal.")
		resultCh <- callbackResult{code: code}
	})
	return mux
}

// authorizeURL builds the downstream /authorize request. code_challenge is the
// RFC 7636 S256 transform of verifier — BASE64URL(SHA256(v)) — exactly what
// tempogate's /token re-derives and constant-time compares.
func (f *Flow) authorizeURL(redirectURI, verifier, state string) string {
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", f.clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", f.scope)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("state", state)
	return f.issuer + oidc.AuthorizePath + "?" + q.Encode()
}

// tokenResponse is the RFC 6749 §5.1 success body subset the CLI needs. It is
// shared by the authorization-code exchange and the refresh-token grant; both
// rotate the refresh token, so RefreshToken is always read back.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// oauthErrorBody is the RFC 6749 §5.2 error body tempogate returns on a failed
// exchange; surfacing error_description gives the engineer an actionable line.
type oauthErrorBody struct {
	Err  string `json:"error"`
	Desc string `json:"error_description"`
}

// postTokenForm POSTs an application/x-www-form-urlencoded body to
// <issuer>/token and decodes the RFC 6749 token response. It is the single
// place the HTTP round-trip, the OAuth2 error mapping, and the success-shape
// validation live, so the authorization-code and refresh-token grants cannot
// diverge in how they talk to the endpoint.
func postTokenForm(ctx context.Context, client *http.Client, issuer string, form url.Values) (tokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		issuer+oidc.TokenPath, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenResponse{}, fmt.Errorf("cli: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return tokenResponse{}, fmt.Errorf("cli: token request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return tokenResponse{}, fmt.Errorf("cli: read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var oe oauthErrorBody
		if json.Unmarshal(body, &oe) == nil && oe.Err != "" {
			return tokenResponse{}, fmt.Errorf("cli: token exchange rejected (%s): %s", oe.Err, oe.Desc)
		}
		return tokenResponse{}, fmt.Errorf("cli: token exchange failed: HTTP %d", resp.StatusCode)
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return tokenResponse{}, fmt.Errorf("cli: decode token response: %w", err)
	}
	if tr.AccessToken == "" {
		return tokenResponse{}, errors.New("cli: token response contained no access_token")
	}
	return tr, nil
}

// exchange swaps the authorization code (+ PKCE verifier) for a Token. The
// absolute expiry is computed off the injected clock so callers can persist a
// refresh deadline.
func (f *Flow) exchange(ctx context.Context, code, verifier, redirectURI string) (Token, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", f.clientID)
	form.Set("code_verifier", verifier)

	tr, err := postTokenForm(ctx, f.httpClient, f.issuer, form)
	if err != nil {
		return Token{}, err
	}
	return Token{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		ExpiresAt:    f.now().Add(time.Duration(tr.ExpiresIn) * time.Second),
	}, nil
}

// writePage renders the loopback browser page. msg can carry the upstream
// error/error_description echoed back on the callback query, which is
// attacker-influenceable, so both fields are HTML-escaped before they reach
// the response — a reflected-XSS guard even though the listener is loopback.
func writePage(w http.ResponseWriter, status int, title, msg string) {
	t := html.EscapeString(title)
	m := html.EscapeString(msg)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">`+
		`<title>`+t+`</title></head><body style="font-family:system-ui,sans-serif;`+
		`max-width:32rem;margin:4rem auto;text-align:center"><h1>`+t+`</h1><p>`+
		m+`</p></body></html>`)
}

// randomURLSafe returns base64url(n random bytes) — the same shape the server
// uses for state/code, and a spec-clean PKCE verifier (unreserved charset).
func randomURLSafe(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// openSystemBrowser is the default opener. It shells out to the platform's
// URL handler rather than taking a dependency: a security-sensitive auth tool
// keeps its supply chain minimal, and "open the system browser" is a
// three-line per-OS exec. RFC 8252 §4 anyway requires the external user-agent,
// which this satisfies.
func openSystemBrowser(rawURL string) error {
	var name string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		name, args = "open", []string{rawURL}
	case "windows":
		name, args = "rundll32", []string{"url.dll,FileProtocolHandler", rawURL}
	default:
		name, args = "xdg-open", []string{rawURL}
	}
	// #nosec G204 -- name is one of three compile-time-constant per-OS
	// handlers (never caller-supplied); the only dynamic argument is the
	// authorize URL this process built from its own configured issuer.
	// Launching the user's browser is the whole point (RFC 8252 §4).
	return exec.Command(name, args...).Start()
}
