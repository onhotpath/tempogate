package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/onhotpath/tempogate/oidc"
)

const (
	// deviceGrantType is the RFC 8628 §3.4 grant_type URN. Sent on every poll
	// against /token; the server's grant dispatcher branches on this exact
	// string, so it lives next to the wire constant on the server side.
	deviceGrantType = "urn:ietf:params:oauth:grant-type:device_code"

	// defaultDeviceClientID is the public client_id the headless CLI presents
	// to tempogate for the device flow. The operator registers it once in
	// OIDC__CLIENTS; it is deliberately distinct from the loopback CLI
	// (tempogate-cli) and from tempogate's own internal verification-page
	// client (tempogate-device-ui) so the audit log answers cleanly which
	// flow any given event belongs to.
	defaultDeviceClientID = "tempogate-device"

	// defaultDeviceScope mirrors the loopback default. openid is the OIDC
	// minimum tempogate's /authorize enforces; email lets the issuer apply
	// its domain allowlist on the verification page.
	defaultDeviceScope = "openid email"

	// defaultMinSleep is the floor on any single sleep. Guards against a
	// misbehaving server returning `interval=0` (or omitting the field
	// entirely — at the JSON layer the two are indistinguishable for an int),
	// which would otherwise turn the polling loop into a tight HTTP storm.
	defaultMinSleep = time.Second

	// slowDownBump is the RFC 8628 §3.5 mandated increment to the polling
	// interval when the server returns `slow_down`. Adds to the *current*
	// interval, not the original — repeated bumps accumulate.
	slowDownBump = 5 * time.Second

	// transientBackoffCap caps the exponential backoff on 5xx / network
	// errors at currentInterval × this factor. Bounded growth keeps a long
	// outage from inflating the sleep into hours while still giving the
	// upstream room to recover.
	transientBackoffCap = 4

	// defaultPollFallback is the floor pollDeadline used when the server's
	// expires_in is absent or zero and the caller did not pass
	// WithDevicePollDeadline. 15 minutes matches tempogate's own server-side
	// deviceCodeTTL so the two timeouts hit at roughly the same point.
	defaultPollFallback = 15 * time.Minute
)

// Sentinel errors map the RFC 8628 §3.5 terminal responses to comparable Go
// values. Callers `errors.Is` against these; the wrapped detail (HTTP status,
// error_description) is only included on the non-sentinel default path so the
// sentinel identity is preserved.
var (
	// ErrUserDenied is returned when the user clicks Deny on the verification
	// page. RFC 8628 §3.5 `access_denied`.
	ErrUserDenied = errors.New("cli: user denied the device authorization")

	// ErrDeviceCodeExpired is returned when the user did not approve before
	// the issuer's deviceCodeTTL elapsed. RFC 8628 §3.5 `expired_token`.
	ErrDeviceCodeExpired = errors.New("cli: device code expired before the user completed approval")

	// ErrInvalidGrant is returned for `invalid_grant` — the device_code is
	// unknown or has already been consumed by an earlier successful poll.
	// Almost always a duplicate-poll race.
	ErrInvalidGrant = errors.New("cli: device code rejected (unknown or already consumed)")

	// ErrInvalidClient is returned for `invalid_client` — the client_id is
	// not registered, or is confidential rather than public. Always a
	// programmer/operator misconfiguration, never a transient condition.
	ErrInvalidClient = errors.New("cli: client_id rejected by the issuer")

	// ErrPollDeadlineExceeded is returned when the caller's polling deadline
	// elapses before any terminal response. Distinct from ErrDeviceCodeExpired
	// (which is the server's view) so callers can tell whether the local
	// deadline or the server's TTL fired first.
	ErrPollDeadlineExceeded = errors.New("cli: polling deadline exceeded")
)

// DeviceFlow is one device-authorization round-trip against a tempogate
// issuer. It mirrors the shape of Flow (the loopback variant) — a single
// struct configured by functional options, with one Run(ctx) entry point that
// returns a Token persistable by the existing Save. The interesting state
// lives in the polling loop, which implements the full RFC 8628 §3.5 error
// matrix.
type DeviceFlow struct {
	issuer       string
	clientID     string
	scope        string
	pollDeadline time.Duration
	minSleep     time.Duration

	now        func() time.Time
	sleep      func(ctx context.Context, d time.Duration) error
	httpClient *http.Client
	out        io.Writer
}

// DeviceOption configures a DeviceFlow. Options follow the package's
// functional-options convention: each constructor's defaults are
// production-safe, options exist primarily so tests can inject seams without
// reshaping the production API.
type DeviceOption func(*DeviceFlow)

// WithDeviceIssuer sets the tempogate base URL (e.g.
// https://tempogate.example.com). A trailing slash is trimmed so endpoint
// paths join cleanly.
func WithDeviceIssuer(rawURL string) DeviceOption {
	return func(f *DeviceFlow) { f.issuer = strings.TrimRight(rawURL, "/") }
}

// WithDeviceClientID overrides the client_id presented to tempogate. Defaults
// to "tempogate-device"; must match a registered public OIDC__CLIENTS entry.
// An empty argument is ignored so callers can pass through a flag value
// without a nil-check.
func WithDeviceClientID(id string) DeviceOption {
	return func(f *DeviceFlow) {
		if id != "" {
			f.clientID = id
		}
	}
}

// WithDeviceScope overrides the scope sent on /device_authorization. Defaults
// to "openid email" — the same minimum the loopback flow uses.
func WithDeviceScope(scope string) DeviceOption {
	return func(f *DeviceFlow) { f.scope = scope }
}

// WithDeviceClock swaps the clock used to compute the token's absolute expiry
// and to measure elapsed polling time. For tests.
func WithDeviceClock(now func() time.Time) DeviceOption {
	return func(f *DeviceFlow) { f.now = now }
}

// WithDeviceHTTPClient swaps the client used for /device_authorization and
// /token. For tests (e.g. to point at an httptest server).
func WithDeviceHTTPClient(c *http.Client) DeviceOption {
	return func(f *DeviceFlow) { f.httpClient = c }
}

// WithDeviceOutput redirects the human-facing "open this URL, type this
// code" prompt. Defaults to io.Discard so the CLI binary can layer its own
// presentation on top; the surrounding tempogate login --device wiring
// reassigns it to stderr so the prompt is visible but cannot contaminate a
// piped token on stdout.
func WithDeviceOutput(w io.Writer) DeviceOption {
	return func(f *DeviceFlow) { f.out = w }
}

// WithDevicePollDeadline caps how long Run will poll before giving up. Acts
// as an upper bound: if set and shorter than the server's expires_in, the
// client exits with ErrPollDeadlineExceeded even though the device_code is
// still live on the server. When unset, Run polls until the server's
// expires_in elapses (or the server itself returns expired_token).
func WithDevicePollDeadline(d time.Duration) DeviceOption {
	return func(f *DeviceFlow) { f.pollDeadline = d }
}

// WithDeviceMinSleep clamps the minimum duration of any single sleep,
// defending against a misbehaving server that returns `interval=0` or a
// pathological exponential backoff calculation. Defaults to 1s.
func WithDeviceMinSleep(d time.Duration) DeviceOption {
	return func(f *DeviceFlow) { f.minSleep = d }
}

// NewDeviceFlow builds a DeviceFlow with production-safe defaults; pass
// options to override individual seams.
func NewDeviceFlow(opts ...DeviceOption) *DeviceFlow {
	f := &DeviceFlow{
		clientID:   defaultDeviceClientID,
		scope:      defaultDeviceScope,
		minSleep:   defaultMinSleep,
		now:        func() time.Time { return time.Now().UTC() },
		sleep:      defaultSleep,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		out:        io.Discard,
	}
	for _, o := range opts {
		o(f)
	}
	return f
}

// defaultSleep is the production sleep seam: a context-aware timer that
// returns ctx.Err() if the caller's context is cancelled mid-wait. Tests
// inject a recording function instead so the polling loop is deterministic
// without elapsed wall-clock time.
func defaultSleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// deviceAuthResponse is the RFC 8628 §3.2 success body. Mirrors
// oidc.deviceAuthorizationBody on the server side; defined here separately
// because consumers should not import the server-internal struct.
type deviceAuthResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// pollAction is the typed result of one poll iteration, dispatched by the
// outer loop. Keeping the action distinct from the Go-level error means the
// loop's switch covers exactly the RFC 8628 §3.5 response space rather than
// inferring "what happened" from a sentinel error mid-iteration.
type pollAction int

const (
	// actionDone — server returned a Token; the loop exits cleanly.
	actionDone pollAction = iota
	// actionPending — `authorization_pending`; sleep one interval, retry.
	actionPending
	// actionSlowDown — `slow_down`; bump interval by +5s, sleep, retry.
	actionSlowDown
	// actionTransient — 5xx or network glitch; exponentially back off, retry.
	actionTransient
)

// Run posts /device_authorization, prints the user_code + verification URLs
// on the configured Writer, then polls /token until the server returns a
// Token, a terminal RFC 8628 §3.5 error, the caller's context is cancelled,
// or the polling deadline elapses.
func (f *DeviceFlow) Run(ctx context.Context) (Token, error) {
	if f.issuer == "" {
		return Token{}, errors.New("cli: issuer is required (pass --issuer or set TEMPOGATE__ISSUER)")
	}

	init, err := f.requestDeviceCode(ctx)
	if err != nil {
		return Token{}, err
	}

	f.printPrompt(init)

	return f.pollLoop(ctx, init)
}

// requestDeviceCode performs the RFC 8628 §3.1 POST against
// /device_authorization. invalid_client at this stage is the
// programmer-error sentinel; everything else surfaces with full diagnostic
// detail because the caller cannot recover automatically.
func (f *DeviceFlow) requestDeviceCode(ctx context.Context) (deviceAuthResponse, error) {
	form := url.Values{}
	form.Set("client_id", f.clientID)
	if f.scope != "" {
		form.Set("scope", f.scope)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		f.issuer+oidc.DeviceAuthorizationPath, strings.NewReader(form.Encode()))
	if err != nil {
		return deviceAuthResponse{}, fmt.Errorf("cli: build device authorization request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return deviceAuthResponse{}, fmt.Errorf("cli: device authorization request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return deviceAuthResponse{}, fmt.Errorf("cli: read device authorization response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var oe oauthErrorBody
		if json.Unmarshal(body, &oe) == nil && oe.Err != "" {
			if oe.Err == "invalid_client" {
				return deviceAuthResponse{}, ErrInvalidClient
			}
			return deviceAuthResponse{}, fmt.Errorf("cli: device authorization rejected (%s): %s", oe.Err, oe.Desc)
		}
		return deviceAuthResponse{}, fmt.Errorf("cli: device authorization failed: HTTP %d", resp.StatusCode)
	}

	var dar deviceAuthResponse
	if err := json.Unmarshal(body, &dar); err != nil {
		return deviceAuthResponse{}, fmt.Errorf("cli: decode device authorization response: %w", err)
	}
	if dar.DeviceCode == "" || dar.UserCode == "" {
		return deviceAuthResponse{}, errors.New("cli: device authorization response missing device_code or user_code")
	}
	return dar, nil
}

// printPrompt writes the RFC 8628 §3.3 user-facing instructions. The
// verification_uri_complete branch is rendered only when the server provides
// one — it is OPTIONAL per spec and a server that omits it should not
// surface as a dangling "(or, …)" paragraph.
func (f *DeviceFlow) printPrompt(init deviceAuthResponse) {
	_, _ = fmt.Fprintf(f.out, `A login URL has been generated. On any device with a browser, open:

  %s

And enter this code:

  %s
`, init.VerificationURI, init.UserCode)
	if init.VerificationURIComplete != "" {
		_, _ = fmt.Fprintf(f.out, `
(or, to skip the manual entry, scan/open:
  %s )
`, init.VerificationURIComplete)
	}
	_, _ = fmt.Fprintln(f.out, "\nWaiting for you to approve in your browser…")
}

// pollLoop drives the RFC 8628 §3.5 state machine. The dispatch is:
//
//   - actionDone     → return Token.
//   - actionPending  → sleep(interval), backoff resets to interval.
//   - actionSlowDown → interval += 5s, sleep(interval), backoff resets.
//   - actionTransient → sleep(backoff), backoff *= 2 (capped at interval×4).
//
// Between iterations we recheck ctx.Done and the elapsed deadline so a
// cancellation or expiry mid-loop is observed before the next HTTP round-trip.
func (f *DeviceFlow) pollLoop(ctx context.Context, init deviceAuthResponse) (Token, error) {
	// A server that omits `interval` (JSON int → 0) or sets it below the
	// configured floor is clamped to minSleep, not to some other "default
	// poll interval" — the operator's floor is the explicit policy.
	interval := time.Duration(init.Interval) * time.Second
	if interval < f.minSleep {
		interval = f.minSleep
	}

	deadline := time.Duration(init.ExpiresIn) * time.Second
	if f.pollDeadline > 0 {
		deadline = f.pollDeadline
	}
	if deadline <= 0 {
		deadline = defaultPollFallback
	}

	start := f.now()
	backoff := interval

	for {
		if err := ctx.Err(); err != nil {
			return Token{}, err
		}
		if f.now().Sub(start) >= deadline {
			return Token{}, ErrPollDeadlineExceeded
		}

		tok, action, err := f.pollOnce(ctx, init.DeviceCode)
		if err != nil {
			return Token{}, err
		}

		var sleepFor time.Duration
		switch action {
		case actionDone:
			return tok, nil
		case actionPending:
			sleepFor = interval
			backoff = interval
		case actionSlowDown:
			interval += slowDownBump
			sleepFor = interval
			backoff = interval
		case actionTransient:
			sleepFor = backoff
			backoff *= 2
			if maxBackoff := interval * time.Duration(transientBackoffCap); backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
		if sleepFor < f.minSleep {
			sleepFor = f.minSleep
		}
		if err := f.sleep(ctx, sleepFor); err != nil {
			return Token{}, err
		}
	}
}

// pollOnce issues a single /token request and classifies the response into a
// pollAction. The non-recoverable sentinel errors (ErrUserDenied,
// ErrDeviceCodeExpired, ErrInvalidGrant, ErrInvalidClient) short-circuit by
// returning a Go-level error; the recoverable conditions (pending, slow_down,
// 5xx, network) return an action for the outer loop to schedule the next
// sleep against. Context cancellation surfaces as ctx.Err() rather than as a
// transient backoff so a cancelled caller exits immediately.
func (f *DeviceFlow) pollOnce(ctx context.Context, deviceCode string) (Token, pollAction, error) {
	form := url.Values{}
	form.Set("grant_type", deviceGrantType)
	form.Set("device_code", deviceCode)
	form.Set("client_id", f.clientID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		f.issuer+oidc.TokenPath, strings.NewReader(form.Encode()))
	if err != nil {
		return Token{}, 0, fmt.Errorf("cli: build poll request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := f.httpClient.Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Token{}, 0, ctxErr
		}
		return Token{}, actionTransient, nil
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Token{}, 0, ctxErr
		}
		return Token{}, actionTransient, nil
	}

	if resp.StatusCode >= 500 && resp.StatusCode < 600 {
		return Token{}, actionTransient, nil
	}

	if resp.StatusCode == http.StatusOK {
		var tr tokenResponse
		if err := json.Unmarshal(body, &tr); err != nil {
			return Token{}, 0, fmt.Errorf("cli: decode token response: %w", err)
		}
		if tr.AccessToken == "" {
			return Token{}, 0, errors.New("cli: token response contained no access_token")
		}
		return Token{
			AccessToken:  tr.AccessToken,
			RefreshToken: tr.RefreshToken,
			ExpiresAt:    f.now().Add(time.Duration(tr.ExpiresIn) * time.Second),
		}, actionDone, nil
	}

	var oe oauthErrorBody
	if jerr := json.Unmarshal(body, &oe); jerr != nil || oe.Err == "" {
		return Token{}, 0, fmt.Errorf("cli: poll failed: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	switch oe.Err {
	case "authorization_pending":
		return Token{}, actionPending, nil
	case "slow_down":
		return Token{}, actionSlowDown, nil
	case "access_denied":
		return Token{}, 0, ErrUserDenied
	case "expired_token":
		return Token{}, 0, ErrDeviceCodeExpired
	case "invalid_grant":
		return Token{}, 0, ErrInvalidGrant
	case "invalid_client":
		return Token{}, 0, ErrInvalidClient
	default:
		return Token{}, 0, fmt.Errorf("cli: poll rejected (HTTP %d, %s): %s", resp.StatusCode, oe.Err, oe.Desc)
	}
}
