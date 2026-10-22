package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// refreshSkew is how long before expiry EnsureFresh proactively renews. Five
// minutes is comfortably longer than any single Temporal call yet short enough
// that a token handed out is usable for its whole advertised life.
const refreshSkew = 5 * time.Minute

type refreshConfig struct {
	now        func() time.Time
	httpClient *http.Client
	skew       time.Duration
}

// RefreshOption tunes EnsureFresh. The production call is the three-arg form;
// the options exist so tests can pin the clock and redirect HTTP without a
// real issuer.
type RefreshOption func(*refreshConfig)

// WithRefreshClock swaps the clock used for the expiry comparison and the new
// token's absolute expiry. For tests.
func WithRefreshClock(now func() time.Time) RefreshOption {
	return func(c *refreshConfig) { c.now = now }
}

// WithRefreshHTTPClient swaps the client used for the refresh-token grant. For
// tests (e.g. an httptest server's client).
func WithRefreshHTTPClient(client *http.Client) RefreshOption {
	return func(c *refreshConfig) { c.httpClient = client }
}

// EnsureFresh returns a usable Token, renewing it first if it is within five
// minutes of expiry. The common path is a pure file read with no network, so
// `tempogate token` stays fast; only the renewal path talks to the issuer.
//
// A missing token file surfaces as ErrNoToken (run `tempogate login`); a
// rejected refresh (revoked / rotated-away / expired) fails cleanly without
// overwriting or silently returning the stale token, so a caller never acts
// on a credential the server has already disowned.
func EnsureFresh(ctx context.Context, path, issuer string, opts ...RefreshOption) (Token, error) {
	cfg := &refreshConfig{
		now:        time.Now,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		skew:       refreshSkew,
	}
	for _, o := range opts {
		o(cfg)
	}

	tok, err := Load(path)
	if err != nil {
		return Token{}, err
	}

	if cfg.now().Before(tok.ExpiresAt.Add(-cfg.skew)) {
		return tok, nil
	}

	if tok.RefreshToken == "" {
		return Token{}, errors.New("cli: token is expiring and has no refresh token; run `tempogate login`")
	}

	clientID := tok.ClientID
	if clientID == "" {
		clientID = audience(tok.AccessToken)
	}
	if clientID == "" {
		return Token{}, errors.New("cli: token file does not record its client_id; run `tempogate login`")
	}

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", tok.RefreshToken)
	// A public client identifies itself on refresh (OAuth 2.1 §4.3.1); the
	// issuer rejects a refresh token presented by any other client.
	form.Set("client_id", clientID)

	tr, err := postTokenForm(ctx, cfg.httpClient, strings.TrimRight(issuer, "/"), form)
	if err != nil {
		return Token{}, fmt.Errorf("cli: refresh failed: %w", err)
	}

	refreshed := Token{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		ExpiresAt:    cfg.now().Add(time.Duration(tr.ExpiresIn) * time.Second),
		ClientID:     clientID,
	}
	// tempogate rotates the refresh token on every exchange; if a deployment
	// ever omits it, keep the one we hold so the next renewal still has a
	// credential to present rather than wedging the session.
	if refreshed.RefreshToken == "" {
		refreshed.RefreshToken = tok.RefreshToken
	}

	if err := Save(path, refreshed); err != nil {
		return Token{}, err
	}
	return refreshed, nil
}

// audience recovers the client a token file was issued to when the file
// predates the persisted client_id: tempogate stamps the requesting client as
// the access token's aud. The JWT is the CLI's own credential and is not
// verified here; a wrong guess only means the issuer refuses the refresh.
// It returns "" when the token is not a JWT with exactly one audience.
func audience(jwt string) string {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Aud json.RawMessage `json:"aud"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return ""
	}
	var one string
	if json.Unmarshal(claims.Aud, &one) == nil {
		return one
	}
	var many []string
	if json.Unmarshal(claims.Aud, &many) == nil && len(many) == 1 {
		return many[0]
	}
	return ""
}
