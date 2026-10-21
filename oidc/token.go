package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/onhotpath/tempogate/keys"
)

const (
	// TokenPath and UserInfoPath are exported so the OIDC discovery document
	// can advertise the same token_endpoint / userinfo_endpoint these
	// handlers register, keeping the two from drifting.
	TokenPath    = "/token"
	UserInfoPath = "/userinfo"

	// basicRealm names the protection space in the WWW-Authenticate
	// challenge sent when HTTP Basic client authentication fails.
	basicRealm = "tempogate"

	grantAuthorizationCode = "authorization_code"
	grantRefreshToken      = "refresh_token"
	// grantDeviceCode is the RFC 8628 §3.4 grant_type the CLI presents on every
	// poll. The full URN is part of the contract — clients copy it verbatim.
	grantDeviceCode = "urn:ietf:params:oauth:grant-type:device_code"

	// DefaultAccessTokenTTL is the lifetime of a minted access token
	// (OIDC_ACCESS_TOKEN_TTL). Short enough that a leaked token has a
	// bounded blast radius; the refresh token covers continuity.
	DefaultAccessTokenTTL = 4 * time.Hour

	// IDTokenTTL is the lifetime of a minted ID token. The relying party
	// verifies it once, at login, and must not use it as a credential, so it
	// lives only long enough to cover the exchange and clock skew.
	IDTokenTTL = 5 * time.Minute

	// DefaultRefreshTokenTTL is the idle lifetime of each rotated refresh
	// token (OIDC_REFRESH_TOKEN_TTL): a session unused for this long ends.
	DefaultRefreshTokenTTL = 7 * 24 * time.Hour

	// DefaultRefreshMaxLifetime is the absolute session lifetime counted
	// from the original sign-in (OIDC_REFRESH_MAX_LIFETIME). Rotation never
	// extends it, so a session is re-authenticated upstream (and re-checked
	// against Google) at least this often.
	DefaultRefreshMaxLifetime = 30 * 24 * time.Hour

	refreshEntropyBytes  = 32
	familyIDEntropyBytes = 16
)

var (
	// ErrRefreshNotFound is returned by ConsumeRefresh when no live token
	// matches: it was never issued, was issued to a different client, was
	// revoked, or its row was reaped. The /token handler maps this to OAuth2
	// invalid_grant.
	ErrRefreshNotFound = errors.New("oidc: refresh token not found")

	// ErrRefreshReused is returned by ConsumeRefresh when the presented token
	// was already rotated. Together with it the store returns the consumed
	// token's row, so the handler can revoke its family (RFC 9700 §4.14.2).
	ErrRefreshReused = errors.New("oidc: refresh token already used")

	// ErrRefreshFamilyRevoked is returned by SaveRefresh when the token's
	// family was revoked, so a rotation racing a revocation cannot keep the
	// chain alive.
	ErrRefreshFamilyRevoked = errors.New("oidc: refresh token family revoked")
)

// Refresh is the opaque, single-use credential a client presents to obtain a
// fresh access token without another Google round-trip. Token is the random
// secret the client holds; JTI references the access token minted alongside
// it, so an operator can correlate a refresh row with the JWT it renewed.
// Each exchange consumes the row and mints a new one (rotation).
//
// FamilyID and AuthTime are fixed at sign-in and carried through every
// rotation: FamilyID names the chain so a replay or an operator can revoke
// all of it at once, and AuthTime anchors the absolute session lifetime.
type Refresh struct {
	Token     string
	JTI       string
	ClientID  string
	Subject   string
	Email     string
	FamilyID  string
	AuthTime  time.Time
	CreatedAt time.Time
	ExpiresAt time.Time
}

// TokenStore is the consumer-side state interface for the /token handler (see
// state/doc.go). It is distinct from CallbackStore — the callback side mints
// the auth code; the token side redeems it (single-use) and manages the
// refresh-token lifecycle. The concrete sqlite.Store satisfies it
// structurally; the type is exported only so the composition root can inject
// it via fx.As.
type TokenStore interface {
	// ConsumeAuthCode atomically marks the authorization code redeemed at
	// the given time and records familyID as the refresh-token family the
	// redemption starts, enforcing single use. The consumed code stays
	// behind as a tombstone: presenting it again returns it, carrying the
	// first redemption's FamilyID, with ErrAuthCodeReused. Any other miss
	// returns ErrAuthCodeNotFound. Expiry is the caller's concern (it owns
	// the clock); a consumed-but-expired code is still returned and then
	// rejected.
	ConsumeAuthCode(ctx context.Context, code, familyID string, at time.Time) (AuthCode, error)

	// SaveRefresh persists a freshly minted refresh token. It returns
	// ErrRefreshFamilyRevoked when r's family has been revoked.
	SaveRefresh(ctx context.Context, r Refresh) error

	// ConsumeRefresh atomically marks the live refresh token issued to
	// clientID consumed at the given time, enforcing single use so every
	// exchange rotates the token. The consumed row stays behind as a
	// tombstone: presenting it again returns its row with ErrRefreshReused.
	// Any other miss returns ErrRefreshNotFound; a token issued to another
	// client does not match and is left in place, so a cross-client attempt
	// cannot burn it.
	ConsumeRefresh(ctx context.Context, token, clientID string, at time.Time) (Refresh, error)

	// RevokeRefreshFamily revokes every token in the family, live or
	// consumed, and reports how many live tokens it revoked.
	RevokeRefreshFamily(ctx context.Context, familyID string, at time.Time) (int, error)
}

// TokenClients is the client registry as the /token handler needs it: look
// a client up to learn its grants and whether it is confidential, and verify
// a presented secret. ClientRegistry satisfies it structurally; the narrow
// interface (consumer-defines-the-interface, see state/doc.go) keeps the
// /token handler decoupled from the registry's redirect-allowlist concerns.
type TokenClients interface {
	Lookup(clientID string) (Client, bool)
	Authenticate(clientID, secret string) bool
}

// Token serves POST /token: it completes the authorization-code flow by
// exchanging a redeemed code for a signed JWT (a confidential client always
// authenticates its secret; PKCE is verified whenever the code carries a
// challenge), renews sessions via the refresh-token grant, and (when a
// DeviceCodeStore is wired in) redeems the RFC 8628 device-code grant the CLI
// polls on.
type Token struct {
	store          TokenStore
	devices        DeviceCodeStore
	signer         *keys.Signer
	clients        TokenClients
	allowedDomains map[string]struct{}
	logger         *slog.Logger
	now            func() time.Time
	newRefresh     func() (string, error)
	observer       TokenObserver

	accessTTL          time.Duration
	refreshTTL         time.Duration
	refreshMaxLifetime time.Duration
}

type TokenOption func(*Token)

// WithTokenClock swaps the clock used for expiry checks and refresh-token
// timestamps. For tests.
func WithTokenClock(now func() time.Time) TokenOption {
	return func(t *Token) { t.now = now }
}

// WithRefreshGenerator swaps the opaque refresh-token generator. For tests.
func WithRefreshGenerator(fn func() (string, error)) TokenOption {
	return func(t *Token) { t.newRefresh = fn }
}

// WithAllowedDomains sets the email-domain allowlist (OIDC_ALLOWED_DOMAINS)
// the refresh grant re-applies on every exchange, so removing a domain ends
// its users' sessions at their next refresh instead of at their absolute
// expiry. Without it no refresh is honoured, mirroring the callback, where
// an empty allowlist admits nobody.
func WithAllowedDomains(raw string) TokenOption {
	return func(t *Token) { t.allowedDomains = parseDomains(raw) }
}

// WithTokenLifetimes sets the access-token TTL, the idle TTL of each rotated
// refresh token, and the absolute session lifetime counted from sign-in.
// Zero keeps the corresponding default; ValidateTokenLifetimes is the
// startup check for operator-supplied values.
func WithTokenLifetimes(access, refreshIdle, refreshMax time.Duration) TokenOption {
	return func(t *Token) {
		if access > 0 {
			t.accessTTL = access
		}
		if refreshIdle > 0 {
			t.refreshTTL = refreshIdle
		}
		if refreshMax > 0 {
			t.refreshMaxLifetime = refreshMax
		}
	}
}

// WithTokenLogger sets the structured log sink for refresh-token security
// events (reuse detection, domain revocation). Defaults to a discarding
// logger so tests and direct constructors stay quiet.
func WithTokenLogger(l *slog.Logger) TokenOption {
	return func(t *Token) { t.logger = l }
}

// ValidateTokenLifetimes rejects a lifetime configuration that would make
// the refresh-token lifecycle incoherent: every value must be positive, an
// access token must expire before the refresh token that renews it would go
// idle, and the idle lifetime cannot exceed the absolute one.
func ValidateTokenLifetimes(access, refreshIdle, refreshMax time.Duration) error {
	switch {
	case access <= 0 || refreshIdle <= 0 || refreshMax <= 0:
		return fmt.Errorf("oidc: OIDC_ACCESS_TOKEN_TTL (%s), OIDC_REFRESH_TOKEN_TTL (%s) and OIDC_REFRESH_MAX_LIFETIME (%s) must all be positive", access, refreshIdle, refreshMax)
	case access >= refreshIdle:
		return fmt.Errorf("oidc: OIDC_ACCESS_TOKEN_TTL (%s) must be shorter than OIDC_REFRESH_TOKEN_TTL (%s)", access, refreshIdle)
	case refreshIdle > refreshMax:
		return fmt.Errorf("oidc: OIDC_REFRESH_TOKEN_TTL (%s) must not exceed OIDC_REFRESH_MAX_LIFETIME (%s)", refreshIdle, refreshMax)
	}
	return nil
}

// WithDeviceCodeStore plugs the RFC 8628 device-code grant in. Without it,
// /token rejects device_code as unsupported_grant_type; with it, the full
// §3.5 polling state machine is exposed. Declared as a separate dependency
// (rather than folded into TokenStore) so the auth-code surface stays
// minimal for deployments that opt out of the device flow.
func WithDeviceCodeStore(s DeviceCodeStore) TokenOption {
	return func(t *Token) { t.devices = s }
}

// WithTokenObserver reports every /token outcome (minted, or the OAuth2
// error code) and every refresh-family revocation to o, e.g. the Prometheus
// metrics. Nil keeps the no-op default.
func WithTokenObserver(o TokenObserver) TokenOption {
	return func(t *Token) {
		if o != nil {
			t.observer = o
		}
	}
}

func NewToken(store TokenStore, signer *keys.Signer, clients TokenClients, opts ...TokenOption) *Token {
	t := &Token{
		store:              store,
		signer:             signer,
		clients:            clients,
		logger:             slog.New(slog.DiscardHandler),
		now:                func() time.Time { return time.Now().UTC() },
		newRefresh:         randomRefresh,
		observer:           nopObserver{},
		accessTTL:          DefaultAccessTokenTTL,
		refreshTTL:         DefaultRefreshTokenTTL,
		refreshMaxLifetime: DefaultRefreshMaxLifetime,
	}
	for _, o := range opts {
		o(t)
	}
	return t
}

// tokenInput takes the raw form body verbatim: OAuth2 §4.1.3 mandates
// application/x-www-form-urlencoded, and parsing it by hand keeps the
// grant-type dispatch explicit rather than bending huma's JSON schema around
// two mutually exclusive parameter sets.
type tokenInput struct {
	RawBody []byte `contentType:"application/x-www-form-urlencoded"`

	// Authorization carries HTTP Basic client credentials. RFC 6749 §2.3.1
	// RECOMMENDS Basic for confidential clients, and golang.org/x/oauth2
	// (the stack the Temporal Web UI uses) tries Basic first under
	// AuthStyleAutoDetect, so the confidential carve-out must read it here as
	// well as from the form body.
	Authorization string `header:"Authorization"`
}

// tokenOutput is the RFC 6749 §5.1 token response. The no-store/no-cache
// headers are mandated by §5.1 so intermediaries never retain a bearer token.
type tokenOutput struct {
	CacheControl string `header:"Cache-Control"`
	Pragma       string `header:"Pragma"`
	Body         tokenResponse
}

type tokenResponse struct {
	// AccessToken is the credential for Temporal: it carries the
	// permissions and the Temporal audience. ExpiresIn describes it.
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	// IDToken is the relying party's proof of login (OIDC Core §2): aud is
	// the client, identity claims only, no permissions, short-lived. It is
	// a separate token so a relying party that receives it, or leaks it,
	// holds nothing Temporal would authorize.
	IDToken string `json:"id_token"`
}

func (t *Token) Register(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "token",
		Method:      http.MethodPost,
		Path:        TokenPath,
		Summary:     "OAuth2 token endpoint (authorization_code + refresh_token grants)",
		Tags:        []string{"oidc"},
	}, func(ctx context.Context, in *tokenInput) (*tokenOutput, error) {
		return t.handle(ctx, in)
	})
}

func (t *Token) handle(ctx context.Context, in *tokenInput) (*tokenOutput, error) {
	out, err := t.grant(ctx, in)
	return out, withBasicChallenge(err, in.Authorization)
}

func (t *Token) grant(ctx context.Context, in *tokenInput) (*tokenOutput, error) {
	form, err := url.ParseQuery(string(in.RawBody))
	if err != nil {
		t.observer.ObserveToken(grantLabelOther, "invalid_request")
		return nil, oauthErr(http.StatusBadRequest, "invalid_request", "malformed form body")
	}

	out, err := t.dispatch(ctx, form, in.Authorization)
	t.observer.ObserveToken(grantLabel(form.Get("grant_type")), tokenErrorCode(err))
	return out, err
}

func (t *Token) dispatch(ctx context.Context, form url.Values, authorization string) (*tokenOutput, error) {
	if err := checkParamLengths(
		paramCap{"client_id", form.Get("client_id"), maxClientIDLen},
		paramCap{"redirect_uri", form.Get("redirect_uri"), maxRedirectURILen},
		paramCap{"code", form.Get("code"), maxCredentialLen},
		paramCap{"code_verifier", form.Get("code_verifier"), maxCredentialLen},
		paramCap{"refresh_token", form.Get("refresh_token"), maxCredentialLen},
		paramCap{"device_code", form.Get("device_code"), maxCredentialLen},
	); err != nil {
		return nil, err
	}

	switch form.Get("grant_type") {
	case grantAuthorizationCode:
		return t.authorizationCodeGrant(ctx, form, authorization)
	case grantRefreshToken:
		return t.refreshTokenGrant(ctx, form, authorization)
	case grantDeviceCode:
		return t.deviceCodeGrant(ctx, form, authorization)
	case "":
		return nil, oauthErr(http.StatusBadRequest, "invalid_request", "grant_type is required")
	default:
		return nil, oauthErr(http.StatusBadRequest, "unsupported_grant_type", "only authorization_code, refresh_token, and urn:ietf:params:oauth:grant-type:device_code are supported")
	}
}

// AuthCodeRedemptionRequest is the parsed input to the auth-code-grant
// redemption step, already past form parsing and Basic-auth parsing. The
// public POST /token handler and the device-flow verification UI both build
// one of these and hand it to RedeemAuthorizationCode; neither needs an HTTP
// round-trip to do so.
type AuthCodeRedemptionRequest struct {
	Code         string
	ClientID     string
	RedirectURI  string
	CodeVerifier string // PKCE; empty when the code carries no challenge.
	ClientSecret string // required for a confidential client; empty for a public one.
}

// AuthCodeRedemption is the consumed AuthCode's claims, ready for either
// id-token minting (the public /token handler) or in-process session
// issuance (the device-flow verification UI).
type AuthCodeRedemption struct {
	Identity Identity
	ClientID string
	Nonce    string

	// FamilyID is the refresh-token family this redemption starts. It is
	// recorded against the code as it is consumed, so a later replay of the
	// code can revoke what was issued here.
	FamilyID string
}

// RedeemAuthorizationCode validates a presented authorization code,
// authenticates the client, consumes the code single-use, enforces PKCE when
// the code was minted with a challenge, and returns the code's claims. No
// HTTP shape involved: callers have already parsed their inputs. Errors are returned
// as OAuth2-shaped huma.StatusErrors via oauthErr so the public /token
// handler can propagate them verbatim; in-process callers can inspect
// errors.Is(..., huma.StatusError) or just surface the message.
func (t *Token) RedeemAuthorizationCode(ctx context.Context, in AuthCodeRedemptionRequest) (*AuthCodeRedemption, error) {
	if in.Code == "" {
		return nil, oauthErr(http.StatusBadRequest, "invalid_request", "code is required")
	}

	// Client authentication is a property of the request, not of the code,
	// so it runs before the single-use code is consumed: a party holding a
	// leaked code but not the secret cannot redeem it, nor burn it for the
	// real client.
	c, err := t.authenticateClient(in.ClientID, in.ClientSecret, GrantTypeAuthorizationCode)
	if err != nil {
		return nil, err
	}
	// A public client has no secret, so the verifier is its only proof.
	if c.Secret == "" && in.CodeVerifier == "" {
		return nil, oauthErr(http.StatusBadRequest, "invalid_request", "code_verifier is required (PKCE)")
	}
	// A malformed verifier is a malformed request, refused before the code
	// is consumed so it cannot burn the legitimate client's code.
	if in.CodeVerifier != "" && !validCodeVerifier(in.CodeVerifier) {
		return nil, oauthErr(http.StatusBadRequest, "invalid_request", "code_verifier must be 43-128 characters of [A-Za-z0-9-._~] (RFC 7636)")
	}

	familyID, err := randomFamilyID()
	if err != nil {
		return nil, fmt.Errorf("oidc: generate refresh token family: %w", err)
	}
	now := t.now()
	ac, err := t.store.ConsumeAuthCode(ctx, in.Code, familyID, now)
	if errors.Is(err, ErrAuthCodeReused) {
		// RFC 6749 §4.1.2: one of the two presenters is not the client, and
		// the server cannot tell which, so what the first redemption issued
		// is revoked. Access tokens already minted stay valid at Temporal
		// until they expire; their refresh tokens end here. A tombstone
		// always names its family; the guard keeps an empty id from ever
		// matching unrelated rows.
		if ac.FamilyID != "" {
			if err := t.revokeFamily(ctx, Refresh{FamilyID: ac.FamilyID, ClientID: ac.ClientID, Email: ac.Email}, now,
				"auth_code_reuse", "oidc: authorization code reuse detected; revoked the tokens issued from it"); err != nil {
				return nil, err
			}
		}
		return nil, oauthErr(http.StatusBadRequest, "invalid_grant", "unknown or already-redeemed authorization code")
	}
	if errors.Is(err, ErrAuthCodeNotFound) {
		return nil, oauthErr(http.StatusBadRequest, "invalid_grant", "unknown or already-redeemed authorization code")
	}
	if err != nil {
		return nil, fmt.Errorf("oidc: consume auth code: %w", err)
	}

	if now.After(ac.ExpiresAt) {
		return nil, oauthErr(http.StatusBadRequest, "invalid_grant", "authorization code expired")
	}
	if ac.Subject == "" {
		return nil, errLegacyGrant("authorization code")
	}
	if in.ClientID != ac.ClientID {
		return nil, oauthErr(http.StatusBadRequest, "invalid_grant", "client_id does not match the authorization request")
	}
	if in.RedirectURI != ac.RedirectURI {
		return nil, oauthErr(http.StatusBadRequest, "invalid_grant", "redirect_uri does not match the authorization request")
	}

	// PKCE is enforced on top of client authentication whenever the code was
	// minted with a challenge, confidential clients included (RFC 9700
	// §2.1.1). A code with no challenge is only minted for a confidential
	// client (the /authorize carve-out), so a public client presenting one
	// fails closed.
	switch {
	case ac.CodeChallenge != "":
		if in.CodeVerifier == "" {
			return nil, oauthErr(http.StatusBadRequest, "invalid_grant", "code_verifier is required (PKCE)")
		}
		if !verifyPKCE(in.CodeVerifier, ac.CodeChallenge) {
			return nil, oauthErr(http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		}
	case c.Secret == "":
		return nil, oauthErr(http.StatusBadRequest, "invalid_grant", "authorization code is not bound to a PKCE challenge")
	}

	return &AuthCodeRedemption{
		Identity: Identity{Subject: ac.Subject, Email: ac.Email},
		ClientID: ac.ClientID,
		Nonce:    ac.Nonce,
		FamilyID: familyID,
	}, nil
}

// authenticateClient resolves the client a /token request speaks for,
// authenticates it, and checks that its registration allows grant g. A
// confidential client always proves its secret (RFC 6749 §3.2.1), whatever
// other proof the request carries. A public client has none to prove, but a
// secret it does present must still be valid rather than silently ignored.
func (t *Token) authenticateClient(clientID, secret string, g GrantType) (Client, error) {
	c, ok := t.clients.Lookup(clientID)
	if !ok {
		return Client{}, oauthErr(http.StatusUnauthorized, "invalid_client", "unknown client")
	}
	if (c.Secret != "" || secret != "") && !t.clients.Authenticate(clientID, secret) {
		return Client{}, oauthErr(http.StatusUnauthorized, "invalid_client", "client authentication failed")
	}
	if !c.Allows(g) {
		return Client{}, oauthErr(http.StatusBadRequest, "unauthorized_client", "client is not registered for this grant type")
	}
	return c, nil
}

// clientCredentials reads the client_id and secret a /token request presents:
// HTTP Basic when sent, otherwise the form body (RFC 6749 §2.3.1).
func clientCredentials(form url.Values, authHeader string) (id, secret string) {
	if id, secret, ok := parseBasicAuth(authHeader); ok {
		return id, secret
	}
	return form.Get("client_id"), form.Get("client_secret")
}

func (t *Token) authorizationCodeGrant(ctx context.Context, form url.Values, authHeader string) (*tokenOutput, error) {
	clientID, presentedSecret := clientCredentials(form, authHeader)
	r, err := t.RedeemAuthorizationCode(ctx, AuthCodeRedemptionRequest{
		Code:         form.Get("code"),
		ClientID:     clientID,
		RedirectURI:  form.Get("redirect_uri"),
		CodeVerifier: form.Get("code_verifier"),
		ClientSecret: presentedSecret,
	})
	if err != nil {
		return nil, err
	}
	return t.issue(ctx, r.Identity, r.ClientID, r.Nonce, lineage{familyID: r.FamilyID, authTime: t.now()})
}

func (t *Token) refreshTokenGrant(ctx context.Context, form url.Values, authHeader string) (*tokenOutput, error) {
	token := form.Get("refresh_token")
	if token == "" {
		return nil, oauthErr(http.StatusBadRequest, "invalid_request", "refresh_token is required")
	}

	// A refresh token is bound to the client it was issued to (RFC 9700
	// §4.14), which must authenticate when confidential (RFC 6749 §6) and
	// identify itself when public (OAuth 2.1 §4.3.1). As with the auth code,
	// the client is authenticated before anything is consumed, and the
	// binding is part of the atomic consume, so neither a failed nor a
	// cross-client attempt burns the legitimate client's token.
	clientID, secret := clientCredentials(form, authHeader)
	if _, err := t.authenticateClient(clientID, secret, GrantTypeRefreshToken); err != nil {
		return nil, err
	}

	now := t.now()
	rt, err := t.store.ConsumeRefresh(ctx, token, clientID, now)
	if errors.Is(err, ErrRefreshReused) {
		// A rotated token came back: either the client or an attacker holds
		// a stale copy, and the server cannot tell which, so the whole
		// family goes (RFC 9700 §4.14.2). That includes the newer token the
		// other party holds. A duplicate presentation that lost a race to
		// rotate the same live token lands here too; it is a replay by
		// definition once one presentation has won.
		if err := t.revokeFamily(ctx, rt, now, "refresh_token_reuse",
			"oidc: refresh token reuse detected; revoked the token family"); err != nil {
			return nil, err
		}
		return nil, oauthErr(http.StatusBadRequest, "invalid_grant", "refresh token already used; the session has been revoked")
	}
	if errors.Is(err, ErrRefreshNotFound) {
		return nil, oauthErr(http.StatusBadRequest, "invalid_grant", "unknown, revoked, or other client's refresh token")
	}
	if err != nil {
		return nil, fmt.Errorf("oidc: consume refresh token: %w", err)
	}

	if now.After(rt.ExpiresAt) {
		return nil, oauthErr(http.StatusBadRequest, "invalid_grant", "refresh token expired")
	}
	// ExpiresAt is already capped at mint time; checking the absolute
	// lifetime here too applies a lowered OIDC_REFRESH_MAX_LIFETIME (and the
	// migration's backfilled auth_time) to tokens minted before it.
	if !now.Before(rt.AuthTime.Add(t.refreshMaxLifetime)) {
		return nil, oauthErr(http.StatusBadRequest, "invalid_grant", "session reached its maximum lifetime; sign in again")
	}
	if rt.Subject == "" {
		return nil, errLegacyGrant("refresh token")
	}
	// The allowlist is re-applied on every refresh, so removing a domain
	// ends its sessions at their next refresh rather than at their absolute
	// expiry. The family is revoked so no sibling token outlives the
	// decision even if the domain is added back.
	if !emailDomainAllowed(t.allowedDomains, rt.Email) {
		if err := t.revokeFamily(ctx, rt, now, "refresh_domain_not_allowed",
			"oidc: refresh refused for a domain no longer allowed; revoked the token family"); err != nil {
			return nil, err
		}
		return nil, oauthErr(http.StatusBadRequest, "invalid_grant", "email domain is no longer allowed")
	}

	// No nonce on refresh: OIDC Core binds nonce to the original
	// authentication request, not to silently-renewed tokens, and the
	// relying party does not re-check it on the refresh path.
	return t.issue(ctx, Identity{Subject: rt.Subject, Email: rt.Email}, rt.ClientID, "", lineage{familyID: rt.FamilyID, authTime: rt.AuthTime})
}

// errLegacyGrant rejects a grant persisted before schema 0010 recorded the
// Google subject. Such a grant was admitted without the hosted-domain check
// and cannot be minted with the correct sub, so the holder must sign in
// again; doing so once is the whole upgrade cost.
func errLegacyGrant(kind string) *oauthError {
	return oauthErr(http.StatusBadRequest, "invalid_grant", kind+" predates this tempogate version; sign in again")
}

// revokeFamily revokes rt's family and records the security event. The
// token value is never logged; the family id is what an operator needs to
// correlate with `tempogate sessions`.
func (t *Token) revokeFamily(ctx context.Context, rt Refresh, now time.Time, event, msg string) error {
	revoked, err := t.store.RevokeRefreshFamily(ctx, rt.FamilyID, now)
	if err != nil {
		return fmt.Errorf("oidc: revoke refresh token family: %w", err)
	}
	t.observer.ObserveFamilyRevoked(event)
	t.logger.WarnContext(ctx, msg,
		"event", event,
		"family_id", rt.FamilyID,
		"client_id", rt.ClientID,
		"email", rt.Email,
		"revoked_live_tokens", revoked,
	)
	return nil
}

// lineage is what a refresh token inherits from the sign-in that started its
// session. The zero value means a new sign-in: issue starts a new family
// anchored at the current time.
type lineage struct {
	familyID string
	authTime time.Time
}

// issue mints the access token, the ID token and a rotated refresh token,
// persisting the latter before responding. It is the single place token
// shape and lifetimes are decided, so the grants cannot drift apart.
func (t *Token) issue(ctx context.Context, id Identity, clientID, nonce string, l lineage) (*tokenOutput, error) {
	now := t.now()
	if l.familyID == "" {
		familyID, err := randomFamilyID()
		if err != nil {
			return nil, fmt.Errorf("oidc: generate refresh token family: %w", err)
		}
		l = lineage{familyID: familyID, authTime: now}
	}

	// The access token is Temporal's credential: permissions, and the
	// Signer's Temporal audience (OIDC_ACCESS_TOKEN_AUDIENCE).
	signed, jti, err := t.signer.Mint(ctx, keys.MintRequest{
		Subject:     id.Subject,
		Email:       id.Email,
		TTL:         t.accessTTL,
		Permissions: flatAdminPermissions(),
		ClientID:    clientID,
	})
	if err != nil {
		return nil, fmt.Errorf("oidc: mint access token: %w", err)
	}
	idToken, err := t.signer.MintIDToken(ctx, keys.IDTokenRequest{
		Subject: id.Subject,
		Email:   id.Email,
		// OIDC Core §2: the ID token's aud is the requesting client.
		Audience: clientID,
		// Echoed only when the client sent one at /authorize (empty on the
		// refresh path); OIDC Core §2 requires the round-trip.
		Nonce:    nonce,
		AuthTime: l.authTime,
		TTL:      IDTokenTTL,
	})
	if err != nil {
		return nil, fmt.Errorf("oidc: mint id token: %w", err)
	}

	refreshTok, err := t.newRefresh()
	if err != nil {
		return nil, fmt.Errorf("oidc: generate refresh token: %w", err)
	}

	// Rotation renews the idle window but never past the session's
	// absolute end.
	expiresAt := now.Add(t.refreshTTL)
	if end := l.authTime.Add(t.refreshMaxLifetime); end.Before(expiresAt) {
		expiresAt = end
	}
	err = t.store.SaveRefresh(ctx, Refresh{
		Token:     refreshTok,
		JTI:       jti,
		ClientID:  clientID,
		Subject:   id.Subject,
		Email:     id.Email,
		FamilyID:  l.familyID,
		AuthTime:  l.authTime,
		CreatedAt: now,
		ExpiresAt: expiresAt,
	})
	if errors.Is(err, ErrRefreshFamilyRevoked) {
		return nil, oauthErr(http.StatusBadRequest, "invalid_grant", "the session has been revoked")
	}
	if err != nil {
		return nil, fmt.Errorf("oidc: persist refresh token: %w", err)
	}

	return &tokenOutput{
		CacheControl: "no-store",
		Pragma:       "no-cache",
		Body: tokenResponse{
			AccessToken:  signed,
			TokenType:    "Bearer",
			ExpiresIn:    int(t.accessTTL.Seconds()),
			RefreshToken: refreshTok,
			IDToken:      idToken,
		},
	}, nil
}

// flatAdminPermissions is the Hour-0 authorization model: every admitted
// identity gets unconditional access. The value is dictated by Temporal's
// default JWT ClaimMapper, which has no namespace wildcard: it grants
// cluster-level and all-namespace access only via the System role, set by a
// permission whose namespace part is exactly the system namespace
// ("temporal-system"). A literal "*" would be treated as an ordinary
// namespace named "*" and would NOT authorize cluster APIs (ListNamespaces,
// cluster-info) or any real namespace. Group- or role-derived grants will
// replace this once the shared permissions model lands.
func flatAdminPermissions() []string {
	return []string{"temporal-system:admin"}
}

// grantLabel maps grant_type to a fixed metric label. The raw value is
// client-controlled, so anything unknown collapses into "other" rather than
// minting a new series per request.
func grantLabel(grantType string) string {
	switch grantType {
	case grantAuthorizationCode:
		return grantLabelAuthorizationCode
	case grantRefreshToken:
		return grantLabelRefreshToken
	case grantDeviceCode:
		return grantLabelDeviceCode
	default:
		return grantLabelOther
	}
}

// tokenErrorCode is the OAuth2 error code a /token failure is reported
// under: the code tempogate itself chose for an OAuth2 error response, or
// server_error for anything that surfaced as a 500. Empty means success.
func tokenErrorCode(err error) string {
	if err == nil {
		return ""
	}
	var oe *oauthError
	if errors.As(err, &oe) {
		return oe.Code
	}
	return errorCodeServer
}

// verifyPKCE checks the RFC 7636 S256 binding: BASE64URL(SHA256(verifier))
// must equal the challenge stored at /authorize. /authorize rejects any
// method other than S256, so plain is unreachable here. The compare is
// constant-time so a mismatch leaks no timing signal about the challenge.
func verifyPKCE(verifier, challenge string) bool {
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

// validCodeVerifier enforces RFC 7636 §4.1: 43 to 128 characters from the
// unreserved set [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~".
func validCodeVerifier(v string) bool {
	if len(v) < 43 || len(v) > 128 {
		return false
	}
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9',
			c == '-', c == '.', c == '_', c == '~':
		default:
			return false
		}
	}
	return true
}

func randomRefresh() (string, error) {
	b := make([]byte, refreshEntropyBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// randomFamilyID is hex rather than base64url so it is easy to select and
// paste from `tempogate sessions list` into `sessions revoke --family`.
func randomFamilyID() (string, error) {
	b := make([]byte, familyIDEntropyBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// withBasicChallenge adds the WWW-Authenticate challenge RFC 6749 §5.2
// requires when a client that used HTTP Basic fails authentication with a
// 401 invalid_client. It keys off the scheme rather than a successful parse
// so a malformed Basic header is challenged too. Form-body credentials are
// not an HTTP authentication scheme, so their failures carry no challenge.
func withBasicChallenge(err error, authHeader string) error {
	var oe *oauthError
	if !errors.As(err, &oe) || oe.status != http.StatusUnauthorized || oe.Code != "invalid_client" || !hasBasicScheme(authHeader) {
		return err
	}
	h := http.Header{}
	h.Set("WWW-Authenticate", `Basic realm="`+basicRealm+`"`)
	return huma.ErrorWithHeaders(err, h)
}

// hasBasicScheme reports whether an Authorization header uses the Basic
// scheme, matched case-insensitively per RFC 7235.
func hasBasicScheme(header string) bool {
	const prefix = "Basic "
	return len(header) >= len(prefix) && strings.EqualFold(header[:len(prefix)], prefix)
}

// parseBasicAuth extracts client credentials from an "Authorization: Basic
// <base64>" header. The scheme match is case-insensitive per RFC 7235. RFC
// 6749 §2.3.1 form-url-encodes client_id/secret before the base64, and
// golang.org/x/oauth2 (the Temporal Web UI's stack) does exactly that, so
// each half is unescaped — falling back to the raw value if it is not valid
// percent-encoding. ok is false for any other or missing scheme, so the
// caller falls back to form-body credentials. The secret is not validated
// here; TokenClients.Authenticate does that in constant time.
func parseBasicAuth(header string) (id, secret string, ok bool) {
	const prefix = "Basic "
	if len(header) <= len(prefix) || !hasBasicScheme(header) {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(header[len(prefix):]))
	if err != nil {
		return "", "", false
	}
	u, p, found := strings.Cut(string(raw), ":")
	if !found {
		return "", "", false
	}
	if dec, err := url.QueryUnescape(u); err == nil {
		u = dec
	}
	if dec, err := url.QueryUnescape(p); err == nil {
		p = dec
	}
	return u, p, true
}
