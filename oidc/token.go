package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
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

	grantAuthorizationCode = "authorization_code"
	grantRefreshToken      = "refresh_token"
	// grantDeviceCode is the RFC 8628 §3.4 grant_type the CLI presents on every
	// poll. The full URN is part of the contract — clients copy it verbatim.
	grantDeviceCode = "urn:ietf:params:oauth:grant-type:device_code"

	// accessTokenTTL is the lifetime of a minted access/id token. Short
	// enough that a leaked token has a bounded blast radius; the refresh
	// token covers continuity.
	accessTokenTTL = 4 * time.Hour

	// refreshTokenTTL bounds how long a session can be silently resumed
	// without a fresh Google round-trip.
	refreshTokenTTL = 30 * 24 * time.Hour

	refreshEntropyBytes = 32
)

// ErrRefreshNotFound is returned by ConsumeRefresh when no token matches —
// because it was never issued, has already been used (single-use; refresh is
// rotated on every exchange), or its row was reaped. The /token handler maps
// this to OAuth2 invalid_grant.
var ErrRefreshNotFound = errors.New("oidc: refresh token not found")

// Refresh is the opaque, single-use credential a client presents to obtain a
// fresh access token without another Google round-trip. Token is the random
// secret the client holds; JTI references the access token minted alongside
// it, so an operator can correlate a refresh row with the JWT it renewed.
// Each exchange consumes the row and mints a new one (rotation), so a
// captured refresh token is usable at most once before it is invalidated by
// the legitimate client's next refresh.
type Refresh struct {
	Token     string
	JTI       string
	ClientID  string
	Email     string
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
	// ConsumeAuthCode atomically loads and deletes the authorization code,
	// enforcing single use. It returns ErrAuthCodeNotFound when no row
	// matches. Expiry is the caller's concern (it owns the clock); a
	// consumed-but-expired code is still returned and then rejected.
	ConsumeAuthCode(ctx context.Context, code string) (AuthCode, error)

	// SaveRefresh persists a freshly minted refresh token.
	SaveRefresh(ctx context.Context, r Refresh) error

	// ConsumeRefresh atomically loads and deletes the refresh token,
	// enforcing single use so every exchange rotates the token. It returns
	// ErrRefreshNotFound when no row matches.
	ConsumeRefresh(ctx context.Context, token string) (Refresh, error)
}

// ClientAuthenticator authenticates a confidential client's secret presented
// at the token endpoint. *ClientRegistry satisfies it structurally; the
// narrow interface (consumer-defines-the-interface, see state/doc.go) keeps
// the /token handler decoupled from the registry's redirect-allowlist
// concerns. It is consulted only on the confidential carve-out path — a
// redeemed code that carried no PKCE challenge — so a client with no secret
// can never authenticate this way.
type ClientAuthenticator interface {
	Authenticate(clientID, secret string) bool
}

// Token serves POST /token: it completes the authorization-code flow by
// exchanging a redeemed code for a signed JWT — PKCE-verified for public
// clients, client-secret-authenticated for the confidential carve-out —
// renews sessions via the refresh-token grant, and (when a DeviceCodeStore
// is wired in) redeems the RFC 8628 device-code grant the CLI polls on.
type Token struct {
	store      TokenStore
	devices    DeviceCodeStore
	signer     *keys.Signer
	clients    ClientAuthenticator
	now        func() time.Time
	newRefresh func() (string, error)
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

// WithDeviceCodeStore plugs the RFC 8628 device-code grant in. Without it,
// /token rejects device_code as unsupported_grant_type; with it, the full
// §3.5 polling state machine is exposed. Declared as a separate dependency
// (rather than folded into TokenStore) so the auth-code surface stays
// minimal for deployments that opt out of the device flow.
func WithDeviceCodeStore(s DeviceCodeStore) TokenOption {
	return func(t *Token) { t.devices = s }
}

func NewToken(store TokenStore, signer *keys.Signer, clients ClientAuthenticator, opts ...TokenOption) *Token {
	t := &Token{
		store:      store,
		signer:     signer,
		clients:    clients,
		now:        func() time.Time { return time.Now().UTC() },
		newRefresh: randomRefresh,
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
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	// IDToken is the same signed JWT as AccessToken. tempogate issues one
	// token that is simultaneously the OAuth2 access token and the OIDC
	// id_token; relying parties (Temporal) verify it the same way either
	// way, so minting a second token would only add surface area.
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
	form, err := url.ParseQuery(string(in.RawBody))
	if err != nil {
		return nil, oauthErr(http.StatusBadRequest, "invalid_request", "malformed form body")
	}

	switch form.Get("grant_type") {
	case grantAuthorizationCode:
		return t.authorizationCodeGrant(ctx, form, in.Authorization)
	case grantRefreshToken:
		return t.refreshTokenGrant(ctx, form)
	case grantDeviceCode:
		return t.deviceCodeGrant(ctx, form)
	case "":
		return nil, oauthErr(http.StatusBadRequest, "invalid_request", "grant_type is required")
	default:
		return nil, oauthErr(http.StatusBadRequest, "unsupported_grant_type", "only authorization_code, refresh_token, and urn:ietf:params:oauth:grant-type:device_code are supported")
	}
}

// AuthCodeRedemptionRequest is the parsed input to the auth-code-grant
// redemption step — already past form parsing, Basic-auth parsing, and the
// PKCE-vs-secret carve-out routing. The public POST /token handler and the
// device-flow verification UI both build one of these and hand it to
// RedeemAuthorizationCode; neither needs an HTTP round-trip to do so.
type AuthCodeRedemptionRequest struct {
	Code         string
	ClientID     string
	RedirectURI  string
	CodeVerifier string // PKCE; empty when authenticating by client secret.
	ClientSecret string // empty when authenticating by PKCE.
}

// AuthCodeRedemption is the consumed AuthCode's claims, ready for either
// id-token minting (the public /token handler) or in-process session
// issuance (the device-flow verification UI).
type AuthCodeRedemption struct {
	Email    string
	ClientID string
	Nonce    string
}

// RedeemAuthorizationCode validates a presented authorization code,
// consumes it single-use, runs the PKCE-or-client-secret proof appropriate
// to how the code was minted, and returns the code's claims. No HTTP shape
// involved — callers have already parsed their inputs. Errors are returned
// as OAuth2-shaped huma.StatusErrors via oauthErr so the public /token
// handler can propagate them verbatim; in-process callers can inspect
// errors.Is(..., huma.StatusError) or just surface the message.
func (t *Token) RedeemAuthorizationCode(ctx context.Context, in AuthCodeRedemptionRequest) (*AuthCodeRedemption, error) {
	if in.Code == "" {
		return nil, oauthErr(http.StatusBadRequest, "invalid_request", "code is required")
	}

	// A request that proves neither PKCE possession nor a client secret is
	// malformed regardless of which client it claims to be — reject it
	// before consuming the single-use code. (Which proof is actually
	// required is decided post-consume from the code's own challenge, so the
	// strict default cannot be downgraded by a confidential-looking
	// request against a public client's code.)
	if in.CodeVerifier == "" && in.ClientSecret == "" {
		return nil, oauthErr(http.StatusBadRequest, "invalid_request", "code_verifier (PKCE) or client authentication is required")
	}

	ac, err := t.store.ConsumeAuthCode(ctx, in.Code)
	if errors.Is(err, ErrAuthCodeNotFound) {
		return nil, oauthErr(http.StatusBadRequest, "invalid_grant", "unknown or already-redeemed authorization code")
	}
	if err != nil {
		return nil, fmt.Errorf("oidc: consume auth code: %w", err)
	}

	if t.now().After(ac.ExpiresAt) {
		return nil, oauthErr(http.StatusBadRequest, "invalid_grant", "authorization code expired")
	}
	if in.ClientID != ac.ClientID {
		return nil, oauthErr(http.StatusBadRequest, "invalid_grant", "client_id does not match the authorization request")
	}
	if in.RedirectURI != ac.RedirectURI {
		return nil, oauthErr(http.StatusBadRequest, "invalid_grant", "redirect_uri does not match the authorization request")
	}

	// The code itself decides which proof is required. A code minted with a
	// PKCE challenge always demands the verifier — that path is unchanged and
	// strict, and a confidential client that chose PKCE still gets it
	// enforced. Only a code minted with no challenge (the confidential
	// carve-out, gated at /authorize on IsConfidential) falls through to
	// client-secret authentication.
	if ac.CodeChallenge != "" {
		if in.CodeVerifier == "" {
			return nil, oauthErr(http.StatusBadRequest, "invalid_request", "code_verifier is required (PKCE)")
		}
		if !verifyPKCE(in.CodeVerifier, ac.CodeChallenge) {
			return nil, oauthErr(http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		}
	} else if !t.clients.Authenticate(ac.ClientID, in.ClientSecret) {
		return nil, oauthErr(http.StatusUnauthorized, "invalid_client", "client authentication failed")
	}

	return &AuthCodeRedemption{Email: ac.Email, ClientID: ac.ClientID, Nonce: ac.Nonce}, nil
}

func (t *Token) authorizationCodeGrant(ctx context.Context, form url.Values, authHeader string) (*tokenOutput, error) {
	basicID, basicSecret, hasBasic := parseBasicAuth(authHeader)
	clientID := form.Get("client_id")
	presentedSecret := form.Get("client_secret")
	if hasBasic {
		clientID = basicID
		presentedSecret = basicSecret
	}

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
	return t.issue(ctx, r.Email, r.ClientID, r.Nonce)
}

func (t *Token) refreshTokenGrant(ctx context.Context, form url.Values) (*tokenOutput, error) {
	token := form.Get("refresh_token")
	if token == "" {
		return nil, oauthErr(http.StatusBadRequest, "invalid_request", "refresh_token is required")
	}

	rt, err := t.store.ConsumeRefresh(ctx, token)
	if errors.Is(err, ErrRefreshNotFound) {
		return nil, oauthErr(http.StatusBadRequest, "invalid_grant", "unknown or already-used refresh token")
	}
	if err != nil {
		return nil, fmt.Errorf("oidc: consume refresh token: %w", err)
	}

	if t.now().After(rt.ExpiresAt) {
		return nil, oauthErr(http.StatusBadRequest, "invalid_grant", "refresh token expired")
	}

	// No nonce on refresh: OIDC Core binds nonce to the original
	// authentication request, not to silently-renewed tokens, and the
	// relying party does not re-check it on the refresh path.
	return t.issue(ctx, rt.Email, rt.ClientID, "")
}

// issue mints the access/id token and a rotated refresh token, persisting the
// latter before responding. It is the single place token shape and lifetimes
// are decided, so the two grants cannot drift apart.
func (t *Token) issue(ctx context.Context, email, clientID, nonce string) (*tokenOutput, error) {
	signed, jti, err := t.signer.Mint(ctx, keys.MintRequest{
		Subject:     email,
		Email:       email,
		TTL:         accessTokenTTL,
		Permissions: flatAdminPermissions(),
		// OIDC Core: the ID token's aud must contain the requesting client.
		// tempogate issues one token that is both access and id token, so it
		// carries the client_id as aud; Temporal's frontend authorizer does
		// not enforce aud, so this is additive for the gRPC path.
		Audience: clientID,
		// Echoed only when the client sent one at /authorize (empty on the
		// refresh path); OIDC Core §2 requires the round-trip.
		Nonce: nonce,
	})
	if err != nil {
		return nil, fmt.Errorf("oidc: mint access token: %w", err)
	}

	refreshTok, err := t.newRefresh()
	if err != nil {
		return nil, fmt.Errorf("oidc: generate refresh token: %w", err)
	}

	now := t.now()
	if err := t.store.SaveRefresh(ctx, Refresh{
		Token:     refreshTok,
		JTI:       jti,
		ClientID:  clientID,
		Email:     email,
		CreatedAt: now,
		ExpiresAt: now.Add(refreshTokenTTL),
	}); err != nil {
		return nil, fmt.Errorf("oidc: persist refresh token: %w", err)
	}

	return &tokenOutput{
		CacheControl: "no-store",
		Pragma:       "no-cache",
		Body: tokenResponse{
			AccessToken:  signed,
			TokenType:    "Bearer",
			ExpiresIn:    int(accessTokenTTL.Seconds()),
			RefreshToken: refreshTok,
			IDToken:      signed,
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

// verifyPKCE checks the RFC 7636 S256 binding: BASE64URL(SHA256(verifier))
// must equal the challenge stored at /authorize. /authorize rejects any
// method other than S256, so plain is unreachable here. The compare is
// constant-time so a mismatch leaks no timing signal about the challenge.
func verifyPKCE(verifier, challenge string) bool {
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

func randomRefresh() (string, error) {
	b := make([]byte, refreshEntropyBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// parseBasicAuth extracts client credentials from an "Authorization: Basic
// <base64>" header. The scheme match is case-insensitive per RFC 7235. RFC
// 6749 §2.3.1 form-url-encodes client_id/secret before the base64, and
// golang.org/x/oauth2 (the Temporal Web UI's stack) does exactly that, so
// each half is unescaped — falling back to the raw value if it is not valid
// percent-encoding. ok is false for any other or missing scheme, so the
// caller falls back to form-body credentials. The secret is not validated
// here; ClientAuthenticator does that in constant time.
func parseBasicAuth(header string) (id, secret string, ok bool) {
	const prefix = "Basic "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
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
