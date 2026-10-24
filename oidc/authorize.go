package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/onhotpath/tempogate/internal/clock"
	"github.com/onhotpath/tempogate/redact"
)

const (
	// AuthorizePath is exported so the OIDC discovery document can advertise
	// the same authorization_endpoint this handler registers, keeping the
	// two from drifting.
	AuthorizePath = "/authorize"

	// CallbackPathPrefix is where each connector's callback lives:
	// CallbackPath(id).
	CallbackPathPrefix = "/callback/"

	// authRequestTTL bounds how long a pending request may sit between the
	// downstream /authorize call and the upstream's round-trip back. Short enough
	// that an abandoned login can't be resumed much later.
	authRequestTTL = 5 * time.Minute

	stateEntropyBytes = 32
)

// oauthError is an RFC 6749 §5.2 error body. It implements huma.StatusError so
// returning it from the handler emits the OAuth2-compliant JSON
// `{"error": "...", "error_description": "..."}` with the chosen status.
type oauthError struct {
	status int
	Code   string `json:"error"`
	Desc   string `json:"error_description,omitempty"`
}

func (e *oauthError) Error() string { return e.Code + ": " + e.Desc }

func (e *oauthError) GetStatus() int { return e.status }

// ClientSafe reports the body as written for the client, so the 5xx
// sanitizer (api.ClientSafeError) keeps the OAuth shape. Descriptions are
// fixed text: never put an internal error's message in one.
func (e *oauthError) ClientSafe() bool { return true }

func oauthErr(status int, code, desc string) *oauthError {
	return &oauthError{status: status, Code: code, Desc: desc}
}

// CallbackPath is the path of connectorID's callback, below the issuer. It
// is the redirect URI registered with that upstream.
func CallbackPath(connectorID string) string {
	return CallbackPathPrefix + connectorID
}

type authorizeInput struct {
	ResponseType        string `query:"response_type"`
	ClientID            string `query:"client_id"`
	RedirectURI         string `query:"redirect_uri"`
	Scope               string `query:"scope"`
	State               string `query:"state"`
	CodeChallenge       string `query:"code_challenge"`
	CodeChallengeMethod string `query:"code_challenge_method"`
	Nonce               string `query:"nonce"`
}

// authorizeOutput carries only a status + Location + the state-binding
// cookie: huma writes a 302 with no body when the output struct has no Body
// field (see processOutputType).
type authorizeOutput struct {
	Status    int
	Location  string `header:"Location"`
	SetCookie string `header:"Set-Cookie"`
}

// Authorizer serves GET /authorize: it validates the downstream client,
// persists a pending AuthRequest, binds it to the browser, and sends the
// browser to the active upstream connector with tempogate's own PKCE
// challenge and nonce.
type Authorizer struct {
	store      AuthRequestStore
	clients    ClientRegistry
	binding    *UpstreamBinding
	connectors *Connectors
	issuer     string
	now        func() time.Time
	newState   func() (string, error)
}

type Option func(*Authorizer)

// WithClock swaps the clock used to stamp AuthRequest timestamps. For tests.
func WithClock(now func() time.Time) Option {
	return func(a *Authorizer) { a.now = now }
}

// WithStateGenerator swaps the internal-state token generator. For tests.
func WithStateGenerator(fn func() (string, error)) Option {
	return func(a *Authorizer) { a.newState = fn }
}

func New(
	store AuthRequestStore,
	clients ClientRegistry,
	binding *UpstreamBinding,
	connectors *Connectors,
	issuer string,
	opts ...Option,
) *Authorizer {
	a := &Authorizer{
		store:      store,
		clients:    clients,
		binding:    binding,
		connectors: connectors,
		issuer:     strings.TrimRight(issuer, "/"),
		now:        clock.Now,
		newState:   randomState,
	}
	for _, o := range opts {
		o(a)
	}
	return a
}

func (a *Authorizer) Register(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID:   "authorize",
		Method:        http.MethodGet,
		Path:          AuthorizePath,
		Summary:       "OIDC authorization endpoint (authorization-code flow; redirects to the upstream identity provider)",
		Tags:          []string{"oidc"},
		DefaultStatus: http.StatusFound,
	}, func(ctx context.Context, in *authorizeInput) (*authorizeOutput, error) {
		return a.handle(ctx, in)
	})
}

func (a *Authorizer) handle(ctx context.Context, in *authorizeInput) (*authorizeOutput, error) {
	// Size caps come first and are answered directly, even once the
	// redirect URI is known: an oversized state would otherwise be echoed
	// back in the redirect.
	if err := checkParamLengths(
		paramCap{"client_id", in.ClientID, maxClientIDLen},
		paramCap{"redirect_uri", in.RedirectURI, maxRedirectURILen},
		paramCap{"scope", in.Scope, maxScopeLen},
		paramCap{"state", in.State, maxStateLen},
		paramCap{"nonce", in.Nonce, maxNonceLen},
	); err != nil {
		return nil, err
	}
	redact.Declare(ctx, redact.Secret, in.State, in.Nonce)
	redact.Declare(ctx, redact.Identifier, in.ClientID)
	if err := a.clients.Validate(in.ClientID, in.RedirectURI); err != nil {
		if errors.Is(err, ErrUnknownClient) {
			return nil, oauthErr(http.StatusBadRequest, "invalid_client", "unknown client_id")
		}
		// RFC 6749 §4.1.2.1: there is no registered redirect URI to report
		// this through, so it is shown to the user agent directly.
		if errors.Is(err, ErrUnauthorizedClient) {
			return nil, oauthErr(http.StatusBadRequest, "unauthorized_client", "client is not registered for the authorization-code flow")
		}
		return nil, oauthErr(http.StatusBadRequest, "invalid_request", "redirect_uri not registered for this client")
	}
	// From here on the redirect URI is the client's own, so errors go back
	// to the client rather than dead-ending the user agent (RFC 6749
	// §4.1.2.1).
	if oe := a.check(in); oe != nil {
		loc, err := authorizationResponse(in.RedirectURI, a.issuer, in.State, url.Values{
			"error":             {oe.Code},
			"error_description": {oe.Desc},
		})
		if err != nil {
			return nil, err
		}
		return &authorizeOutput{Status: http.StatusFound, Location: loc}, nil
	}

	internalState, err := a.newState()
	if err != nil {
		return nil, fmt.Errorf("oidc: generate state: %w", err)
	}
	redact.Declare(ctx, redact.Secret, internalState)

	conn := a.connectors.Active()
	now := a.now()
	ar := AuthRequest{
		InternalState:       internalState,
		ConnectorID:         conn.ID(),
		ClientID:            in.ClientID,
		RedirectURI:         in.RedirectURI,
		Scope:               in.Scope,
		ClientState:         in.State,
		CodeChallenge:       in.CodeChallenge,
		CodeChallengeMethod: in.CodeChallengeMethod,
		Nonce:               in.Nonce,
		CreatedAt:           now,
		ExpiresAt:           now.Add(authRequestTTL),
	}
	if err := a.store.SaveAuthRequest(ctx, ar); err != nil {
		return nil, fmt.Errorf("oidc: persist auth request: %w", err)
	}

	start, err := conn.Begin(ctx, BeginParams{
		RedirectURI:   a.issuer + CallbackPath(conn.ID()),
		State:         internalState,
		CodeChallenge: a.binding.codeChallenge(conn.ID(), internalState),
		Nonce:         a.binding.nonce(conn.ID(), internalState),
		RequestID:     a.binding.requestID(conn.ID(), internalState),
	})
	if err != nil {
		return nil, fmt.Errorf("oidc: begin %s sign-in: %w", conn.ID(), err)
	}
	return &authorizeOutput{
		Status:    http.StatusFound,
		Location:  start.RedirectURL,
		SetCookie: a.binding.Cookie(conn.ID(), internalState).String(),
	}, nil
}

// check validates the parts of an authorization request that are reported
// to the client through its redirect URI.
func (a *Authorizer) check(in *authorizeInput) *oauthError {
	if in.ResponseType != "code" {
		return oauthErr(http.StatusBadRequest, "unsupported_response_type", "only response_type=code is supported")
	}
	if !scopeContains(in.Scope, "openid") {
		return oauthErr(http.StatusBadRequest, "invalid_scope", "scope must include openid")
	}
	// PKCE posture (see docs/pkce-and-confidential-clients.md): mandatory for
	// every public client, exactly as OAuth 2.1 / RFC 9700 require. The sole
	// relaxation is a registered *confidential* client (one with a secret),
	// which may omit code_challenge because it instead authenticates that
	// secret at /token. PKCE is still enforced for a confidential client that
	// does send a challenge - the carve-out only widens, never weakens, when
	// a challenge is absent.
	if in.CodeChallenge == "" {
		if !a.clients.IsConfidential(in.ClientID) {
			return oauthErr(http.StatusBadRequest, "invalid_request", "code_challenge is required (PKCE)")
		}
		return nil
	}
	if !validCodeChallenge(in.CodeChallenge) {
		return oauthErr(http.StatusBadRequest, "invalid_request", "code_challenge must be 43 base64url characters (S256)")
	}
	if in.CodeChallengeMethod != "S256" {
		return oauthErr(http.StatusBadRequest, "invalid_request", "code_challenge_method must be S256")
	}
	return nil
}

// authorizationResponse builds the Location of an authorization response,
// success or error, to the client's validated redirect URI: params, the
// client's state when it sent one (RFC 6749 §4.1.2), and iss (RFC 9207) so
// the client can tell which authorization server answered. The URI was
// matched exactly against the client's registration at /authorize; the
// Location is rebuilt from the parsed url.URL with the query set through
// url.Values rather than by string concatenation, so a parameter value can
// never change the scheme, host or path the browser is sent to.
func authorizationResponse(redirectURI, issuer, state string, params url.Values) (string, error) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return "", fmt.Errorf("oidc: parse redirect_uri: %w", err)
	}
	q := u.Query()
	for k, vs := range params {
		q.Set(k, vs[0])
	}
	if state != "" {
		q.Set("state", state)
	}
	if issuer != "" {
		q.Set("iss", issuer)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func scopeContains(scope, want string) bool {
	for _, s := range strings.Fields(scope) {
		if s == want {
			return true
		}
	}
	return false
}

func randomState() (string, error) {
	b := make([]byte, stateEntropyBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
