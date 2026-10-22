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
)

const (
	// AuthorizePath is exported so the OIDC discovery document can advertise
	// the same authorization_endpoint this handler registers, keeping the
	// two from drifting.
	AuthorizePath = "/authorize"

	// CallbackPath is exported so the oidc/google provider can build a
	// redirect_uri that exactly matches the one /authorize sends to Google;
	// a mismatch makes Google reject the code exchange.
	CallbackPath = "/callback/google"

	// authRequestTTL bounds how long a pending request may sit between the
	// downstream /authorize call and Google's round-trip back. Short enough
	// that an abandoned login can't be resumed much later.
	authRequestTTL = 5 * time.Minute

	// googleScope is the upstream scope set. `email` is required so the
	// callback can run the domain allowlist check.
	googleScope = "openid email"

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

func oauthErr(status int, code, desc string) *oauthError {
	return &oauthError{status: status, Code: code, Desc: desc}
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

// authorizeOutput carries only a status + Location: huma writes a 302 with no
// body when the output struct has no Body field (see processOutputType).
type authorizeOutput struct {
	Status   int
	Location string `header:"Location"`
}

// Authorizer serves GET /authorize: it validates the downstream client,
// persists a pending AuthRequest, and redirects the browser to Google.
type Authorizer struct {
	store        AuthRequestStore
	clients      ClientRegistry
	issuer       string
	googleClient string
	googleAuth   string
	now          func() time.Time
	newState     func() (string, error)
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
	issuer, googleClientID, googleAuthEndpoint string,
	opts ...Option,
) *Authorizer {
	a := &Authorizer{
		store:        store,
		clients:      clients,
		issuer:       strings.TrimRight(issuer, "/"),
		googleClient: googleClientID,
		googleAuth:   googleAuthEndpoint,
		now:          func() time.Time { return time.Now().UTC() },
		newState:     randomState,
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
		Summary:       "OIDC authorization endpoint (authorization-code flow; redirects to Google)",
		Tags:          []string{"oidc"},
		DefaultStatus: http.StatusFound,
	}, func(ctx context.Context, in *authorizeInput) (*authorizeOutput, error) {
		return a.handle(ctx, in)
	})
}

func (a *Authorizer) handle(ctx context.Context, in *authorizeInput) (*authorizeOutput, error) {
	if in.ResponseType != "code" {
		return nil, oauthErr(http.StatusBadRequest, "unsupported_response_type", "only response_type=code is supported")
	}
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
	if !scopeContains(in.Scope, "openid") {
		return nil, oauthErr(http.StatusBadRequest, "invalid_scope", "scope must include openid")
	}
	// PKCE posture (see docs/pkce-and-confidential-clients.md): mandatory for
	// every public client, exactly as OAuth 2.1 / RFC 9700 require. The sole
	// relaxation is a registered *confidential* client (one with a secret),
	// which may omit code_challenge because it instead authenticates that
	// secret at /token. PKCE is still enforced for a confidential client that
	// does send a challenge — the carve-out only widens, never weakens, when
	// a challenge is absent.
	if in.CodeChallenge == "" {
		if !a.clients.IsConfidential(in.ClientID) {
			return nil, oauthErr(http.StatusBadRequest, "invalid_request", "code_challenge is required (PKCE)")
		}
	} else if in.CodeChallengeMethod != "S256" {
		return nil, oauthErr(http.StatusBadRequest, "invalid_request", "code_challenge_method must be S256")
	}

	internalState, err := a.newState()
	if err != nil {
		return nil, fmt.Errorf("oidc: generate state: %w", err)
	}

	now := a.now()
	ar := AuthRequest{
		InternalState:       internalState,
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

	loc, err := a.googleURL(internalState)
	if err != nil {
		return nil, fmt.Errorf("oidc: build upstream url: %w", err)
	}
	return &authorizeOutput{Status: http.StatusFound, Location: loc}, nil
}

func (a *Authorizer) googleURL(internalState string) (string, error) {
	u, err := url.Parse(a.googleAuth)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("client_id", a.googleClient)
	q.Set("redirect_uri", a.issuer+CallbackPath)
	q.Set("response_type", "code")
	q.Set("scope", googleScope)
	q.Set("state", internalState)
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
