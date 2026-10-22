package google

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/onhotpath/tempogate/oidc"
)

// ID is the Google connector's id: its callback is /callback/google.
const ID = "google"

// Identity is what a verified Google id_token asserts. HostedDomain is the
// `hd` claim: Google sets it only for accounts managed by a Google Workspace
// or Cloud organization, so it is empty for consumer accounts, including one
// created for an address at an allowed domain.
type Identity struct {
	Subject       string
	Email         string
	EmailVerified bool
	HostedDomain  string
}

// Exchanger redeems a Google authorization code for a verified identity.
// *Client is the production one; the seam lets the server's callback tests
// run the real connector against a fake Google.
type Exchanger interface {
	ExchangeAndVerify(ctx context.Context, code, redirectURI, codeVerifier, nonce string) (Identity, error)
}

// Config is the Google connector's configuration (OIDC_GOOGLE_* and
// OIDC_ALLOWED_HOSTED_DOMAINS).
type Config struct {
	ClientID     string
	AuthEndpoint string
	// IssuerURL is the `iss` Google's responses carry.
	IssuerURL string
	// HostedDomains is the comma-separated Workspace allowlist for the `hd`
	// claim; empty turns Workspace mode off.
	HostedDomains string
}

// Connector is Google behind oidc.Connector.
type Connector struct {
	clientID      string
	authEndpoint  *url.URL
	issuer        string
	hostedDomains map[string]struct{}
	hdHint        string
	exchanger     Exchanger
}

// NewConnector validates cfg. The authorization endpoint is parsed here, so
// a malformed OIDC_GOOGLE_AUTH_ENDPOINT stops the server at startup rather
// than failing every sign-in.
func NewConnector(cfg Config, exchanger Exchanger) (*Connector, error) {
	auth, err := url.Parse(cfg.AuthEndpoint)
	if err != nil || auth.Scheme == "" || auth.Host == "" {
		return nil, fmt.Errorf("google: authorization endpoint %q must be an absolute URL", cfg.AuthEndpoint)
	}
	hosted := oidc.ParseDomains(cfg.HostedDomains)
	return &Connector{
		clientID:      cfg.ClientID,
		authEndpoint:  auth,
		issuer:        strings.TrimRight(cfg.IssuerURL, "/"),
		hostedDomains: hosted,
		hdHint:        hostedDomainHint(hosted),
		exchanger:     exchanger,
	}, nil
}

// hostedDomainHint is the `hd` request parameter for the configured hosted
// domains: the domain itself when there is exactly one, `*` (any Workspace
// account) when there are several, and nothing when there are none. It only
// steers Google's account chooser; it is not a security control, since the
// user can edit the request. Complete's check of the `hd` claim is what
// enforces the restriction.
func hostedDomainHint(hosted map[string]struct{}) string {
	switch len(hosted) {
	case 0:
		return ""
	case 1:
		for d := range hosted {
			return d
		}
	}
	return "*"
}

func (c *Connector) ID() string { return ID }

func (c *Connector) DisplayName() string { return "Google" }

func (c *Connector) Flow() oidc.Flow {
	return oidc.Flow{ResponseMethod: http.MethodGet, StateParam: "state"}
}

// Begin sends the browser to Google's authorization endpoint with the
// server's PKCE challenge and nonce.
func (c *Connector) Begin(_ context.Context, p oidc.BeginParams) (oidc.Start, error) {
	u := *c.authEndpoint
	q := u.Query()
	q.Set("client_id", c.clientID)
	q.Set("redirect_uri", p.RedirectURI)
	q.Set("response_type", "code")
	q.Set("scope", scopes)
	q.Set("state", p.State)
	q.Set("code_challenge", p.CodeChallenge)
	q.Set("code_challenge_method", "S256")
	q.Set("nonce", p.Nonce)
	if c.hdHint != "" {
		q.Set("hd", c.hdHint)
	}
	u.RawQuery = q.Encode()
	return oidc.Start{RedirectURL: u.String()}, nil
}

// Complete forwards an `error` Google sent back (e.g. the user declined
// consent), else redeems the code and verifies the id_token, then applies
// the Workspace gate.
func (c *Connector) Complete(ctx context.Context, p oidc.CompleteParams) (oidc.Completion, error) {
	if e := p.Params.Get("error"); e != "" {
		return oidc.Completion{}, &oidc.UpstreamDenied{Code: e, Description: p.Params.Get("error_description")}
	}
	code := p.Params.Get("code")
	if code == "" {
		return oidc.Completion{}, oidc.ErrMissingResponse
	}
	// RFC 9207: a response naming another issuer is a mix-up, not ours.
	if iss := p.Params.Get("iss"); iss != "" && subtle.ConstantTimeCompare([]byte(iss), []byte(c.issuer)) != 1 {
		return oidc.Completion{}, &oidc.UpstreamError{Reason: oidc.UpstreamReasonIssuer, Err: errors.New("google: authorization response names another issuer")}
	}
	id, err := c.exchanger.ExchangeAndVerify(ctx, code, p.RedirectURI, p.CodeVerifier, p.Nonce)
	if err != nil {
		return oidc.Completion{}, err
	}
	completion := oidc.Completion{Identity: oidc.UpstreamIdentity{
		Subject:       id.Subject,
		Email:         id.Email,
		EmailVerified: id.EmailVerified,
	}}
	if !c.hostedDomainAllowed(id.HostedDomain) {
		completion.Refusal = oidc.RefusalHostedDomainNotAllowed
	}
	return completion, nil
}

// FormActionSources is the origin of the authorization endpoint Begin
// redirects to.
func (c *Connector) FormActionSources(context.Context) ([]string, error) {
	return []string{c.authEndpoint.Scheme + "://" + c.authEndpoint.Host}, nil
}

// hostedDomainAllowed is the Workspace-mode gate. With no hosted domains
// configured it admits everyone (the email allowlist alone decides);
// otherwise the `hd` claim must be present and listed.
func (c *Connector) hostedDomainAllowed(hd string) bool {
	if len(c.hostedDomains) == 0 {
		return true
	}
	_, ok := c.hostedDomains[strings.ToLower(hd)]
	return ok
}
