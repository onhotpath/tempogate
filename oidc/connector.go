package oidc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"time"
)

// Connector federates the browser leg of a login to one upstream identity
// service. It must not assume OIDC: an OAuth2 service with a user API
// (GitHub) and SAML's POST binding fit the same two calls. Capabilities only
// some connectors have (re-validating a user on refresh, a directory of
// suspended users and groups) are separate interfaces discovered by type
// assertion, so adding one never changes this one.
//
// The server owns everything that is the same for every connector: the
// pending auth request and its single use, the browser binding and the
// values derived from it, the shared admission gates, the authorization code
// and the tokens. A connector owns the upstream protocol only.
type Connector interface {
	// ID is the immutable connector id (see ValidateConnectorID). It is the
	// callback path segment and is mixed into every binding value, so a
	// state minted for one connector never verifies at another's callback.
	ID() string
	// DisplayName is the user-facing name ("Google") for error text.
	DisplayName() string
	// Flow says how the upstream returns the browser to the callback.
	Flow() Flow
	// Begin builds the upstream start request. It must send p.State in
	// Flow().StateParam, the redirect URL exactly as p.RedirectURI, and every
	// binding value its protocol can carry (PKCE challenge, nonce, request
	// ID). It must never send the PKCE verifier. If it makes a network call,
	// the rules of Complete apply to it.
	Begin(ctx context.Context, p BeginParams) (Start, error)
	// Complete runs once the server has checked the browser binding and
	// consumed the state for this connector, under an overall deadline. It
	// must:
	//   - return *UpstreamDenied when the upstream reports a user-facing
	//     failure (an OAuth `error`), checked first;
	//   - return ErrMissingResponse when the code or assertion is absent;
	//   - prove the response belongs to this login: the PKCE verifier on a
	//     code exchange, and the nonce (id_token) or request ID (SAML) when
	//     the protocol has one; reject an RFC 9207 `iss` that is present and
	//     differs from the upstream issuer;
	//   - pin the upstream issuer and verify signature, audience and
	//     validity window;
	//   - set EmailVerified only when the upstream proves it, never by
	//     default: the server refuses an unproven email;
	//   - bound every network call (the upstreamhttp helper) and report it
	//     to an UpstreamObserver;
	//   - return every other failure as *UpstreamError, and never put a
	//     code, token or assertion in its text.
	Complete(ctx context.Context, p CompleteParams) (Completion, error)
	// FormActionSources are the origins the device verification page's CSP
	// form-action must allow so its redirect chain can reach Begin's target.
	// Called once at startup.
	FormActionSources(ctx context.Context) ([]string, error)
}

// Flow describes how an upstream returns the browser to the callback.
type Flow struct {
	// ResponseMethod is http.MethodGet (query parameters) or, for SAML's
	// POST binding, http.MethodPost (a form body). Only GET is served yet.
	ResponseMethod string
	// StateParam is the parameter that carries the state back: "state" for
	// OAuth2/OIDC, "RelayState" for SAML.
	StateParam string
}

// BeginParams are the server-derived values a Connector's start request
// carries. Every binding value is derived from (connector id, state) under
// OIDC_SESSION_SIGNING_KEY, never stored.
type BeginParams struct {
	// RedirectURI is the issuer's callback for this connector.
	RedirectURI string
	State       string
	// CodeChallenge is the S256 PKCE challenge of the verifier Complete gets.
	CodeChallenge string
	Nonce         string
	// RequestID is an XML NCName ("_" then hex) for protocols that echo a
	// request id (SAML InResponseTo).
	RequestID string
}

// Start is where Begin sends the browser.
type Start struct {
	RedirectURL string
}

// CompleteParams carry the upstream's response and the binding values Begin
// was given for the same state.
type CompleteParams struct {
	RedirectURI string
	// Params are the query (GET) or form (POST) parameters, as received.
	Params       url.Values
	CodeVerifier string
	Nonce        string
	RequestID    string
}

// Completion is a verified upstream identity and the connector's own
// verdict on it.
type Completion struct {
	Identity UpstreamIdentity
	// Refusal names a connector-specific gate the identity failed (one of
	// the Refusal* constants), evaluated after the shared gates; "" admits.
	Refusal string
}

// UpstreamIdentity is who the upstream says signed in.
type UpstreamIdentity struct {
	// Subject is the upstream's stable, never reassigned id for the
	// account, unique within the connector. Never an email or login name:
	// those can move to another person.
	Subject       string
	Email         string
	EmailVerified bool
	// Groups are upstream group names; nil when the connector supplies
	// none. Not consumed yet.
	Groups []string
}

// RefusalHostedDomainNotAllowed is the Google Workspace (`hd`) gate.
const RefusalHostedDomainNotAllowed = reasonHostedDomainNotAllowed

// ErrMissingResponse is Complete's answer to a callback without a code or
// assertion.
var ErrMissingResponse = errors.New("oidc: upstream response has no code or assertion")

// UpstreamDenied is an error the upstream reported for the user to see (an
// OAuth `error` such as access_denied). The callback forwards it to the
// client instead of dead-ending the browser.
type UpstreamDenied struct {
	Code        string
	Description string
}

func (e *UpstreamDenied) Error() string { return "oidc: upstream denied the sign-in: " + e.Code }

// Reasons an UpstreamError carries. They are what the callback logs about a
// failed upstream sign-in: the error text itself is never logged, because a
// token endpoint's error body or a verifier message could echo a code or
// token.
const (
	UpstreamReasonDiscovery = "discovery_unavailable"
	UpstreamReasonExchange  = "code_exchange_failed"
	UpstreamReasonIDToken   = "id_token_invalid"
	UpstreamReasonNonce     = "nonce_mismatch"
	UpstreamReasonClaims    = "claims_incomplete"
	UpstreamReasonIssuer    = "issuer_mismatch"
)

// UpstreamError classifies a failed Complete. OAuthError is the RFC 6749
// §5.2 error code the token endpoint answered with (e.g. invalid_grant,
// invalid_client), when there is one; it is a fixed token, safe to log, and
// the quickest way to tell a bad client secret from a replayed code. Timeout
// marks a call that got no answer in time, which points at the upstream or
// the network rather than at the login.
type UpstreamError struct {
	Reason     string
	OAuthError string
	Timeout    bool
	Err        error
}

func (e *UpstreamError) Error() string { return e.Err.Error() }

func (e *UpstreamError) Unwrap() error { return e.Err }

// UpstreamObserver is told the latency and outcome of every call a
// connector makes upstream, by operation ("discovery", "code_exchange",
// "verify_id_token"). A failure is an *UpstreamError, whose Timeout flag
// tells a call that ran out of time from one the upstream answered. The
// metrics package satisfies it.
type UpstreamObserver interface {
	ObserveUpstream(op string, took time.Duration, err error)
}

// connectorIDPattern keeps an id safe as a path segment, a cookie path, a
// token subject prefix and a label value.
var connectorIDPattern = regexp.MustCompile(`^[a-z][a-z0-9]{0,31}$`)

// reservedConnectorIDs can never name a connector: `key` prefixes
// integration-key subjects, and the others are kept for tempogate itself.
var reservedConnectorIDs = []string{"key", "tempogate", "system", "local"}

// ValidateConnectorID reports whether id may name a connector. Ids are
// immutable: renaming one ends every session that came through it.
func ValidateConnectorID(id string) error {
	if !connectorIDPattern.MatchString(id) {
		return fmt.Errorf("oidc: connector id %q must match %s", id, connectorIDPattern)
	}
	if slices.Contains(reservedConnectorIDs, id) {
		return fmt.Errorf("oidc: connector id %q is reserved", id)
	}
	return nil
}

// Connectors are the configured upstream connectors, by id. Callbacks are
// routed by id, so state and sessions never depend on there being one; only
// the choice of where /authorize sends a browser does, and with one active
// connector that is Active.
type Connectors struct {
	byID   map[string]Connector
	active Connector
}

// NewConnectors validates the configured connectors. Exactly one may be
// active for now; choosing between several at sign-in is tracked in #54.
func NewConnectors(cs ...Connector) (*Connectors, error) {
	switch len(cs) {
	case 0:
		return nil, errors.New("oidc: no upstream connector is configured")
	case 1:
	default:
		return nil, fmt.Errorf("oidc: %d upstream connectors are configured, but only one may be active", len(cs))
	}
	c := cs[0]
	if err := ValidateConnectorID(c.ID()); err != nil {
		return nil, err
	}
	if err := validateFlow(c.Flow()); err != nil {
		return nil, fmt.Errorf("oidc: connector %q: %w", c.ID(), err)
	}
	return &Connectors{byID: map[string]Connector{c.ID(): c}, active: c}, nil
}

// Active is the connector /authorize sends browsers to.
func (c *Connectors) Active() Connector { return c.active }

// Lookup returns the connector with id, if it is configured.
func (c *Connectors) Lookup(id string) (Connector, bool) {
	conn, ok := c.byID[id]
	return conn, ok
}

// validateFlow admits only GET responses for now: an upstream that returns
// the browser with a cross-site POST (SAML) would need a binding cookie that
// rides a cross-site POST, which is not built yet.
func validateFlow(f Flow) error {
	if f.ResponseMethod != http.MethodGet {
		return fmt.Errorf("response method %q is not supported (only GET)", f.ResponseMethod)
	}
	if f.StateParam == "" {
		return errors.New("state parameter is empty")
	}
	return nil
}
