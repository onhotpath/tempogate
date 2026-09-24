package oidc

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"go.uber.org/fx"

	"github.com/onhotpath/tempogate/keys"
)

// sessionSigningKeyBytes is the required HMAC-SHA256 key length. RFC 4231
// permits any length, but cutting the key shorter than the digest output
// shrinks the effective security margin without any operator benefit.
const sessionSigningKeyBytes = 32

type clientRegistryParams struct {
	fx.In

	Clients string `name:"oidc_clients"`
	Secrets string `name:"oidc_client_secrets"`
}

// newClientRegistry parses the single shared ClientRegistry both /authorize
// and /token depend on. A malformed OIDC__CLIENTS or OIDC__CLIENT_SECRETS —
// or a secret declared for an unregistered client — fails graph construction
// here rather than surfacing as a per-request error later, so the PKCE
// carve-out can never be half-configured at runtime.
func newClientRegistry(p clientRegistryParams) (ClientRegistry, error) {
	reg, err := ParseClientRegistry(p.Clients)
	if err != nil {
		return nil, err
	}
	if err := reg.WithSecrets(p.Secrets); err != nil {
		return nil, err
	}
	return reg, nil
}

type authorizeParams struct {
	fx.In

	Store   AuthRequestStore
	Clients ClientRegistry

	Issuer         string `name:"oidc_issuer"`
	GoogleClientID string `name:"google_client_id"`
	GoogleAuth     string `name:"google_auth_endpoint"`
}

// newAuthorizeRegistrar builds the /authorize endpoint over the shared
// registry, so its PKCE/confidential decisions cannot drift from /token's.
func newAuthorizeRegistrar(p authorizeParams) func(huma.API) {
	a := New(p.Store, p.Clients, p.Issuer, p.GoogleClientID, p.GoogleAuth)
	return a.Register
}

type callbackParams struct {
	fx.In

	Store    CallbackStore
	Upstream Upstream

	AllowedDomains string `name:"oidc_allowed_domains"`
}

// newCallbackRegistrar builds the /callback/google endpoint. The Google
// upstream is injected as oidc.Upstream (bound by the oidc/google provider
// via fx.As), so this package never imports oauth2/go-oidc.
func newCallbackRegistrar(p callbackParams) func(huma.API) {
	c := NewCallback(p.Store, p.Upstream, p.AllowedDomains)
	return c.Register
}

type tokenParams struct {
	fx.In

	Store   TokenStore
	Devices DeviceCodeStore
	Signer  *keys.Signer
	Clients ClientRegistry
}

// newToken builds the shared *Token. It is provided as its own dependency
// (rather than constructed inline by newTokenRegistrar) so the device-flow
// verification UI can consume the same instance and call its
// RedeemAuthorizationCode method in-process — sidestepping the HTTPS
// self-loopback the SSO callback would otherwise need to do back through
// the issuer URL. The Signer is provided by keys.Fx over the shared
// keypair aggregate; TokenStore and DeviceCodeStore are both satisfied by
// state/sqlite via fx.As; ClientRegistry is the same instance /authorize
// uses, so a code minted without PKCE is redeemable only by the
// confidential client that secret-authenticates here. Wiring the
// DeviceCodeStore in unconditionally turns the RFC 8628 grant branch on
// for every tempogate deployment — opting back out would mean removing
// the /device_authorization registrar as well, so the consistent posture
// is to expose the whole device flow or none of it.
func newToken(p tokenParams) *Token {
	return NewToken(p.Store, p.Signer, p.Clients, WithDeviceCodeStore(p.Devices))
}

// newTokenRegistrar exposes the shared *Token's HTTP surface as a registrar
// in the api_registrars group.
func newTokenRegistrar(t *Token) func(huma.API) {
	return t.Register
}

type sessionManagerParams struct {
	fx.In

	Store BrowserSessionStore

	TTL           time.Duration `name:"oidc_session_ttl"`
	SigningKeyB64 string        `name:"oidc_session_signing_key"`
}

// newSessionManager builds the device-flow verification-page session manager
// against the shared BrowserSessionStore. The HMAC-SHA256 signing key is
// validated here so a misconfigured OIDC__SESSION_SIGNING_KEY fails graph
// construction at startup — never at the first failed cookie verify under
// load. An empty key is treated as missing (mirrors how OIDC__CLIENTS
// surfaces an unset value); a base64url-decoded length other than 32 is
// rejected because a shorter key would silently weaken the cookie MAC.
func newSessionManager(p sessionManagerParams) (*SessionManager, error) {
	if p.SigningKeyB64 == "" {
		return nil, fmt.Errorf("oidc: OIDC__SESSION_SIGNING_KEY is required (base64url-encoded %d bytes)", sessionSigningKeyBytes)
	}
	key, err := base64.RawURLEncoding.DecodeString(p.SigningKeyB64)
	if err != nil {
		return nil, fmt.Errorf("oidc: OIDC__SESSION_SIGNING_KEY must be base64url-encoded: %w", err)
	}
	if len(key) != sessionSigningKeyBytes {
		return nil, fmt.Errorf("oidc: OIDC__SESSION_SIGNING_KEY must decode to %d bytes, got %d", sessionSigningKeyBytes, len(key))
	}

	opts := []SessionOption{}
	if p.TTL > 0 {
		opts = append(opts, WithSessionTTL(p.TTL))
	}
	return NewSessionManager(p.Store, key, opts...), nil
}

type userInfoParams struct {
	fx.In

	Verifier *keys.Verifier
}

// newUserInfoRegistrar builds the /userinfo endpoint. The Verifier is
// provided by keys.Fx over the same keypair aggregate the Signer uses, so a
// token minted by /token verifies here.
func newUserInfoRegistrar(p userInfoParams) func(huma.API) {
	u := NewUserInfo(p.Verifier)
	return u.Register
}

type deviceAuthorizationParams struct {
	fx.In

	Store   DeviceCodeStore
	Clients ClientRegistry

	Issuer string `name:"oidc_issuer"`
}

// newDeviceAuthorizationRegistrar builds the /device_authorization endpoint.
// DeviceCodeStore is satisfied by state/sqlite via fx.As; ClientRegistry is
// the same instance /authorize and /token use, so the "registered public
// client" gate stays in lockstep with the PKCE posture decided there.
func newDeviceAuthorizationRegistrar(p deviceAuthorizationParams) func(huma.API) {
	h := NewDeviceAuthorization(p.Store, p.Clients, p.Issuer)
	return h.Register
}

type deviceUIParams struct {
	fx.In

	Devices  DeviceCodeStore
	Sessions *SessionManager
	Clients  ClientRegistry
	Token    *Token
	Logger   *slog.Logger

	Issuer             string `name:"oidc_issuer"`
	SigningKeyB64      string `name:"oidc_session_signing_key"`
	GoogleAuthEndpoint string `name:"google_auth_endpoint"`
}

// newDeviceUIRegistrar builds the verification-UI surface. The internal
// tempogate-device-ui client must be present in the shared ClientRegistry
// and registered confidential — NewDeviceUI surfaces both misconfigurations
// as graph-construction errors, so an operator who forgets the
// OIDC__CLIENT_SECRETS entry learns about it at startup rather than when
// the first user submits the verification form. The signing key is the
// same one OIDC__SESSION_SIGNING_KEY backs SessionManager with, decoded
// once here so the bounce state and the session cookie share a single
// cryptographic root.
func newDeviceUIRegistrar(p deviceUIParams) (func(huma.API), error) {
	key, err := base64.RawURLEncoding.DecodeString(p.SigningKeyB64)
	if err != nil {
		return nil, fmt.Errorf("oidc: OIDC__SESSION_SIGNING_KEY must be base64url-encoded: %w", err)
	}
	if len(key) != sessionSigningKeyBytes {
		return nil, fmt.Errorf("oidc: OIDC__SESSION_SIGNING_KEY must decode to %d bytes, got %d", sessionSigningKeyBytes, len(key))
	}
	ui, err := NewDeviceUI(p.Devices, p.Sessions, p.Clients, p.Token, key, p.Issuer,
		// Whitelist the upstream IdP's origin in the device_enter page's CSP
		// form-action directive. CSP3 checks form-action across the redirect
		// chain (POST /device → 303 /authorize → 302 upstream), so the
		// cross-origin hop is silently dropped by the browser unless this
		// source is present.
		WithUpstreamIDPOrigin(p.GoogleAuthEndpoint),
		// Surface the device-flow SSO callback failure modes through the
		// project's structured logger. Without this, every callback failure
		// collapses into the same generic HTML page with no log trail and
		// the operator has no way to diagnose a stuck device flow.
		WithDeviceUILogger(p.Logger),
	)
	if err != nil {
		return nil, err
	}
	return ui.Register, nil
}

// Fx contributes the /authorize, /callback/google, /token, /userinfo,
// /device_authorization and /device* registrars into the shared
// "api_registrars" group the api package collects. The store, upstream,
// signer and verifier dependencies are satisfied by state/sqlite,
// oidc/google and keys via fx.As / fx.Provide.
func Fx() fx.Option {
	return fx.Options(
		fx.Provide(newClientRegistry),
		fx.Provide(newSessionManager),
		fx.Provide(newToken),
		fx.Provide(
			fx.Annotate(
				newAuthorizeRegistrar,
				fx.ResultTags(`group:"api_registrars"`),
			),
		),
		fx.Provide(
			fx.Annotate(
				newCallbackRegistrar,
				fx.ResultTags(`group:"api_registrars"`),
			),
		),
		fx.Provide(
			fx.Annotate(
				newTokenRegistrar,
				fx.ResultTags(`group:"api_registrars"`),
			),
		),
		fx.Provide(
			fx.Annotate(
				newUserInfoRegistrar,
				fx.ResultTags(`group:"api_registrars"`),
			),
		),
		fx.Provide(
			fx.Annotate(
				newDeviceAuthorizationRegistrar,
				fx.ResultTags(`group:"api_registrars"`),
			),
		),
		fx.Provide(
			fx.Annotate(
				newDeviceUIRegistrar,
				fx.ResultTags(`group:"api_registrars"`),
			),
		),
	)
}
