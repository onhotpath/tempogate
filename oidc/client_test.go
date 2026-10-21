package oidc_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/onhotpath/tempogate/oidc"
)

type ClientRegistrySuite struct {
	suite.Suite
}

func TestClientRegistrySuite(t *testing.T) {
	suite.Run(t, new(ClientRegistrySuite))
}

var (
	authCodeGrants   = []oidc.GrantType{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken}
	deviceOnlyGrants = []oidc.GrantType{oidc.GrantTypeDeviceCode, oidc.GrantTypeRefreshToken}
)

func (s *ClientRegistrySuite) TestParse() {
	cases := []struct {
		name string
		raw  string
		want oidc.ClientRegistry
	}{
		{
			name: "empty string yields empty registry",
			raw:  "",
			want: oidc.ClientRegistry{},
		},
		{
			name: "single entry keeps scheme after first colon and is public",
			raw:  "ui:https://app.example.com/cb",
			want: oidc.ClientRegistry{"ui": oidc.Client{
				RedirectURIs: []string{"https://app.example.com/cb"},
				GrantTypes:   authCodeGrants,
			}},
		},
		{
			name: "multiple entries with surrounding spaces",
			raw:  "ui:https://app.example.com/cb, cli:http://127.0.0.1/callback",
			want: oidc.ClientRegistry{
				"ui": oidc.Client{
					RedirectURIs: []string{"https://app.example.com/cb"},
					GrantTypes:   authCodeGrants,
				},
				"cli": oidc.Client{
					RedirectURIs: []string{"http://127.0.0.1/callback"},
					GrantTypes:   authCodeGrants,
				},
			},
		},
		{
			name: "repeating an id registers several exact URIs in order",
			raw:  "ui:https://a.example.com/cb,ui:https://b.example.com/cb",
			want: oidc.ClientRegistry{"ui": oidc.Client{
				RedirectURIs: []string{"https://a.example.com/cb", "https://b.example.com/cb"},
				GrantTypes:   authCodeGrants,
			}},
		},
		{
			name: "IPv6 loopback without port",
			raw:  "cli:http://[::1]/callback",
			want: oidc.ClientRegistry{"cli": oidc.Client{
				RedirectURIs: []string{"http://[::1]/callback"},
				GrantTypes:   authCodeGrants,
			}},
		},
		{
			name: "empty value registers a device-only client (documented form)",
			raw:  "tempogate-device:",
			want: oidc.ClientRegistry{"tempogate-device": oidc.Client{GrantTypes: deviceOnlyGrants}},
		},
	}

	for _, tc := range cases {
		s.Run(tc.name, func() {
			got, err := oidc.ParseClientRegistry(tc.raw)
			s.Require().NoError(err)
			s.Equal(tc.want, got)
			for id := range got {
				s.Falsef(got.IsConfidential(id), "%s must be public until WithSecrets opts it in", id)
			}
		})
	}
}

// TestParseRejects pins the fail-fast startup validation: anything that is
// not an exact, absolute redirect URI (in particular the old prefix shapes)
// must stop the server from booting rather than widen what /authorize
// accepts.
func (s *ClientRegistrySuite) TestParseRejects() {
	cases := []struct {
		name string
		raw  string
	}{
		{"missing colon", "noseparator"},
		{"empty id", ":https://app.example.com/cb"},
		{"duplicate (id, uri) pair", "ui:https://a.example.com/cb,ui:https://a.example.com/cb"},
		{"duplicate device-only entry", "dev:,dev:"},
		{"device-only mixed with a URI (empty first)", "dev:,dev:https://a.example.com/cb"},
		{"device-only mixed with a URI (URI first)", "dev:https://a.example.com/cb,dev:"},
		{"old loopback prefix with trailing colon", "cli:http://127.0.0.1:"},
		{"loopback with a pinned port", "cli:http://127.0.0.1:39473/callback"},
		{"IPv6 loopback with a pinned port", "cli:http://[::1]:39473/callback"},
		{"loopback without a path", "cli:http://127.0.0.1"},
		{"loopback with a query", "cli:http://127.0.0.1/callback?x=1"},
		{"bare scheme prefix", "ui:https://"},
		{"host-only prefix, no path", "ui:https://ui.example.com"},
		{"host with trailing colon", "ui:https://ui.example.com:/cb"},
		{"userinfo", "ui:https://user@ui.example.com/cb"},
		{"userinfo hiding the real host", "ui:https://ui.example.com@evil.example/cb"},
		{"fragment", "ui:https://ui.example.com/cb#frag"},
		{"empty fragment", "ui:https://ui.example.com/cb#"},
		{"relative reference", "ui:/cb"},
		{"scheme-relative", "ui://ui.example.com/cb"},
		{"opaque URI", "ui:https:ui.example.com/cb"},
		{"unparseable", "ui:https://ui.example.com/%zz"},
		{"non-loopback plain http without the insecure flag", "ui:http://temporal-ui:8080/auth/sso/callback"},
		{"localhost is not loopback class", "ui:http://localhost:8080/cb"},
		{"custom scheme", "ui:com.example.app:/cb"},
		{"old e2e device form", "tempogate-device:cli"},
	}

	for _, tc := range cases {
		s.Run(tc.name, func() {
			_, err := oidc.ParseClientRegistry(tc.raw)
			s.Require().Error(err)
			s.ErrorIs(err, oidc.ErrInvalidClientRegistration)
		})
	}
}

// TestParseInsecureFlag proves OIDC_ALLOW_INSECURE_REDIRECT_URIS only relaxes
// the https requirement for non-loopback URIs; every structural check (no
// userinfo, no prefix shape, ...) still applies.
func (s *ClientRegistrySuite) TestParseInsecureFlag() {
	reg, err := oidc.ParseClientRegistry(
		"ui:http://temporal-ui:8080/auth/sso/callback,dev:http://localhost:8080/cb",
		oidc.AllowInsecureRedirectURIs(true),
	)
	s.Require().NoError(err)
	s.Equal([]string{"http://temporal-ui:8080/auth/sso/callback"}, reg["ui"].RedirectURIs)

	for _, raw := range []string{
		"ui:http://temporal-ui:8080",
		"ui:http://127.0.0.1:",
		"ui:http://x@temporal-ui:8080/cb",
		"ui:ftp://temporal-ui/cb",
	} {
		_, err := oidc.ParseClientRegistry(raw, oidc.AllowInsecureRedirectURIs(true))
		s.Require().Errorf(err, "%s must still be rejected with the insecure flag", raw)
	}
}

// TestWithSecrets covers the deliberately-separate confidential opt-in: only a
// registered client may be given a secret, and a typo (unknown id, dup, empty)
// must fail fast so the PKCE carve-out can never be enabled by accident.
func (s *ClientRegistrySuite) TestWithSecrets() {
	cases := []struct {
		name      string
		secrets   string
		wantErr   error
		wantConf  []string
		wantPlain []string
	}{
		{
			name:      "empty leaves every client public",
			secrets:   "",
			wantPlain: []string{"ui", "cli"},
		},
		{
			name:      "secret promotes exactly one client to confidential",
			secrets:   "ui:s3cr3t",
			wantConf:  []string{"ui"},
			wantPlain: []string{"cli"},
		},
		{
			name:     "secret may itself contain colons",
			secrets:  "ui:a:b:c",
			wantConf: []string{"ui"},
		},
		{
			name:    "secret for unregistered client_id fails",
			secrets: "ghost:s3cr3t",
			wantErr: oidc.ErrUnknownClientSecret,
		},
		{
			name:    "malformed secret entry fails",
			secrets: "noseparator",
			wantErr: errSentinelAny,
		},
		{
			name:    "empty secret fails",
			secrets: "ui:",
			wantErr: errSentinelAny,
		},
		{
			name:    "duplicate secret for same client fails",
			secrets: "ui:a,ui:b",
			wantErr: errSentinelAny,
		},
	}

	for _, tc := range cases {
		s.Run(tc.name, func() {
			reg, err := oidc.ParseClientRegistry("ui:https://app.example.com/cb,cli:http://127.0.0.1/callback")
			s.Require().NoError(err)

			err = reg.WithSecrets(tc.secrets)
			if tc.wantErr != nil {
				s.Require().Error(err)
				if tc.wantErr != errSentinelAny {
					s.Truef(errors.Is(err, tc.wantErr), "want %v, got %v", tc.wantErr, err)
				}
				return
			}
			s.Require().NoError(err)
			for _, id := range tc.wantConf {
				s.Truef(reg.IsConfidential(id), "%s should be confidential", id)
			}
			for _, id := range tc.wantPlain {
				s.Falsef(reg.IsConfidential(id), "%s should stay public", id)
			}
		})
	}
}

// TestValidate is the C1 attack table: every vector that used to slip past
// the prefix check, plus the loopback edge cases RFC 8252 §7.3 / RFC 9700
// §2.1 call out, must be rejected; only the exact registered URI (or, for the
// loopback class, the exact path on any port) is accepted.
func (s *ClientRegistrySuite) TestValidate() {
	reg, err := oidc.ParseClientRegistry(
		"ui:https://ui.example.com/auth/sso/callback," +
			"ui:https://ui.example.com/other?tenant=a," +
			"cli:http://127.0.0.1/callback," +
			"cli6:http://[::1]/callback," +
			"tempogate-device:",
	)
	s.Require().NoError(err)

	cases := []struct {
		name        string
		clientID    string
		redirectURI string
		wantErr     error
	}{
		// Accepted.
		{"exact match", "ui", "https://ui.example.com/auth/sso/callback", nil},
		{"exact match with registered query", "ui", "https://ui.example.com/other?tenant=a", nil},
		{"loopback any port", "cli", "http://127.0.0.1:54321/callback", nil},
		{"loopback another port", "cli", "http://127.0.0.1:1/callback", nil},
		{"loopback no port", "cli", "http://127.0.0.1/callback", nil},
		{"IPv6 loopback any port", "cli6", "http://[::1]:54321/callback", nil},

		// Client-level failures.
		{"unknown client", "other", "https://ui.example.com/auth/sso/callback", oidc.ErrUnknownClient},
		{"device-only client at the code flow", "tempogate-device", "http://127.0.0.1:1234/callback", oidc.ErrUnauthorizedClient},
		{"device-only client with empty redirect", "tempogate-device", "", oidc.ErrUnauthorizedClient},

		// Old-prefix bypasses from the C1 table.
		{"loopback userinfo", "cli", "http://127.0.0.1:@evil.example/callback", oidc.ErrRedirectURINotAllowed},
		{"loopback userinfo with port", "cli", "http://127.0.0.1:1234@evil.example/callback", oidc.ErrRedirectURINotAllowed},
		{"host suffix", "ui", "https://ui.example.com.evil.tld/auth/sso/callback", oidc.ErrRedirectURINotAllowed},
		{"userinfo", "ui", "https://ui.example.com@evil.tld/auth/sso/callback", oidc.ErrRedirectURINotAllowed},
		{"dot-segment escape", "ui", "https://ui.example.com/auth/sso/callback/../../open-redirect?to=https://evil.tld", oidc.ErrRedirectURINotAllowed},
		{"path extension", "ui", "https://ui.example.com/auth/sso/callback/extra", oidc.ErrRedirectURINotAllowed},

		// Acceptance-criteria extras.
		{"loopback host suffix", "cli", "http://127.0.0.1.evil.tld:1234/callback", oidc.ErrRedirectURINotAllowed},
		{"localhost when only 127.0.0.1 registered", "cli", "http://localhost:1234/callback", oidc.ErrRedirectURINotAllowed},
		{"loopback fragment", "cli", "http://127.0.0.1:1234/callback#frag", oidc.ErrRedirectURINotAllowed},
		{"loopback empty fragment", "cli", "http://127.0.0.1:1234/callback#", oidc.ErrRedirectURINotAllowed},
		{"loopback over https", "cli", "https://127.0.0.1:1234/callback", oidc.ErrRedirectURINotAllowed},
		{"scheme-relative", "cli", "//evil.tld", oidc.ErrRedirectURINotAllowed},
		{"scheme-relative loopback", "cli", "//127.0.0.1:1234/callback", oidc.ErrRedirectURINotAllowed},
		{"uppercase host", "ui", "https://UI.example.com/auth/sso/callback", oidc.ErrRedirectURINotAllowed},
		{"uppercase scheme", "ui", "HTTPS://ui.example.com/auth/sso/callback", oidc.ErrRedirectURINotAllowed},
		{"uppercase scheme loopback", "cli", "HTTP://127.0.0.1:1234/callback", oidc.ErrRedirectURINotAllowed},
		{"percent-encoded host", "ui", "https://ui%2Eexample.com/auth/sso/callback", oidc.ErrRedirectURINotAllowed},
		{"percent-encoded loopback host", "cli", "http://%31%32%37.0.0.1:1234/callback", oidc.ErrRedirectURINotAllowed},
		{"percent-encoded path", "ui", "https://ui.example.com/auth/sso/%63allback", oidc.ErrRedirectURINotAllowed},
		{"percent-encoded loopback path", "cli", "http://127.0.0.1:1234/%63allback", oidc.ErrRedirectURINotAllowed},
		{"trailing slash", "ui", "https://ui.example.com/auth/sso/callback/", oidc.ErrRedirectURINotAllowed},
		{"loopback trailing slash", "cli", "http://127.0.0.1:1234/callback/", oidc.ErrRedirectURINotAllowed},
		{"loopback dot segment", "cli", "http://127.0.0.1:1234/x/../callback", oidc.ErrRedirectURINotAllowed},
		{"loopback unexpected query", "cli", "http://127.0.0.1:1234/callback?next=https://evil.tld", oidc.ErrRedirectURINotAllowed},
		{"loopback empty query", "cli", "http://127.0.0.1:1234/callback?", oidc.ErrRedirectURINotAllowed},
		{"loopback empty port", "cli", "http://127.0.0.1:/callback", oidc.ErrRedirectURINotAllowed},
		{"loopback other address", "cli", "http://127.0.0.2:1234/callback", oidc.ErrRedirectURINotAllowed},
		{"IPv4 loopback against IPv6 registration", "cli6", "http://127.0.0.1:1234/callback", oidc.ErrRedirectURINotAllowed},
		{"expanded IPv6 loopback", "cli6", "http://[0:0:0:0:0:0:0:1]:1234/callback", oidc.ErrRedirectURINotAllowed},
		{"default port is not a wildcard for non-loopback", "ui", "https://ui.example.com:443/auth/sso/callback", oidc.ErrRedirectURINotAllowed},
		{"missing registered query", "ui", "https://ui.example.com/other", oidc.ErrRedirectURINotAllowed},
		{"extra query", "ui", "https://ui.example.com/auth/sso/callback?x=1", oidc.ErrRedirectURINotAllowed},
		{"unparseable", "cli", "http://127.0.0.1:1234/%zz", oidc.ErrRedirectURINotAllowed},
		{"empty redirect_uri", "ui", "", oidc.ErrRedirectURINotAllowed},
	}

	for _, tc := range cases {
		s.Run(tc.name, func() {
			err := reg.Validate(tc.clientID, tc.redirectURI)
			if tc.wantErr != nil {
				s.Require().Error(err)
				s.Truef(errors.Is(err, tc.wantErr), "want %v, got %v", tc.wantErr, err)
				return
			}
			s.Require().NoError(err)
		})
	}
}

func (s *ClientRegistrySuite) TestAllows() {
	reg, err := oidc.ParseClientRegistry("ui:https://ui.example.com/cb,dev:")
	s.Require().NoError(err)

	s.True(reg["ui"].Allows(oidc.GrantTypeAuthorizationCode))
	s.True(reg["ui"].Allows(oidc.GrantTypeRefreshToken))
	s.False(reg["ui"].Allows(oidc.GrantTypeDeviceCode))

	s.False(reg["dev"].Allows(oidc.GrantTypeAuthorizationCode))
	s.True(reg["dev"].Allows(oidc.GrantTypeRefreshToken))
	s.True(reg["dev"].Allows(oidc.GrantTypeDeviceCode))
}

// TestAuthenticate proves the carve-out can never degrade into "no PKCE and no
// client auth": a public client, an unknown client, a wrong secret, and an
// empty presented secret all fail; only the exact registered secret passes.
func (s *ClientRegistrySuite) TestAuthenticate() {
	reg := oidc.ClientRegistry{
		"ui":     oidc.Client{RedirectURIs: []string{"https://app.example.com/cb"}, Secret: "right-secret"},
		"public": oidc.Client{RedirectURIs: []string{"https://spa.example.com/cb"}},
	}

	cases := []struct {
		name      string
		clientID  string
		presented string
		want      bool
	}{
		{"correct secret authenticates", "ui", "right-secret", true},
		{"wrong secret fails", "ui", "wrong-secret", false},
		{"empty presented secret fails", "ui", "", false},
		{"public client never authenticates by secret", "public", "anything", false},
		{"unknown client fails", "ghost", "right-secret", false},
	}

	for _, tc := range cases {
		s.Run(tc.name, func() {
			s.Equal(tc.want, reg.Authenticate(tc.clientID, tc.presented))
		})
	}
}

// errSentinelAny marks table cases that only assert "some error", distinct
// from cases that pin a specific sentinel via errors.Is.
var errSentinelAny = errors.New("any error")
