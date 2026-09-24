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

func (s *ClientRegistrySuite) TestParse() {
	cases := []struct {
		name    string
		raw     string
		want    oidc.ClientRegistry
		wantErr bool
	}{
		{
			name: "empty string yields empty registry",
			raw:  "",
			want: oidc.ClientRegistry{},
		},
		{
			name: "single entry keeps scheme after first colon and is public",
			raw:  "ui:https://app.example.com/cb",
			want: oidc.ClientRegistry{"ui": oidc.Client{RedirectPrefix: "https://app.example.com/cb"}},
		},
		{
			name: "multiple entries with surrounding spaces",
			raw:  "ui:https://app.example.com/cb, cli:http://127.0.0.1",
			want: oidc.ClientRegistry{
				"ui":  oidc.Client{RedirectPrefix: "https://app.example.com/cb"},
				"cli": oidc.Client{RedirectPrefix: "http://127.0.0.1"},
			},
		},
		{
			name:    "missing colon is an error",
			raw:     "noseparator",
			wantErr: true,
		},
		{
			name:    "empty id is an error",
			raw:     ":https://app.example.com",
			wantErr: true,
		},
		{
			name:    "empty prefix is an error",
			raw:     "ui:",
			wantErr: true,
		},
		{
			name:    "duplicate client_id is an error",
			raw:     "ui:https://a.example.com,ui:https://b.example.com",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		s.Run(tc.name, func() {
			got, err := oidc.ParseClientRegistry(tc.raw)
			if tc.wantErr {
				s.Require().Error(err)
				return
			}
			s.Require().NoError(err)
			s.Equal(tc.want, got)
			for id := range got {
				s.Falsef(got.IsConfidential(id), "%s must be public until WithSecrets opts it in", id)
			}
		})
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
			reg, err := oidc.ParseClientRegistry("ui:https://app.example.com/cb,cli:http://127.0.0.1")
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

func (s *ClientRegistrySuite) TestValidate() {
	reg := oidc.ClientRegistry{"ui": oidc.Client{RedirectPrefix: "https://app.example.com/auth"}}

	cases := []struct {
		name        string
		clientID    string
		redirectURI string
		wantErr     error
	}{
		{
			name:        "known client under prefix",
			clientID:    "ui",
			redirectURI: "https://app.example.com/auth/callback",
		},
		{
			name:        "unknown client",
			clientID:    "other",
			redirectURI: "https://app.example.com/auth/callback",
			wantErr:     oidc.ErrUnknownClient,
		},
		{
			name:        "redirect_uri outside prefix",
			clientID:    "ui",
			redirectURI: "https://evil.example.com/auth/callback",
			wantErr:     oidc.ErrRedirectURINotAllowed,
		},
		{
			name:        "empty redirect_uri",
			clientID:    "ui",
			redirectURI: "",
			wantErr:     oidc.ErrRedirectURINotAllowed,
		},
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

// TestAuthenticate proves the carve-out can never degrade into "no PKCE and no
// client auth": a public client, an unknown client, a wrong secret, and an
// empty presented secret all fail; only the exact registered secret passes.
func (s *ClientRegistrySuite) TestAuthenticate() {
	reg := oidc.ClientRegistry{
		"ui":     oidc.Client{RedirectPrefix: "https://app.example.com/cb", Secret: "right-secret"},
		"public": oidc.Client{RedirectPrefix: "https://spa.example.com/cb"},
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
