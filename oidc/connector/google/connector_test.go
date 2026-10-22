package google_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/onhotpath/tempogate/oidc"
	"github.com/onhotpath/tempogate/oidc/connector/google"
)

const testAuthEndpoint = "https://accounts.google.com/o/oauth2/v2/auth"

type stubExchanger struct {
	id    google.Identity
	err   error
	calls int
}

func (e *stubExchanger) ExchangeAndVerify(context.Context, string, string, string, string) (google.Identity, error) {
	e.calls++
	return e.id, e.err
}

func newConnector(t *testing.T, hosted string, ex google.Exchanger) *google.Connector {
	t.Helper()
	c, err := google.NewConnector(google.Config{
		ClientID:      testClientID,
		AuthEndpoint:  testAuthEndpoint,
		IssuerURL:     "https://accounts.google.com",
		HostedDomains: hosted,
	}, ex)
	require.NoError(t, err)
	return c
}

func TestConnectorDescribesGoogle(t *testing.T) {
	c := newConnector(t, "", &stubExchanger{})
	require.Equal(t, "google", c.ID())
	require.NoError(t, oidc.ValidateConnectorID(c.ID()))
	require.Equal(t, "Google", c.DisplayName())
	require.Equal(t, oidc.Flow{ResponseMethod: http.MethodGet, StateParam: "state"}, c.Flow())
	sources, err := c.FormActionSources(context.Background())
	require.NoError(t, err)
	require.Equal(t, []string{"https://accounts.google.com"}, sources)
}

func TestNewConnectorRejectsAMalformedAuthEndpoint(t *testing.T) {
	for _, raw := range []string{"http://%zz/bad", "/relative", ""} {
		_, err := google.NewConnector(google.Config{AuthEndpoint: raw}, &stubExchanger{})
		require.Error(t, err, raw)
	}
}

func TestBeginSendsTheServersBindingValues(t *testing.T) {
	start, err := newConnector(t, "", &stubExchanger{}).Begin(context.Background(), oidc.BeginParams{
		RedirectURI:   "https://tempogate.example.com/callback/google",
		State:         "st",
		CodeChallenge: "challenge",
		Nonce:         "nonce",
		RequestID:     "_unused",
	})
	require.NoError(t, err)
	u, err := url.Parse(start.RedirectURL)
	require.NoError(t, err)
	require.Equal(t, "accounts.google.com", u.Host)
	require.Equal(t, "/o/oauth2/v2/auth", u.Path)
	require.Equal(t, url.Values{
		"client_id":             {testClientID},
		"redirect_uri":          {"https://tempogate.example.com/callback/google"},
		"response_type":         {"code"},
		"scope":                 {"openid email"},
		"state":                 {"st"},
		"code_challenge":        {"challenge"},
		"code_challenge_method": {"S256"},
		"nonce":                 {"nonce"},
	}, u.Query(), "the verifier and request id never leave tempogate")
}

// TestBeginHostedDomainHint covers the `hd` parameter sent to Google. It is a
// UX hint only (Google pre-selects the Workspace account); Complete's `hd`
// claim check is the security control.
func TestBeginHostedDomainHint(t *testing.T) {
	for _, tc := range []struct{ hosted, want string }{
		{"", ""},
		{" Example.COM ", "example.com"},
		{"example.com,corp.example.org", "*"},
	} {
		hosted, want := tc.hosted, tc.want
		start, err := newConnector(t, hosted, &stubExchanger{}).Begin(context.Background(), oidc.BeginParams{State: "st"})
		require.NoError(t, err)
		u, err := url.Parse(start.RedirectURL)
		require.NoError(t, err)
		require.Equal(t, want != "", u.Query().Has("hd"), hosted)
		require.Equal(t, want, u.Query().Get("hd"), hosted)
	}
}

func TestComplete(t *testing.T) {
	alice := google.Identity{Subject: "sub-alice", Email: "alice@example.com", EmailVerified: true, HostedDomain: "example.com"}
	cases := []struct {
		name     string
		hosted   string
		params   url.Values
		exchange error
		wantErr  func(*testing.T, error)
		refusal  string
		calls    int
	}{
		{
			name:   "an upstream error is forwarded first",
			params: url.Values{"error": {"access_denied"}, "error_description": {"declined"}, "code": {"c"}},
			wantErr: func(t *testing.T, err error) {
				var denied *oidc.UpstreamDenied
				require.ErrorAs(t, err, &denied)
				require.Equal(t, oidc.UpstreamDenied{Code: "access_denied", Description: "declined"}, *denied)
			},
		},
		{
			name:    "no code",
			params:  url.Values{"state": {"st"}},
			wantErr: func(t *testing.T, err error) { require.ErrorIs(t, err, oidc.ErrMissingResponse) },
		},
		{
			name:   "RFC 9207 iss of another issuer",
			params: url.Values{"code": {"c"}, "iss": {"https://evil.example.com"}},
			wantErr: func(t *testing.T, err error) {
				var ue *oidc.UpstreamError
				require.ErrorAs(t, err, &ue)
				require.Equal(t, oidc.UpstreamReasonIssuer, ue.Reason)
			},
		},
		{name: "RFC 9207 iss of Google", params: url.Values{"code": {"c"}, "iss": {"https://accounts.google.com"}}, calls: 1},
		{
			name:     "exchange failure",
			params:   url.Values{"code": {"c"}},
			exchange: &oidc.UpstreamError{Reason: oidc.UpstreamReasonExchange, Err: errors.New("invalid_grant")},
			wantErr: func(t *testing.T, err error) {
				var ue *oidc.UpstreamError
				require.ErrorAs(t, err, &ue)
				require.Equal(t, oidc.UpstreamReasonExchange, ue.Reason)
			},
			calls: 1,
		},
		{name: "workspace off", params: url.Values{"code": {"c"}}, calls: 1},
		{name: "workspace on, hd listed", hosted: "EXAMPLE.com", params: url.Values{"code": {"c"}}, calls: 1},
		{name: "workspace on, hd not listed", hosted: "corp.example.org", params: url.Values{"code": {"c"}}, refusal: oidc.RefusalHostedDomainNotAllowed, calls: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ex := &stubExchanger{id: alice, err: tc.exchange}
			got, err := newConnector(t, tc.hosted, ex).Complete(context.Background(), oidc.CompleteParams{Params: tc.params})
			require.Equal(t, tc.calls, ex.calls)
			if tc.wantErr != nil {
				tc.wantErr(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, oidc.Completion{
				Identity: oidc.UpstreamIdentity{Subject: "sub-alice", Email: "alice@example.com", EmailVerified: true},
				Refusal:  tc.refusal,
			}, got)
		})
	}
}
