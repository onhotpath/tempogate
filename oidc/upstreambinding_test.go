package oidc_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/onhotpath/tempogate/oidc"
)

func newTestBinding(t *testing.T, issuer string) *oidc.UpstreamBinding {
	t.Helper()
	return newTestBindingWithKey(t, issuer, testSigningKeyText)
}

func newTestBindingWithKey(t *testing.T, issuer, key string) *oidc.UpstreamBinding {
	t.Helper()
	b, err := oidc.NewUpstreamBinding(issuer, []byte(key))
	require.NoError(t, err)
	return b
}

type UpstreamBindingSuite struct {
	suite.Suite
}

func TestUpstreamBindingSuite(t *testing.T) {
	suite.Run(t, new(UpstreamBindingSuite))
}

func (s *UpstreamBindingSuite) TestRejectsAKeyThatIsNot32Bytes() {
	for _, key := range []string{"", "short", testSigningKeyText + "x"} {
		_, err := oidc.NewUpstreamBinding(testIssuer, []byte(key))
		s.Error(err, "key of %d bytes", len(key))
	}
}

// TestHTTPSIssuerUsesHostPrefixedCookie: on https the binding cookie carries
// the __Host- prefix, which the browser only accepts when Secure, host-only
// and Path=/; a sibling subdomain therefore cannot plant one.
func (s *UpstreamBindingSuite) TestHTTPSIssuerUsesHostPrefixedCookie() {
	for _, issuer := range []string{testIssuer, testIssuer + "/idp"} {
		c := newTestBinding(s.T(), issuer).Cookie("google", "st")
		s.True(strings.HasPrefix(c.Name, "__Host-"), c.Name)
		s.True(c.Secure)
		s.Equal("/", c.Path)
		s.Empty(c.Domain)
		s.True(c.HttpOnly)
		s.Equal(http.SameSiteLaxMode, c.SameSite)
		s.NoError(c.Valid())
	}
}

// TestPlainHTTPIssuerFallsBackToPathScopedCookie: a browser refuses a
// __Host- or Secure cookie over plain http, so a local/compose issuer gets an
// unprefixed cookie scoped to the callback path instead.
func (s *UpstreamBindingSuite) TestPlainHTTPIssuerFallsBackToPathScopedCookie() {
	cases := map[string]string{
		"http://tempogate:8000":      "/callback/google",
		"http://tempogate:8000/":     "/callback/google",
		"http://localhost:8000/idp/": "/idp/callback/google",
	}
	for issuer, path := range cases {
		c := newTestBinding(s.T(), issuer).Cookie("google", "st")
		s.False(strings.HasPrefix(c.Name, "__Host-"), c.Name)
		s.False(c.Secure)
		s.Equal(path, c.Path)
		s.True(c.HttpOnly)
		s.NoError(c.Valid())
	}
}

func (s *UpstreamBindingSuite) TestCookieIsPerStateAndKeyed() {
	b := newTestBinding(s.T(), testIssuer)
	one, two := b.Cookie("google", "state-one"), b.Cookie("google", "state-two")
	s.NotEqual(one.Name, two.Name, "concurrent logins in one browser must not overwrite each other")
	s.NotEqual(one.Value, two.Value)
	s.NotContains(one.Value, "state-one")
	s.Equal(one.Value, b.Cookie("google", "state-one").Value, "deterministic for a state")

	other := newTestBindingWithKey(s.T(), testIssuer, "fedcba9876543210fedcba9876543210")
	s.NotEqual(one.Value, other.Cookie("google", "state-one").Value, "the value depends on the server key")
}

// TestRoundTripBindsTheGoogleLeg drives /authorize then /callback/google with
// one binding: the browser carries the cookie from one to the other, and the
// upstream is handed the verifier and nonce that match exactly what
// /authorize sent Google.
func (s *UpstreamBindingSuite) TestRoundTripBindsTheGoogleLeg() {
	store := newMemCallbackStore()
	binding := newTestBinding(s.T(), testIssuer)
	reg, err := oidc.ParseClientRegistry("ui:" + testRedirectURI)
	s.Require().NoError(err)
	up := &fakeUpstream{id: aliceIdentity()}

	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("test", "0.0.0"))
	conns := googleConnectors(s.T(), up, "")
	oidc.New(store, reg, binding, conns, testIssuer).Register(api)
	oidc.NewCallback(store, conns, binding, "example.com", oidc.WithCallbackPermissionResolver(permitAll)).Register(api)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// The test server is plain http, but the binding is for an https
	// issuer, so the jar would withhold the Secure cookie; carry it by hand
	// exactly as the browser would over TLS.
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(srv.URL + "/authorize?" + validParams().Encode())
	s.Require().NoError(err)
	_ = resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)
	s.Require().Len(resp.Cookies(), 1)
	bindingCookie := resp.Cookies()[0]

	upstream, err := url.Parse(resp.Header.Get("Location"))
	s.Require().NoError(err)
	uq := upstream.Query()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/callback/google?"+callbackQuery("google-code", uq.Get("state")).Encode(), http.NoBody)
	s.Require().NoError(err)
	req.AddCookie(bindingCookie)
	resp, err = client.Do(req)
	s.Require().NoError(err)
	_ = resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)

	s.Equal("google-code", up.gotCode)
	s.Equal(uq.Get("code_challenge"), s256(up.gotVerifier), "the verifier must match the challenge sent to Google")
	s.Equal(uq.Get("nonce"), up.gotNonce, "the nonce checked must be the one sent to Google")
}
