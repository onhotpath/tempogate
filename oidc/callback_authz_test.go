package oidc_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"

	"github.com/onhotpath/tempogate/oidc"
)

func (s *CallbackSuite) TestNoPermissionsRedirectsAccessDeniedWithoutACode() {
	s.resolver.denyEmail("alice@example.com")
	s.store.put(s.pendingRequest(fixedState))

	resp := s.get(callbackQuery("google-code-xyz", fixedState))
	defer resp.Body.Close()

	s.Equal(http.StatusFound, resp.StatusCode)
	loc, err := url.Parse(resp.Header.Get("Location"))
	s.Require().NoError(err)
	target, _ := url.Parse(testRedirectURI)
	s.Equal(target.Host+target.Path, loc.Host+loc.Path, "sent back to the client, which can tell the user")
	q := loc.Query()
	s.Equal("access_denied", q.Get("error"))
	s.Contains(q.Get("error_description"), "no Temporal access is granted to this account")
	s.NotContains(q.Get("error_description"), "alice", "the redirect names no identity")
	s.Empty(q.Get("code"))
	s.Equal("client-state-abc", q.Get("state"))
	s.Equal(testIssuer, q.Get("iss"))
	s.Contains(resp.Header.Get("Set-Cookie"), "Max-Age=0", "the binding cookie is cleared")

	s.Equal(0, s.store.codeCount(), "no code is minted for a person with no grant")
	s.False(s.store.pending(fixedState), "the auth request is spent")
	s.Equal([]string{"failure/authz_denied"}, s.observed.logins)
	s.Equal([]string{"login"}, s.observed.denials())
	s.Contains(s.logs.String(), `"cause":"authz_denied"`)
	s.Contains(s.logs.String(), `"email":"alice@example.com"`)
}

func (s *CallbackSuite) TestAdmissionGatesRunBeforeAuthorization() {
	s.up.id.Email = "mallory@evil.example.net"
	s.store.put(s.pendingRequest(fixedState))

	resp := s.get(callbackQuery("c", fixedState))
	defer resp.Body.Close()
	s.Equal(http.StatusForbidden, resp.StatusCode)
	s.Empty(s.resolver.calls(), "a person refused admission is never resolved")
}

func (s *CallbackSuite) TestResolverFailureIsServerError() {
	s.resolver.err = errors.New("directory unavailable")
	s.store.put(s.pendingRequest(fixedState))

	resp := s.get(callbackQuery("c", fixedState))
	defer resp.Body.Close()
	s.Equal(http.StatusInternalServerError, resp.StatusCode)
	s.Equal(0, s.store.codeCount())
	s.Equal([]string{"failure/internal"}, s.observed.logins)
}

func (s *CallbackSuite) TestCallbackWithoutResolverDeniesEveryone() {
	c := oidc.NewCallback(s.store, s.up, s.binding, allowedDomains,
		oidc.WithCallbackIssuer(testIssuer),
		oidc.WithCallbackClock(func() time.Time { return fixedNow }),
	)
	mux := http.NewServeMux()
	c.Register(humago.New(mux, huma.DefaultConfig("test", "0.0.0")))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	s.store.put(s.pendingRequest(fixedState))

	resp := s.getFrom(srv, callbackQuery("c", fixedState), s.binding.Cookie(fixedState))
	defer resp.Body.Close()
	s.Equal(http.StatusFound, resp.StatusCode)
	loc, err := url.Parse(resp.Header.Get("Location"))
	s.Require().NoError(err)
	s.Equal("access_denied", loc.Query().Get("error"))
	s.Equal(0, s.store.codeCount())
}
