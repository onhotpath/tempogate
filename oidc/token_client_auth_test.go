package oidc_test

import (
	"net/http"
	"net/url"
	"time"

	"github.com/onhotpath/tempogate/oidc"
)

// confPKCEAuthCode is a code minted for the confidential client that also
// sent a PKCE challenge at /authorize. Both proofs are then owed at /token
// (RFC 9700 §2.1.1): the secret authenticates the client, the verifier binds
// the code to its authorization request.
func (s *TokenSuite) confPKCEAuthCode(code string) oidc.AuthCode {
	ac := s.confAuthCode(code)
	ac.CodeChallenge = pkceChallenge
	ac.CodeChallengeMethod = "S256"
	return ac
}

// TestConfidentialClientAlwaysAuthenticates is the M1 regression: a stored
// PKCE challenge must not stand in for a confidential client's secret, and
// the secret must not stand in for a stored challenge.
func (s *TokenSuite) TestConfidentialClientAlwaysAuthenticates() {
	cases := []struct {
		name       string
		pkce       bool   // the code was minted with a PKCE challenge
		verifier   string // code_verifier in the body
		formSecret string // client_secret in the body
		basic      bool   // send webui:confidentialSecret as HTTP Basic instead
		wantStatus int
		wantErr    string
	}{
		{"pkce code, verifier only, no secret", true, pkceVerifier, "", false, http.StatusUnauthorized, "invalid_client"},
		{"pkce code, verifier and wrong secret", true, pkceVerifier, "not-the-secret", false, http.StatusUnauthorized, "invalid_client"},
		{"pkce code, verifier and form secret", true, pkceVerifier, confidentialSecret, false, http.StatusOK, ""},
		{"pkce code, verifier and basic secret", true, pkceVerifier, "", true, http.StatusOK, ""},
		{"pkce code, secret but no verifier", true, "", confidentialSecret, false, http.StatusBadRequest, "invalid_grant"},
		{"pkce code, secret but wrong verifier", true, "wrong-verifier-wrong-verifier-wrong-verifier-0", confidentialSecret, false, http.StatusBadRequest, "invalid_grant"},
		{"no-pkce code, no secret", false, "", "", false, http.StatusUnauthorized, "invalid_client"},
		{"no-pkce code, verifier only", false, pkceVerifier, "", false, http.StatusUnauthorized, "invalid_client"},
		{"no-pkce code, form secret", false, "", confidentialSecret, false, http.StatusOK, ""},
		{"no-pkce code, basic secret", false, "", "", true, http.StatusOK, ""},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			ac := s.confAuthCode("conf-1")
			if tc.pkce {
				ac = s.confPKCEAuthCode("conf-1")
			}
			s.store.putCode(ac)

			f := confCodeForm()
			if tc.verifier != "" {
				f.Set("code_verifier", tc.verifier)
			}
			if tc.formSecret != "" {
				f.Set("client_secret", tc.formSecret)
			}
			var resp *http.Response
			if tc.basic {
				f.Del("client_id")
				resp = s.postBasic(f, "webui", confidentialSecret)
			} else {
				resp = s.post(f)
			}
			defer resp.Body.Close()

			s.Require().Equal(tc.wantStatus, resp.StatusCode)
			if tc.wantErr != "" {
				s.Equal(tc.wantErr, s.decodeOAuthError(resp))
				return
			}
			s.NotEmpty(s.decodeTokenResponse(resp).AccessToken)
		})
	}
}

// TestFailedClientAuthDoesNotBurnCode: client authentication is decided by
// the request, before the single-use code is consumed, so someone holding a
// leaked code but not the secret cannot invalidate it for the real client.
func (s *TokenSuite) TestFailedClientAuthDoesNotBurnCode() {
	s.store.putCode(s.confPKCEAuthCode("conf-1"))

	f := confCodeForm()
	f.Set("code_verifier", pkceVerifier)
	stolen := s.post(f)
	defer stolen.Body.Close()
	s.Require().Equal(http.StatusUnauthorized, stolen.StatusCode)
	s.Equal("invalid_client", s.decodeOAuthError(stolen))

	f.Set("client_secret", confidentialSecret)
	resp := s.post(f)
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)
}

// TestBasicInvalidClientSendsWWWAuthenticate: a client that tried HTTP Basic
// and failed gets the challenge RFC 6749 §5.2 requires with the 401, naming
// the scheme it used. A form-body attempt gets no challenge, since the client
// never used an HTTP authentication scheme.
func (s *TokenSuite) TestBasicInvalidClientSendsWWWAuthenticate() {
	s.store.putCode(s.confPKCEAuthCode("conf-1"))

	f := confCodeForm()
	f.Del("client_id")
	f.Set("code_verifier", pkceVerifier)
	basic := s.postBasic(f, "webui", "not-the-secret")
	defer basic.Body.Close()
	s.Require().Equal(http.StatusUnauthorized, basic.StatusCode)
	s.Equal(`Basic realm="tempogate"`, basic.Header.Get("WWW-Authenticate"))
	s.Equal("invalid_client", s.decodeOAuthError(basic))

	f.Set("client_id", "webui")
	f.Set("client_secret", "not-the-secret")
	form := s.post(f)
	defer form.Body.Close()
	s.Require().Equal(http.StatusUnauthorized, form.StatusCode)
	s.Empty(form.Header.Get("WWW-Authenticate"))
}

// TestPublicClientUnchanged: a public client still redeems with the verifier
// alone and sends no secret.
func (s *TokenSuite) TestPublicClientUnchanged() {
	s.store.putCode(s.authCode("code-1"))

	resp := s.post(authCodeForm())
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)
}

func (s *TokenSuite) TestUnknownClientIsInvalidClient() {
	s.store.putCode(s.authCode("code-1"))

	f := authCodeForm()
	f.Set("client_id", "someone-else")
	resp := s.post(f)
	defer resp.Body.Close()
	s.Equal(http.StatusUnauthorized, resp.StatusCode)
	s.Equal("invalid_client", s.decodeOAuthError(resp))
}

// TestGrantTypeNotAllowedIsUnauthorizedClient: /token enforces the grants a
// client's registration allows (RFC 6749 §5.2), not just /authorize and
// /device_authorization.
func (s *TokenSuite) TestGrantTypeNotAllowedIsUnauthorizedClient() {
	// Registrations ParseClientRegistry cannot produce: every parsed client
	// may refresh, so these exercise the refresh_token check directly.
	s.clients["no-refresh"] = oidc.Client{
		RedirectURIs: []string{testRedirectURI},
		GrantTypes:   []oidc.GrantType{oidc.GrantTypeAuthorizationCode},
	}

	refresh := func(token, clientID string) url.Values {
		s.store.putRefresh(oidc.Refresh{
			Token: token, ClientID: clientID, Email: "alice@example.com",
			CreatedAt: signNow, ExpiresAt: signNow.Add(time.Hour),
		})
		f := url.Values{}
		f.Set("grant_type", "refresh_token")
		f.Set("refresh_token", token)
		f.Set("client_id", clientID)
		return f
	}
	deviceOnlyCode := func() url.Values {
		ac := s.authCode("dev-1")
		ac.ClientID = "tempogate-device"
		s.store.putCode(ac)
		f := authCodeForm()
		f.Set("code", "dev-1")
		f.Set("client_id", "tempogate-device")
		return f
	}

	cases := []struct {
		name string
		form func() url.Values
	}{
		{"device-only client uses authorization_code", deviceOnlyCode},
		{"auth-code-only client uses device_code", func() url.Values { return deviceForm("dc-1", "ui") }},
		{"client without refresh_token uses refresh_token", func() url.Values { return refresh("rt-1", "no-refresh") }},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			resp := s.post(tc.form())
			defer resp.Body.Close()
			s.Equal(http.StatusBadRequest, resp.StatusCode)
			s.Equal("unauthorized_client", s.decodeOAuthError(resp))
		})
	}

	// A token whose client has since been deregistered cannot be redeemed:
	// the client presenting it no longer authenticates.
	deregistered := s.post(refresh("rt-2", "deregistered"))
	defer deregistered.Body.Close()
	s.Equal(http.StatusUnauthorized, deregistered.StatusCode)
	s.Equal("invalid_client", s.decodeOAuthError(deregistered))
}

// TestDeviceCodeGrantAuthenticatesConfidentialClient: the device grant runs
// the same client authentication, so a device client registered with a
// secret must present it (form or HTTP Basic) on every poll.
func (s *TokenSuite) TestDeviceCodeGrantAuthenticatesConfidentialClient() {
	const id, secret = "conf-device", "conf-device-secret"
	s.clients[id] = oidc.Client{GrantTypes: []oidc.GrantType{oidc.GrantTypeDeviceCode}, Secret: secret}

	noSecret := s.post(deviceForm("dc-1", id))
	defer noSecret.Body.Close()
	s.Equal(http.StatusUnauthorized, noSecret.StatusCode)
	s.Equal("invalid_client", s.decodeOAuthError(noSecret))

	// Authenticated, so the request reaches the device-code lookup.
	f := deviceForm("dc-1", "")
	basic := s.postBasic(f, id, secret)
	defer basic.Body.Close()
	s.Equal(http.StatusBadRequest, basic.StatusCode)
	s.Equal("invalid_grant", s.decodeOAuthError(basic))
}

// TestPublicClientNoChallengeCodeIsInvalidGrant: a verifier cannot redeem a
// code that was never bound to a challenge, so a public client can never
// complete the flow without PKCE.
func (s *TokenSuite) TestPublicClientNoChallengeCodeIsInvalidGrant() {
	ac := s.authCode("code-1")
	ac.CodeChallenge = ""
	s.store.putCode(ac)

	resp := s.post(authCodeForm())
	defer resp.Body.Close()
	s.Equal(http.StatusBadRequest, resp.StatusCode)
	s.Equal("invalid_grant", s.decodeOAuthError(resp))
}
