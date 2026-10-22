package oidc_test

import (
	"errors"
	"net/http"
	"net/url"
	"time"
)

func (s *DeviceUISuite) TestSSOCallbackAccessDeniedDeniesTheDeviceCode() {
	state := s.signedBounceState(deviceUITestUserCanonical, deviceUITestStateNonce, deviceUINow.Add(time.Minute).Unix())
	resp, err := s.client.Do(s.req(http.MethodGet,
		"/device/sso-callback?error=access_denied&error_description=whatever&state="+url.QueryEscape(state)))
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Equal(http.StatusForbidden, resp.StatusCode)
	body := readBody(s.T(), resp)
	s.Contains(body, "Access denied")
	s.Contains(body, "no access to Temporal")
	s.NotContains(body, "whatever", "the upstream description is never reflected")
	s.Empty(resp.Cookies(), "no session is issued")
	s.Equal(1, s.store.countDenied(), "the CLI's next poll gets access_denied")
	s.Zero(s.store.countApproved())
	s.Zero(s.redeemer.callCount())
	s.Empty(s.observed.denials(), "the callback already counted this refusal")
}

func (s *DeviceUISuite) TestSSOCallbackAccessDeniedNeedsAValidState() {
	resp, err := s.client.Do(s.req(http.MethodGet, "/device/sso-callback?error=access_denied&state=forged"))
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Equal(http.StatusOK, resp.StatusCode)
	s.Contains(readBody(s.T(), resp), "could not be completed")
	s.Zero(s.store.countDenied(), "a forged state cannot end someone's device login")
}

func (s *DeviceUISuite) TestSSOCallbackAccessDeniedOnADecidedCodeStillRendersThePage() {
	s.Require().NoError(s.store.DenyDeviceCode(s.T().Context(), deviceUITestUserCanonical, deviceUINow))
	state := s.signedBounceState(deviceUITestUserCanonical, deviceUITestStateNonce, deviceUINow.Add(time.Minute).Unix())
	resp, err := s.client.Do(s.req(http.MethodGet, "/device/sso-callback?error=access_denied&state="+url.QueryEscape(state)))
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusForbidden, resp.StatusCode)
}

func (s *DeviceUISuite) TestConfirmWithNoPermissionsDeniesInsteadOfPrompting() {
	cookieValue := s.seedSession()
	s.resolver.denyEmail(deviceUITestEmail)
	r := s.req(http.MethodGet, "/device/confirm?user_code="+deviceUITestUserDisplay)
	r.Header.Set("Cookie", cookieValue)
	resp, err := s.client.Do(r)
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Equal(http.StatusForbidden, resp.StatusCode)
	body := readBody(s.T(), resp)
	s.Contains(body, "Access denied")
	s.NotContains(body, `action="/device/approve"`)
	s.Equal(1, s.store.countDenied())
	s.Equal([]string{"device_verification"}, s.observed.denials())
}

func (s *DeviceUISuite) TestApproveWithNoPermissionsDenies() {
	// The session was issued while the person still had a grant; the rule
	// has since gone (sessions outlive rule changes).
	cookieValue := s.seedSession()
	s.resolver.denyEmail(deviceUITestEmail)
	form := url.Values{"csrf_token": {deviceUITestSID}, "user_code": {deviceUITestUserDisplay}}
	r := s.post("/device/approve", form)
	r.Header.Set("Cookie", cookieValue)
	resp, err := s.client.Do(r)
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Equal(http.StatusForbidden, resp.StatusCode)
	s.Contains(readBody(s.T(), resp), "Access denied")
	s.Zero(s.store.countApproved(), "no device code is approved for a person with no grant")
	s.Equal(1, s.store.countDenied())
	s.Equal([]string{"device_verification"}, s.observed.denials())
}

func (s *DeviceUISuite) TestResolverFailureOnConfirmIsServerError() {
	cookieValue := s.seedSession()
	s.resolver.err = errors.New("directory unavailable")
	r := s.req(http.MethodGet, "/device/confirm?user_code="+deviceUITestUserDisplay)
	r.Header.Set("Cookie", cookieValue)
	resp, err := s.client.Do(r)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusInternalServerError, resp.StatusCode)
	s.Zero(s.store.countDenied())
}

func (s *DeviceUISuite) TestResolverFailureOnApproveIsServerError() {
	cookieValue := s.seedSession()
	s.resolver.err = errors.New("directory unavailable")
	form := url.Values{"csrf_token": {deviceUITestSID}, "user_code": {deviceUITestUserDisplay}}
	r := s.post("/device/approve", form)
	r.Header.Set("Cookie", cookieValue)
	resp, err := s.client.Do(r)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusInternalServerError, resp.StatusCode)
	s.Zero(s.store.countApproved())
}

func (s *DeviceUISuite) TestDenyForNoAccessStoreFailureIsServerError() {
	s.store.denyErr = errors.New("disk fell off")
	state := s.signedBounceState(deviceUITestUserCanonical, deviceUITestStateNonce, deviceUINow.Add(time.Minute).Unix())
	resp, err := s.client.Do(s.req(http.MethodGet, "/device/sso-callback?error=access_denied&state="+url.QueryEscape(state)))
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusInternalServerError, resp.StatusCode)
}
