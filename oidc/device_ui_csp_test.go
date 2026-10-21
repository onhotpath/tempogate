package oidc_test

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"regexp"
)

var (
	inlineStylePattern = regexp.MustCompile(`(?s)<style>(.*?)</style>`)
	styleAttrPattern   = regexp.MustCompile(`(?i)\sstyle\s*=`)
	eventAttrPattern   = regexp.MustCompile(`(?i)\son[a-z]+\s*=`)
)

// devicePageResponses renders every device-ui page shape a browser can land
// on: the entry form, the confirm prompt, the approved and denied results,
// and the error page.
func (s *DeviceUISuite) devicePageResponses() map[string]*http.Response {
	out := map[string]*http.Response{}
	get := func(name, path string, cookie string) {
		r := s.req(http.MethodGet, path)
		if cookie != "" {
			r.Header.Set("Cookie", cookie)
		}
		resp, err := s.client.Do(r)
		s.Require().NoError(err)
		out[name] = resp
	}
	get("enter", "/device", "")
	get("confirm", "/device/confirm?user_code="+deviceUITestUserDisplay, s.seedSession())
	get("error", "/device/confirm", s.seedSession())

	form := url.Values{"csrf_token": {deviceUITestSID}, "user_code": {deviceUITestUserDisplay}}
	approve := s.post("/device/approve", form)
	approve.Header.Set("Cookie", s.seedSession())
	resp, err := s.client.Do(approve)
	s.Require().NoError(err)
	out["approved"] = resp

	deny := s.post("/device/deny", form)
	deny.Header.Set("Cookie", s.seedSession())
	resp, err = s.client.Do(deny)
	s.Require().NoError(err)
	out["denied"] = resp
	return out
}

// TestDevicePagesSendCSPHeader: the policy must travel as a header, because
// browsers ignore frame-ancestors in a <meta> CSP and the confirm page is
// exactly what a clickjacking page would frame. The page sets its own policy
// (not just the listener default) since only it knows its form-action
// sources.
func (s *DeviceUISuite) TestDevicePagesSendCSPHeader() {
	for name, resp := range s.devicePageResponses() {
		body := readBody(s.T(), resp)
		_ = resp.Body.Close()
		s.Equal(http.StatusOK, resp.StatusCode, name)
		csp := resp.Header.Get("Content-Security-Policy")
		s.Contains(csp, "default-src 'none'", name)
		s.Contains(csp, "frame-ancestors 'none'", name)
		s.Contains(csp, "base-uri 'none'", name)
		s.Contains(csp, "form-action 'self'", name)
		s.NotContains(csp, "'unsafe-inline'", "%s: inline styles are allowed by hash, not wholesale", name)
		s.NotContains(body, `http-equiv="Content-Security-Policy"`,
			"%s: a second, meta-delivered policy would intersect with the header and could silently drift from it", name)
	}
}

// TestDevicePagesKeepSameOriginReferrer: the listener default is
// no-referrer, but under no-referrer a browser sends "Origin: null" on the
// Approve/Deny POST, which the CSRF origin check rejects. The device pages
// therefore opt back into same-origin.
func (s *DeviceUISuite) TestDevicePagesKeepSameOriginReferrer() {
	for name, resp := range s.devicePageResponses() {
		_ = resp.Body.Close()
		s.Equal("same-origin", resp.Header.Get("Referrer-Policy"), name)
	}
}

// TestDevicePagesInlineCodeAllowedByCSP: the CSP allows exactly the one
// inline <style> block by hash and nothing else, so the pages must carry no
// inline script, no style attribute and no event-handler attribute, and the
// style block must hash to the value the policy names. A template edit that
// changes the CSS without the hash following would leave the page unstyled.
func (s *DeviceUISuite) TestDevicePagesInlineCodeAllowedByCSP() {
	for name, resp := range s.devicePageResponses() {
		body := readBody(s.T(), resp)
		_ = resp.Body.Close()
		s.NotContains(body, "<script", name)
		s.NotRegexp(styleAttrPattern, body, name)
		s.NotRegexp(eventAttrPattern, body, name)

		blocks := inlineStylePattern.FindAllStringSubmatch(body, -1)
		s.Require().Len(blocks, 1, "%s: exactly one inline <style> block", name)
		sum := sha256.Sum256([]byte(blocks[0][1]))
		want := "style-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
		s.Contains(resp.Header.Get("Content-Security-Policy"), want, name)
	}
}
