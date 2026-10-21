package oidc_test

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"

	"github.com/onhotpath/tempogate/api/requestid"
	"github.com/onhotpath/tempogate/oidc"
)

// TestServerErrorsRenderHTMLWithRequestID pins the device UI's 5xx contract:
// a browser that hits a storage failure gets the HTML error page (not a JSON
// problem document) at 500, the page names the request id, and the cause is
// logged once under that id without leaking it to the page.
func (s *DeviceUISuite) TestServerErrorsRenderHTMLWithRequestID() {
	storeErr := errors.New("sqlite: SQL logic error: no such table: device_codes (/var/lib/tempogate/state.db)")

	cases := []struct {
		name  string
		setup func()
		req   func(cookie string) *http.Request
	}{
		{
			name:  "enter submit lookup",
			setup: func() { s.store.lookupErr = storeErr },
			req: func(string) *http.Request {
				return s.post("/device", url.Values{"user_code": {deviceUITestUserDisplay}})
			},
		},
		{
			name:  "confirm lookup",
			setup: func() { s.store.lookupErr = storeErr },
			req: func(cookie string) *http.Request {
				r := s.req(http.MethodGet, "/device/confirm?user_code="+deviceUITestUserDisplay)
				r.Header.Set("Cookie", cookie)
				return r
			},
		},
		{
			name:  "approve flip",
			setup: func() { s.store.approveErr = storeErr },
			req: func(cookie string) *http.Request {
				r := s.post("/device/approve", url.Values{"csrf_token": {deviceUITestSID}, "user_code": {deviceUITestUserDisplay}})
				r.Header.Set("Cookie", cookie)
				return r
			},
		},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			s.store.lookupErr, s.store.approveErr = nil, nil
			cookie := s.seedSession()
			tc.setup()

			var logs bytes.Buffer
			srv := s.deviceUIServerWithRequestIDs(&logs)
			defer srv.Close()

			r := tc.req(cookie)
			target, err := url.Parse(srv.URL)
			s.Require().NoError(err)
			r.URL.Host = target.Host

			resp, err := s.client.Do(r)
			s.Require().NoError(err)
			defer resp.Body.Close()
			page := readBody(s.T(), resp)
			reqID := resp.Header.Get(requestid.Header)

			s.Equal(http.StatusInternalServerError, resp.StatusCode)
			s.True(strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html"), "got %q", resp.Header.Get("Content-Type"))
			s.Equal("no-store", resp.Header.Get("Cache-Control"))
			s.Require().NotEmpty(reqID)
			s.Contains(page, reqID)
			s.NotContains(page, "sqlite")
			s.NotContains(page, "no such table")
			s.NotContains(page, "/var/lib/tempogate")

			line := decodeSingleLogLine(s.T(), logs.Bytes())
			s.Equal("ERROR", line["level"])
			s.Equal(reqID, line["request_id"])
			s.Contains(line["err"], "no such table")
			assertNoSecretLeak(s.T(), logs.Bytes(), []string{deviceUITestSID, cookie})
		})
	}
	s.store.lookupErr, s.store.approveErr = nil, nil
}

func (s *DeviceUISuite) deviceUIServerWithRequestIDs(logs *bytes.Buffer) *httptest.Server {
	ui, err := oidc.NewDeviceUI(s.store, s.sessions, s.clients, s.redeemer, s.key, testIssuer,
		oidc.WithDeviceUIClock(func() time.Time { return deviceUINow }),
		oidc.WithDeviceUIStateNonceGenerator(func() (string, error) { return deviceUITestStateNonce, nil }),
		oidc.WithDeviceUILogger(slog.New(slog.NewJSONHandler(logs, nil))),
	)
	s.Require().NoError(err)
	mux := http.NewServeMux()
	ui.Register(humago.New(mux, huma.DefaultConfig("device-ui-5xx-test", "0.0.0")))
	return httptest.NewServer(requestid.Middleware(mux))
}
