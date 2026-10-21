package admin_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/onhotpath/tempogate/admin"
)

const (
	guardToken      = "tg-admin-primary-token"
	guardOtherToken = "tg-admin-rotated-token"
)

func digestHex(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func mustDigests(t *testing.T, csv string) [][sha256.Size]byte {
	t.Helper()
	d, err := admin.ParseTokenDigests(csv)
	require.NoError(t, err)
	return d
}

func TestParseTokenDigests(t *testing.T) {
	good := digestHex(guardToken)
	other := digestHex(guardOtherToken)
	cases := []struct {
		name    string
		in      string
		wantLen int
		wantErr bool
	}{
		{name: "empty locks the api", in: "", wantLen: 0},
		{name: "single digest", in: good, wantLen: 1},
		{name: "rotation list with whitespace", in: " " + good + " , " + other + " ", wantLen: 2},
		{name: "trailing comma tolerated", in: good + ",", wantLen: 1},
		{name: "uppercase hex accepted", in: strings.ToUpper(good), wantLen: 1},
		{name: "too short", in: good[:63], wantErr: true},
		{name: "too long", in: good + "0", wantErr: true},
		{name: "not hex", in: strings.Repeat("z", 64), wantErr: true},
		{name: "raw token instead of digest", in: guardToken, wantErr: true},
		{name: "one bad entry fails the whole list", in: good + ",nope", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := admin.ParseTokenDigests(tc.in)
			if tc.wantErr {
				require.Error(t, err)
				// The error must never echo the configured value back: an
				// operator who pasted the raw token would leak it to logs.
				require.NotContains(t, err.Error(), guardToken)
				return
			}
			require.NoError(t, err)
			require.Len(t, got, tc.wantLen)
		})
	}
}

type GuardSuite struct {
	suite.Suite

	logs *observer.ObservedLogs
	srv  *httptest.Server
}

func TestGuardSuite(t *testing.T) {
	suite.Run(t, new(GuardSuite))
}

// newGuardedAPI reproduces the api package's admin ordering: the open probe is
// registered before the guard is installed, so Huma's per-registration
// middleware capture leaves it outside the guard; everything after is inside.
func newGuardedAPI(g *admin.Guard, registrars ...func(huma.API)) (*http.ServeMux, huma.API) {
	mux := http.NewServeMux()
	a := humago.New(mux, huma.DefaultConfig("test", "0.0.0"))
	huma.Register(a, huma.Operation{
		OperationID: "open-probe",
		Method:      http.MethodGet,
		Path:        "/admin/healthz",
	}, func(_ context.Context, _ *struct{}) (*struct{}, error) { return &struct{}{}, nil })
	g.Install(a)
	huma.Register(a, huma.Operation{
		OperationID: "guarded-probe",
		Method:      http.MethodGet,
		Path:        "/admin/probe",
	}, func(_ context.Context, _ *struct{}) (*struct{}, error) { return &struct{}{}, nil })
	for _, r := range registrars {
		r(a)
	}
	return mux, a
}

func (s *GuardSuite) SetupTest() {
	core, logs := observer.New(zapcore.DebugLevel)
	s.logs = logs
	g := admin.NewGuard(
		admin.WithTokenDigests(mustDigests(s.T(), digestHex(guardToken)+","+digestHex(guardOtherToken))),
		admin.WithAllowedHosts([]string{"127.0.0.1:8081", "localhost:8081", "[::1]:8081", "admin.internal"}),
		admin.WithGuardLogger(zap.New(core)),
	)
	mux, _ := newGuardedAPI(g)
	s.srv = httptest.NewServer(mux)
}

func (s *GuardSuite) TearDownTest() { s.srv.Close() }

func (s *GuardSuite) do(path, host, authz string) *http.Response {
	req, err := http.NewRequest(http.MethodGet, s.srv.URL+path, http.NoBody)
	s.Require().NoError(err)
	if host != "" {
		req.Host = host
	}
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	resp, err := http.DefaultClient.Do(req)
	s.Require().NoError(err)
	s.Require().NoError(resp.Body.Close())
	return resp
}

func (s *GuardSuite) TestRequests() {
	cases := []struct {
		name       string
		path       string
		host       string
		authz      string
		wantStatus int
		wantReason string
	}{
		{name: "healthz open without auth", path: "/admin/healthz", host: "localhost:8081", wantStatus: http.StatusNoContent},
		{name: "healthz open on a foreign host", path: "/admin/healthz", host: "evil.example", wantStatus: http.StatusNoContent},
		{name: "no header", path: "/admin/probe", host: "localhost:8081", wantStatus: http.StatusUnauthorized, wantReason: "missing_credentials"},
		{name: "wrong scheme", path: "/admin/probe", host: "localhost:8081", authz: "Basic " + guardToken, wantStatus: http.StatusUnauthorized, wantReason: "missing_credentials"},
		{name: "empty bearer", path: "/admin/probe", host: "localhost:8081", authz: "Bearer ", wantStatus: http.StatusUnauthorized, wantReason: "missing_credentials"},
		{name: "wrong token", path: "/admin/probe", host: "localhost:8081", authz: "Bearer nope", wantStatus: http.StatusUnauthorized, wantReason: "invalid_token"},
		{name: "digest sent as token", path: "/admin/probe", host: "localhost:8081", authz: "Bearer " + digestHex(guardToken), wantStatus: http.StatusUnauthorized, wantReason: "invalid_token"},
		{name: "valid token", path: "/admin/probe", host: "localhost:8081", authz: "Bearer " + guardToken, wantStatus: http.StatusNoContent},
		{name: "scheme is case-insensitive", path: "/admin/probe", host: "localhost:8081", authz: "bearer " + guardToken, wantStatus: http.StatusNoContent},
		{name: "rotated second digest accepted", path: "/admin/probe", host: "127.0.0.1:8081", authz: "Bearer " + guardOtherToken, wantStatus: http.StatusNoContent},
		{name: "ipv6 loopback host", path: "/admin/probe", host: "[::1]:8081", authz: "Bearer " + guardToken, wantStatus: http.StatusNoContent},
		{name: "host compare is case-insensitive", path: "/admin/probe", host: "LOCALHOST:8081", authz: "Bearer " + guardToken, wantStatus: http.StatusNoContent},
		{name: "portless entry matches any port", path: "/admin/probe", host: "admin.internal:443", authz: "Bearer " + guardToken, wantStatus: http.StatusNoContent},
		{name: "rebinding host rejected before auth", path: "/admin/probe", host: "evil.example", wantStatus: http.StatusMisdirectedRequest, wantReason: "host_not_allowed"},
		{name: "rebinding host rejected even with a valid token", path: "/admin/probe", host: "evil.example:8081", authz: "Bearer " + guardToken, wantStatus: http.StatusMisdirectedRequest, wantReason: "host_not_allowed"},
		{name: "allowed name on the wrong port", path: "/admin/probe", host: "localhost:9999", authz: "Bearer " + guardToken, wantStatus: http.StatusMisdirectedRequest, wantReason: "host_not_allowed"},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			s.logs.TakeAll()
			resp := s.do(tc.path, tc.host, tc.authz)
			s.Equal(tc.wantStatus, resp.StatusCode)
			if tc.wantStatus == http.StatusUnauthorized {
				s.Equal(`Bearer realm="tempogate-admin"`, resp.Header.Get("WWW-Authenticate"))
			}
			rejected := s.logs.FilterMessage("admin request rejected").All()
			if tc.wantReason == "" {
				s.Empty(rejected)
				return
			}
			s.Require().Len(rejected, 1)
			entry := rejected[0]
			s.Equal(zapcore.WarnLevel, entry.Level)
			fields := entry.ContextMap()
			s.Equal(tc.wantReason, fields["reason"])
			s.Equal("denied", fields["outcome"])
			s.Equal(tc.path, fields["path"])
			s.NotEmpty(fields["remote_addr"])
			for _, v := range fields {
				if str, ok := v.(string); ok {
					s.NotContains(str, guardToken, "the presented token must never be logged")
				}
			}
		})
	}
}

func TestGuardLockedWithoutDigests(t *testing.T) {
	core, logs := observer.New(zapcore.DebugLevel)
	g := admin.NewGuard(
		admin.WithAllowedHosts([]string{"localhost:8081"}),
		admin.WithGuardLogger(zap.New(core)),
	)
	mux, _ := newGuardedAPI(g)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	for _, authz := range []string{"", "Bearer ", "Bearer anything"} {
		req, err := http.NewRequest(http.MethodGet, srv.URL+"/admin/probe", http.NoBody)
		require.NoError(t, err)
		req.Host = "localhost:8081"
		if authz != "" {
			req.Header.Set("Authorization", authz)
		}
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "authz=%q", authz)
	}

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/admin/healthz", http.NoBody)
	require.NoError(t, err)
	req.Host = "localhost:8081"
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusNoContent, resp.StatusCode, "a locked admin API still answers its liveness probe")

	reasons := map[any]bool{}
	for _, e := range logs.FilterMessage("admin request rejected").All() {
		reasons[e.ContextMap()["reason"]] = true
	}
	require.True(t, reasons["locked"], "a locked API must say so in the rejection log")
}

func TestGuardDeclaresBearerSecurityScheme(t *testing.T) {
	g := admin.NewGuard()
	_, a := newGuardedAPI(g)
	schemes := a.OpenAPI().Components.SecuritySchemes
	require.Contains(t, schemes, admin.SecurityScheme)
	require.Equal(t, "http", schemes[admin.SecurityScheme].Type)
	require.Equal(t, "bearer", schemes[admin.SecurityScheme].Scheme)
}

func TestGuardNilLoggerPanics(t *testing.T) {
	require.Panics(t, func() { admin.WithGuardLogger(nil) })
}
