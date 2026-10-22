package admin_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/onhotpath/tempogate/admin"
	"github.com/onhotpath/tempogate/keys"
)

// AuditSuite drives the keys handler behind the guard, the way the admin
// listener serves it, and asserts on the structured audit trail and on the
// temporal-system grant gate.
type AuditSuite struct {
	suite.Suite

	logs     *observer.ObservedLogs
	registry *memRegistry
	srv      *httptest.Server
}

func TestAuditSuite(t *testing.T) {
	suite.Run(t, new(AuditSuite))
}

func (s *AuditSuite) setup(extra ...admin.KeysOption) {
	core, logs := observer.New(zapcore.DebugLevel)
	s.logs = logs
	logger := zap.New(core)

	ks := keys.New(keys.WithStore(&memKeyStore{}), keys.WithGenerateOptions(keys.WithRSABits(2048)))
	s.Require().NoError(ks.Init(context.Background()))
	signer := keys.NewSigner(keys.WithKeys(ks), keys.WithIssuer(testIssuer))
	s.registry = newMemRegistry(func() time.Time { return signNow })

	h := admin.NewKeys(s.registry, signer, append([]admin.KeysOption{admin.WithLogger(logger)}, extra...)...)
	g := admin.NewGuard(
		admin.WithTokenDigests(mustDigests(s.T(), digestHex(guardToken))),
		admin.WithAllowedHosts([]string{"localhost:8081"}),
		admin.WithGuardLogger(logger),
	)
	mux, _ := newGuardedAPI(g, h.Register)
	s.srv = httptest.NewServer(mux)
	s.T().Cleanup(s.srv.Close)
}

func (s *AuditSuite) request(method, path, body string) (*http.Response, []byte) {
	var rdr io.Reader = http.NoBody
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, s.srv.URL+path, rdr)
	s.Require().NoError(err)
	req.Host = "localhost:8081"
	req.Header.Set("Authorization", "Bearer "+guardToken)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	s.Require().NoError(err)
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)
	return resp, b
}

func (s *AuditSuite) audit() []observer.LoggedEntry {
	return s.logs.FilterMessage("admin audit").All()
}

func (s *AuditSuite) TestCreateAndRevokeAreAudited() {
	s.setup()
	resp, b := s.request(http.MethodPost, admin.KeysPath, withExpiry(`{"namespace":"payments","role":"worker","owner":"svc-recon"}`))
	s.Require().Equal(http.StatusCreated, resp.StatusCode, string(b))
	var created postResp
	s.Require().NoError(json.Unmarshal(b, &created))
	row, err := s.registry.ByID(context.Background(), created.ID)
	s.Require().NoError(err)

	entries := s.audit()
	s.Require().Len(entries, 1)
	f := entries[0].ContextMap()
	s.Equal(zapcore.InfoLevel, entries[0].Level)
	s.Equal("create", f["action"])
	s.Equal("success", f["outcome"])
	s.Equal(created.ID, f["id"])
	s.Equal(row.JTI, f["jti"])
	s.Equal("payments", f["namespace"])
	s.Equal("worker", f["role"])
	s.Equal("svc-recon", f["owner"])
	s.Equal(digestHex(guardToken)[:8], f["caller"], "caller is the matched digest's fingerprint")
	s.NotEmpty(f["remote_addr"])
	for _, v := range f {
		if str, ok := v.(string); ok {
			s.NotContains(str, guardToken)
			s.NotContains(str, created.JWT)
		}
	}

	s.logs.TakeAll()
	resp, _ = s.request(http.MethodDelete, "/admin/keys/"+created.ID, "")
	s.Require().Equal(http.StatusNoContent, resp.StatusCode)
	entries = s.audit()
	s.Require().Len(entries, 1)
	f = entries[0].ContextMap()
	s.Equal("revoke", f["action"])
	s.Equal("success", f["outcome"])
	s.Equal(created.ID, f["id"])
	s.Equal(row.JTI, f["jti"])
	s.Equal("payments", f["namespace"])
	s.Equal("worker", f["role"])
	s.Equal("svc-recon", f["owner"])
	s.Equal(digestHex(guardToken)[:8], f["caller"])
	s.NotEmpty(f["remote_addr"])
}

func (s *AuditSuite) TestRejectedCreateIsAudited() {
	s.setup()
	resp, _ := s.request(http.MethodPost, admin.KeysPath, withExpiry(`{"namespace":"payments","role":"root","owner":"x"}`))
	s.Require().Equal(http.StatusBadRequest, resp.StatusCode)
	entries := s.audit()
	s.Require().Len(entries, 1)
	s.Equal("create", entries[0].ContextMap()["action"])
	s.Equal("invalid", entries[0].ContextMap()["outcome"])
}

func (s *AuditSuite) TestRevokeUnknownIsAudited() {
	s.setup()
	resp, _ := s.request(http.MethodDelete, "/admin/keys/00000000-0000-7000-8000-000000000099", "")
	s.Require().Equal(http.StatusNotFound, resp.StatusCode)
	entries := s.audit()
	s.Require().Len(entries, 1)
	s.Equal("revoke", entries[0].ContextMap()["action"])
	s.Equal("not_found", entries[0].ContextMap()["outcome"])
}

func (s *AuditSuite) TestSystemGrantRefusedByDefault() {
	s.setup()
	resp, b := s.request(http.MethodPost, admin.KeysPath, withExpiry(`{"namespace":"temporal-system","role":"admin","owner":"x"}`))
	s.Require().Equal(http.StatusForbidden, resp.StatusCode, string(b))
	s.Contains(string(b), "ADMIN_ALLOW_SYSTEM_GRANTS")
	s.NotContains(string(b), `"jwt"`)

	rows, err := s.registry.List(context.Background(), admin.ListFilter{Limit: 10})
	s.Require().NoError(err)
	s.Empty(rows, "a refused grant must not persist a key")

	entries := s.audit()
	s.Require().Len(entries, 1)
	f := entries[0].ContextMap()
	s.Equal("create", f["action"])
	s.Equal("denied", f["outcome"])
	s.Equal("temporal-system", f["namespace"])
}

func (s *AuditSuite) TestSystemGrantAllowedWhenEnabled() {
	s.setup(admin.WithSystemGrants(true))
	resp, b := s.request(http.MethodPost, admin.KeysPath, withExpiry(`{"namespace":"temporal-system","role":"admin","owner":"x"}`))
	s.Require().Equal(http.StatusCreated, resp.StatusCode, string(b))
}

func (s *AuditSuite) TestOperationsDeclareBearerSecurity() {
	s.setup()
	ks := keys.New(keys.WithStore(&memKeyStore{}), keys.WithGenerateOptions(keys.WithRSABits(2048)))
	s.Require().NoError(ks.Init(context.Background()))
	h := admin.NewKeys(newMemRegistry(time.Now), keys.NewSigner(keys.WithKeys(ks)))
	_, a := newGuardedAPI(admin.NewGuard(), h.Register)
	want := []map[string][]string{{admin.SecurityScheme: {}}}
	for path, item := range a.OpenAPI().Paths {
		for _, op := range []*huma.Operation{item.Get, item.Post, item.Put, item.Patch, item.Delete} {
			if op == nil || path == "/admin/healthz" || op.OperationID == "guarded-probe" {
				continue
			}
			s.Equalf(want, op.Security, "%s %s must declare the admin bearer scheme", op.Method, path)
		}
	}
}

func (s *AuditSuite) TestNilLoggerPanics() {
	s.Panics(func() { admin.WithLogger(nil) })
}

// withExpiry adds a near-future expires_at to a create body; the handler runs
// on the wall clock here, and every key must carry one.
func withExpiry(body string) string {
	exp := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	return strings.TrimSuffix(body, "}") + `,"expires_at":"` + exp + `"}`
}
