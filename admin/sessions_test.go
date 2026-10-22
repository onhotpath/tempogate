package admin_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/onhotpath/tempogate/admin"
	"github.com/onhotpath/tempogate/oidc"
	"github.com/onhotpath/tempogate/state/sqlite"
)

type sessionResp struct {
	FamilyID       string `json:"family_id"`
	ClientID       string `json:"client_id"`
	Email          string `json:"email"`
	Subject        string `json:"subject"`
	Connector      string `json:"connector"`
	AuthTime       string `json:"auth_time"`
	LastRotationAt string `json:"last_rotation_at"`
	ExpiresAt      string `json:"expires_at"`
}

// SessionsSuite drives the session admin routes behind the guard over a real
// sqlite store, so list and revoke run the same SQL as `tempogate sessions`.
type SessionsSuite struct {
	suite.Suite

	ctx   context.Context
	store *sqlite.Store
	logs  *observer.ObservedLogs
	srv   *httptest.Server
}

func TestSessionsSuite(t *testing.T) {
	suite.Run(t, new(SessionsSuite))
}

func (s *SessionsSuite) SetupTest() {
	s.ctx = context.Background()
	store, err := sqlite.New(sqlite.WithPath(filepath.Join(s.T().TempDir(), "sessions.db")), sqlite.WithBusyTimeout(time.Second))
	s.Require().NoError(err)
	s.Require().NoError(store.Migrate(s.ctx))
	s.store = store
	s.T().Cleanup(func() { _ = store.Close() })

	core, logs := observer.New(zapcore.DebugLevel)
	s.logs = logs
	h := admin.NewSessions(&storeSessions{s: store}, admin.WithSessionsLogger(zap.New(core)))
	g := admin.NewGuard(
		admin.WithTokenDigests(mustDigests(s.T(), digestHex(guardToken))),
		admin.WithAllowedHosts([]string{"127.0.0.1"}),
	)
	mux, _ := newGuardedAPI(g, h.Register)
	s.srv = httptest.NewServer(mux)
	s.T().Cleanup(s.srv.Close)
}

// seed stores one live refresh token, i.e. one session, of a Google
// sign-in.
func (s *SessionsSuite) seed(token, family, subject, email string) {
	s.seedAt("google", token, family, subject, email)
}

func (s *SessionsSuite) seedAt(connectorID, token, family, subject, email string) {
	now := time.Now().UTC()
	s.Require().NoError(s.store.SaveRefresh(s.ctx, oidc.Refresh{
		Token: token, JTI: "jti-" + token, ClientID: "tempogate-cli", ConnectorID: connectorID, Subject: subject, Email: email,
		FamilyID: family, AuthTime: now.Add(-time.Hour), CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}))
}

// live reports whether token can still be refreshed.
func (s *SessionsSuite) live(token string) bool {
	_, err := s.store.ConsumeRefresh(s.ctx, token, "tempogate-cli", time.Now().UTC())
	if errors.Is(err, oidc.ErrRefreshNotFound) {
		return false
	}
	s.Require().NoError(err)
	return true
}

func (s *SessionsSuite) do(client *http.Client, method, path, body string) (int, []byte) {
	var rdr io.Reader = http.NoBody
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, s.srv.URL+path, rdr)
	s.Require().NoError(err)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	s.Require().NoError(err)
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)
	return resp.StatusCode, b
}

func (s *SessionsSuite) list(query url.Values) []sessionResp {
	path := admin.SessionsPath
	if len(query) > 0 {
		path += "?" + query.Encode()
	}
	status, b := s.do(authedClient, http.MethodGet, path, "")
	s.Require().Equal(http.StatusOK, status, string(b))
	var out struct {
		Items []sessionResp `json:"items"`
	}
	s.Require().NoError(json.Unmarshal(b, &out))
	return out.Items
}

func (s *SessionsSuite) revoke(body string) (int, []byte) {
	return s.do(authedClient, http.MethodPost, admin.SessionsRevokePath, body)
}

func (s *SessionsSuite) revoked(body string) int {
	status, b := s.revoke(body)
	s.Require().Equal(http.StatusOK, status, string(b))
	var out struct {
		Revoked int `json:"revoked"`
	}
	s.Require().NoError(json.Unmarshal(b, &out))
	return out.Revoked
}

func (s *SessionsSuite) audit() []map[string]any {
	var out []map[string]any
	for _, e := range s.logs.FilterMessage("admin audit").All() {
		out = append(out, e.ContextMap())
	}
	return out
}

func (s *SessionsSuite) TestRoutesNeedTheAdminToken() {
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, admin.SessionsPath, ""},
		{http.MethodPost, admin.SessionsRevokePath, `{"email":"alice@example.com"}`},
	} {
		status, _ := s.do(http.DefaultClient, tc.method, tc.path, tc.body)
		s.Equal(http.StatusUnauthorized, status, "%s %s", tc.method, tc.path)
	}
	s.Empty(s.audit(), "an unauthenticated request never reaches the handler")
}

func (s *SessionsSuite) TestRoutesRefuseHostsOutsideTheAllowlist() {
	s.seed("tok-a", "fam-a", "sub-a", "alice@example.com")
	req, err := http.NewRequest(http.MethodPost, s.srv.URL+admin.SessionsRevokePath, strings.NewReader(`{"email":"alice@example.com"}`))
	s.Require().NoError(err)
	req.Host = "evil.example"
	req.Header.Set("Content-Type", "application/json")
	resp, err := authedClient.Do(req)
	s.Require().NoError(err)
	_ = resp.Body.Close()
	s.Equal(http.StatusMisdirectedRequest, resp.StatusCode)
	s.True(s.live("tok-a"), "a rebinding request revokes nothing")
}

func (s *SessionsSuite) TestListShowsSessionsButNeverTokens() {
	s.seed("secret-token-a", "fam-a", "sub-a", "alice@example.com")
	s.seed("secret-token-b", "fam-b", "sub-b", "bob@example.com")

	status, raw := s.do(authedClient, http.MethodGet, admin.SessionsPath, "")
	s.Require().Equal(http.StatusOK, status)
	s.NotContains(string(raw), "secret-token", "token values never leave the store")
	s.NotContains(string(raw), "jti-", "nor do refresh-token ids")
	var generic struct {
		Items []map[string]any `json:"items"`
	}
	s.Require().NoError(json.Unmarshal(raw, &generic))
	s.Require().Len(generic.Items, 2)
	keys := make([]string, 0, len(generic.Items[0]))
	for k := range generic.Items[0] {
		keys = append(keys, k)
	}
	s.ElementsMatch([]string{"family_id", "client_id", "email", "subject", "connector", "auth_time", "last_rotation_at", "expires_at"}, keys,
		"the view is an allowlist of metadata, no token or hash field")

	items := s.list(nil)
	s.Equal("fam-a", items[0].FamilyID)
	s.Equal("tempogate-cli", items[0].ClientID)
	s.Equal("alice@example.com", items[0].Email)
	s.Equal("google:sub-a", items[0].Subject, "the subject is shown as the token's sub")
	s.Equal("google", items[0].Connector)
	for _, ts := range []string{items[0].AuthTime, items[0].LastRotationAt, items[0].ExpiresAt} {
		_, err := time.Parse(time.RFC3339, ts)
		s.NoError(err)
	}

	byEmail := s.list(url.Values{"email": {"BOB@example.com"}})
	s.Require().Len(byEmail, 1)
	s.Equal("fam-b", byEmail[0].FamilyID)

	bySubject := s.list(url.Values{"subject": {"google:sub-a"}})
	s.Require().Len(bySubject, 1)
	s.Equal("fam-a", bySubject[0].FamilyID)
	s.Empty(s.list(url.Values{"subject": {"google:SUB-A"}}), "a subject is matched exactly")
	s.Empty(s.list(url.Values{"subject": {"okta:sub-a"}}), "the same upstream sub at another connector is another person")

	s.Empty(s.audit(), "listing is read-only and not audited, like listing keys")
}

func (s *SessionsSuite) TestListIsEmptyNotNull() {
	status, raw := s.do(authedClient, http.MethodGet, admin.SessionsPath, "")
	s.Require().Equal(http.StatusOK, status)
	s.JSONEq(`{"items":[]}`, stripSchema(s.T(), raw))
}

func (s *SessionsSuite) TestRevokeByEmail() {
	s.seed("a1", "fam-a1", "sub-a", "alice@example.com")
	s.seed("a2", "fam-a2", "sub-a", "Alice@Example.com")
	s.seed("b1", "fam-b", "sub-b", "bob@example.com")

	s.Equal(2, s.revoked(`{"email":"ALICE@example.com"}`))
	s.False(s.live("a1"))
	s.False(s.live("a2"))
	s.True(s.live("b1"))

	s.Zero(s.revoked(`{"email":"alice@example.com"}`), "revoking again ends nothing new")

	entries := s.audit()
	s.Require().Len(entries, 2)
	e := entries[0]
	s.Equal("revoke_sessions", e["action"])
	s.Equal("success", e["outcome"])
	s.Equal("ALICE@example.com", e["email"])
	s.Empty(e["subject"])
	s.Empty(e["family_id"])
	s.EqualValues(2, e["revoked"])
	s.Equal(digestHex(guardToken)[:8], e["caller"])
	s.NotEmpty(e["remote_addr"])
	s.EqualValues(0, entries[1]["revoked"])
}

func (s *SessionsSuite) TestRevokeBySubject() {
	s.seed("a1", "fam-a1", "sub-a", "alice@example.com")
	s.seed("a2", "fam-a2", "sub-a", "alice-renamed@example.com")
	s.seed("b1", "fam-b", "sub-b", "bob@example.com")

	s.seedAt("okta", "o1", "fam-o", "sub-a", "alice@example.com")

	s.Equal(2, s.revoked(`{"subject":"google:sub-a"}`))
	s.False(s.live("a1"))
	s.False(s.live("a2"))
	s.True(s.live("b1"))
	s.True(s.live("o1"), "the same upstream sub at another connector is another person")

	e := s.audit()[0]
	s.Equal("google:sub-a", e["subject"])
	s.EqualValues(2, e["revoked"])
}

// TestSubjectMustBeTheTokenForm: a bare upstream sub names no connector, so
// it is refused rather than matching nothing and reporting success.
func (s *SessionsSuite) TestSubjectMustBeTheTokenForm() {
	s.seed("a1", "fam-a1", "sub-a", "alice@example.com")
	for _, sub := range []string{"sub-a", "google:", ":sub-a", "Google:sub-a"} {
		status, b := s.revoke(`{"subject":"` + sub + `"}`)
		s.Equal(http.StatusBadRequest, status, "%s: %s", sub, b)
		s.Contains(string(b), "<connector>:<upstream sub>")

		status, b = s.do(authedClient, http.MethodGet, admin.SessionsPath+"?"+url.Values{"subject": {sub}}.Encode(), "")
		s.Equal(http.StatusBadRequest, status, "%s: %s", sub, b)
	}
	s.True(s.live("a1"))
}

func (s *SessionsSuite) TestRevokeByFamily() {
	s.seed("a1", "fam-a1", "sub-a", "alice@example.com")
	s.seed("a2", "fam-a2", "sub-a", "alice@example.com")

	s.Equal(1, s.revoked(`{"family_id":"fam-a1"}`))
	s.False(s.live("a1"))
	s.True(s.live("a2"))

	s.Zero(s.revoked(`{"family_id":"fam-a1"}`), "an already revoked family is idempotent, like DELETE /admin/keys/{id}")

	e := s.audit()[0]
	s.Equal("fam-a1", e["family_id"])
	s.EqualValues(1, e["revoked"])
}

func (s *SessionsSuite) TestRevokeUnknownFamilyIsNotFound() {
	status, b := s.revoke(`{"family_id":"no-such-family"}`)
	s.Equal(http.StatusNotFound, status, string(b))
	s.Contains(string(b), "session not found")

	e := s.audit()[0]
	s.Equal("not_found", e["outcome"])
	s.Equal("no-such-family", e["family_id"])
	s.EqualValues(0, e["revoked"])
}

func (s *SessionsSuite) TestRevokeNeedsExactlyOneSelector() {
	s.seed("a1", "fam-a1", "sub-a", "alice@example.com")
	for _, body := range []string{
		`{}`,
		`{"email":""}`,
		`{"email":"alice@example.com","family_id":"fam-a1"}`,
		`{"email":"alice@example.com","subject":"sub-a"}`,
	} {
		status, b := s.revoke(body)
		s.Equal(http.StatusBadRequest, status, "%s: %s", body, b)
		s.Contains(string(b), "exactly one of email, subject or family_id")
	}
	s.True(s.live("a1"), "a refused request revokes nothing")
	for _, e := range s.audit() {
		s.Equal("invalid", e["outcome"])
	}
}

func (s *SessionsSuite) TestStoreFailuresAreServerErrors() {
	s.Require().NoError(s.store.Close())

	status, _ := s.do(authedClient, http.MethodGet, admin.SessionsPath, "")
	s.Equal(http.StatusInternalServerError, status)

	status, _ = s.revoke(`{"email":"alice@example.com"}`)
	s.Equal(http.StatusInternalServerError, status)
	s.Equal("error", s.audit()[0]["outcome"])
}

func TestNewSessionsPanicsOnNilDependencies(t *testing.T) {
	require.Panics(t, func() { admin.NewSessions(nil) })
	require.Panics(t, func() { admin.WithSessionsLogger(nil) })
}

// stripSchema drops Huma's $schema link so a body can be compared verbatim.
func stripSchema(t *testing.T, raw []byte) string {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	delete(m, "$schema")
	b, err := json.Marshal(m)
	require.NoError(t, err)
	return string(b)
}

// storeSessions mirrors state/sqlite's unexported admin.SessionStore
// adapter, the way storeRegistry mirrors the KeyRegistry one.
type storeSessions struct{ s *sqlite.Store }

func (a *storeSessions) List(ctx context.Context, f admin.SessionFilter, now time.Time) ([]admin.Session, error) {
	rows, err := a.s.ListRefreshSessions(ctx, sqlite.RefreshSessionFilter{Email: f.Email, ConnectorID: f.ConnectorID, Subject: f.Subject}, now)
	if err != nil {
		return nil, err
	}
	out := make([]admin.Session, 0, len(rows))
	for _, r := range rows {
		out = append(out, admin.Session(r))
	}
	return out, nil
}

func (a *storeSessions) RevokeFamily(ctx context.Context, familyID string, at time.Time) (int, error) {
	return a.s.RevokeRefreshFamily(ctx, familyID, at)
}

func (a *storeSessions) RevokeEmail(ctx context.Context, email string, at time.Time) (int, error) {
	return a.s.RevokeRefreshByEmail(ctx, email, at)
}

func (a *storeSessions) RevokeSubject(ctx context.Context, connectorID, subject string, at time.Time) (int, error) {
	return a.s.RevokeRefreshBySubject(ctx, connectorID, subject, at)
}
