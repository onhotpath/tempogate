package admin_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/onhotpath/tempogate/admin"
	"github.com/onhotpath/tempogate/keys"
	"github.com/onhotpath/tempogate/state/sqlite"
)

type signingKeyResp struct {
	Kid         string  `json:"kid"`
	Alg         string  `json:"alg"`
	CreatedAt   string  `json:"created_at"`
	RetiredAt   *string `json:"retired_at,omitempty"`
	Active      bool    `json:"active"`
	ActivatesAt *string `json:"activates_at,omitempty"`
}

type signingKeyList struct {
	Items []signingKeyResp `json:"items"`
}

// SigningKeysSuite drives the signing-key admin routes behind the guard over
// a real sqlite store, so retirement goes through the same SQL the CLI uses.
type SigningKeysSuite struct {
	suite.Suite

	ctx   context.Context
	store *sqlite.Store
	keys  *keys.Keys
	now   time.Time
	mu    sync.Mutex
	logs  *observer.ObservedLogs
	srv   *httptest.Server
}

func TestSigningKeysSuite(t *testing.T) {
	suite.Run(t, new(SigningKeysSuite))
}

func (s *SigningKeysSuite) SetupTest() {
	s.ctx = context.Background()
	s.now = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	store, err := sqlite.New(sqlite.WithPath(filepath.Join(s.T().TempDir(), "sk.db")), sqlite.WithBusyTimeout(time.Second))
	s.Require().NoError(err)
	s.Require().NoError(store.Migrate(s.ctx))
	s.store = store
	s.T().Cleanup(func() { _ = store.Close() })

	s.keys = s.newKeys()
	s.Require().NoError(s.keys.Init(s.ctx))

	core, logs := observer.New(zapcore.DebugLevel)
	s.logs = logs
	h := admin.NewSigningKeys(s.keys, admin.WithSigningKeysLogger(zap.New(core)))
	g := admin.NewGuard(
		admin.WithTokenDigests(mustDigests(s.T(), digestHex(guardToken))),
		admin.WithAllowedHosts([]string{"127.0.0.1"}),
	)
	mux, _ := newGuardedAPI(g, h.Register)
	s.srv = httptest.NewServer(mux)
	s.T().Cleanup(s.srv.Close)
}

// signingKeysPublishDelay is KEYS_PUBLISH_DELAY for the suite.
const signingKeysPublishDelay = 5 * time.Minute

// advance steps the suite clock forward, e.g. past the publish delay.
func (s *SigningKeysSuite) advance(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = s.now.Add(d)
}

func (s *SigningKeysSuite) clock() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = s.now.Add(time.Second)
	return s.now
}

// newKeys builds a *keys.Keys over the suite's store; a second one stands in
// for `tempogate keys` running in another process.
func (s *SigningKeysSuite) newKeys() *keys.Keys {
	return keys.New(
		keys.WithStore(s.store),
		keys.WithClock(s.clock),
		keys.WithRetirementGrace(time.Hour),
		keys.WithPublishDelay(signingKeysPublishDelay),
		keys.WithGenerateOptions(keys.WithRSABits(2048)),
	)
}

func (s *SigningKeysSuite) do(method, path string) (int, []byte) {
	req, err := http.NewRequest(method, s.srv.URL+path, http.NoBody)
	s.Require().NoError(err)
	resp, err := authedClient.Do(req)
	s.Require().NoError(err)
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)
	return resp.StatusCode, b
}

func (s *SigningKeysSuite) list() []signingKeyResp {
	status, b := s.do(http.MethodGet, admin.SigningKeysPath)
	s.Require().Equal(http.StatusOK, status, string(b))
	var out signingKeyList
	s.Require().NoError(json.Unmarshal(b, &out))
	return out.Items
}

func (s *SigningKeysSuite) retire(kid string) (int, []byte) {
	return s.do(http.MethodPost, strings.Replace(admin.SigningKeyRetirePath, "{kid}", kid, 1))
}

func (s *SigningKeysSuite) latestKid() string {
	kp, err := s.keys.Latest()
	s.Require().NoError(err)
	return kp.Kid
}

func (s *SigningKeysSuite) audit() []map[string]any {
	var out []map[string]any
	for _, e := range s.logs.FilterMessage("admin audit").All() {
		out = append(out, e.ContextMap())
	}
	return out
}

func (s *SigningKeysSuite) TestListShowsTheActiveKey() {
	items := s.list()
	s.Require().Len(items, 1)
	s.Equal(s.latestKid(), items[0].Kid)
	s.Equal(keys.AlgRS256, items[0].Alg)
	s.NotEmpty(items[0].CreatedAt)
	s.Nil(items[0].RetiredAt)
	s.True(items[0].Active)
}

func (s *SigningKeysSuite) TestRetireRefusesTheOnlyActiveKey() {
	kid := s.latestKid()
	status, b := s.retire(kid)
	s.Equal(http.StatusConflict, status, string(b))
	s.Contains(string(b), "keys generate", "the refusal tells the operator how to proceed")
	s.Equal(kid, s.latestKid())

	entries := s.audit()
	s.Require().Len(entries, 1)
	s.Equal("retire_signing_key", entries[0]["action"])
	s.Equal("conflict", entries[0]["outcome"])
	s.Equal(kid, entries[0]["kid"])
}

func (s *SigningKeysSuite) TestRetireUnknownKidIs404() {
	status, b := s.retire("no-such-kid")
	s.Equal(http.StatusNotFound, status, string(b))
	entries := s.audit()
	s.Require().Len(entries, 1)
	s.Equal("not_found", entries[0]["outcome"])
}

func (s *SigningKeysSuite) TestRotateThenRetireWithoutRestart() {
	old := s.latestKid()

	// `tempogate keys generate --force` from another process.
	rotated, err := s.newKeys().Generate(s.ctx, true)
	s.Require().NoError(err)

	items := s.list()
	s.Require().Len(items, 2, "the list reads through to the store, so a key generated elsewhere shows up")
	s.Equal(old, items[0].Kid)
	s.True(items[0].Active, "the old key keeps signing while the new one is pending")
	s.Nil(items[0].ActivatesAt)
	s.Equal(rotated.Kid, items[1].Kid)
	s.False(items[1].Active)
	s.Require().NotNil(items[1].ActivatesAt, "a pending key shows when it starts signing")
	activates, err := time.Parse(time.RFC3339, *items[1].ActivatesAt)
	s.Require().NoError(err)
	s.True(activates.Equal(rotated.CreatedAt.Add(signingKeysPublishDelay)))

	status, b := s.retire(old)
	s.Require().Equal(http.StatusConflict, status, "retiring the signer before its replacement is published: %s", b)
	s.Contains(string(b), rotated.Kid)
	s.Contains(string(b), "force=true")
	s.Equal(old, s.latestKid())

	s.advance(signingKeysPublishDelay)
	items = s.list()
	s.False(items[0].Active)
	s.True(items[1].Active, "the new key signs once its publish delay has passed")
	s.Nil(items[1].ActivatesAt)

	status, b = s.retire(old)
	s.Require().Equal(http.StatusOK, status, string(b))
	var got signingKeyResp
	s.Require().NoError(json.Unmarshal(b, &got))
	s.Equal(old, got.Kid)
	s.Require().NotNil(got.RetiredAt)
	s.False(got.Active)

	s.Equal(rotated.Kid, s.latestKid(), "the in-process signer moves to the new key right after the retire")
	published := s.keys.Published()
	s.Len(published, 2, "the retired key stays published during its grace")

	status, b = s.retire(old)
	s.Require().Equal(http.StatusOK, status, "retire is idempotent: %s", b)
	var again signingKeyResp
	s.Require().NoError(json.Unmarshal(b, &again))
	s.Equal(*got.RetiredAt, *again.RetiredAt)

	status, b = s.retire(rotated.Kid)
	s.Equal(http.StatusConflict, status, "the remaining key is now the only active one: %s", b)

	entries := s.audit()
	s.Require().Len(entries, 4)
	s.Equal("replacement_pending", entries[0]["outcome"])
	s.Equal("success", entries[1]["outcome"])
	s.Equal(old, entries[1]["kid"])
	s.Equal(digestHex(guardToken)[:8], entries[1]["caller"])
	s.NotEmpty(entries[1]["remote_addr"])
}

func (s *SigningKeysSuite) TestForceRetiresTheSignerDuringThePublishDelay() {
	old := s.latestKid()
	rotated, err := s.newKeys().Generate(s.ctx, true)
	s.Require().NoError(err)

	status, b := s.do(http.MethodPost, strings.Replace(admin.SigningKeyRetirePath, "{kid}", old, 1)+"?force=true")
	s.Require().Equal(http.StatusOK, status, string(b))
	s.Equal(rotated.Kid, s.latestKid(), "a forced retire hands signing to the pending key at once")

	entries := s.audit()
	s.Require().Len(entries, 1)
	s.Equal("success", entries[0]["outcome"])
	s.Equal(true, entries[0]["force"])
}

func (s *SigningKeysSuite) TestRoutesRequireTheAdminToken() {
	for _, path := range []string{admin.SigningKeysPath, strings.Replace(admin.SigningKeyRetirePath, "{kid}", "x", 1)} {
		method := http.MethodGet
		if path != admin.SigningKeysPath {
			method = http.MethodPost
		}
		req, err := http.NewRequest(method, s.srv.URL+path, http.NoBody)
		s.Require().NoError(err)
		resp, err := http.DefaultClient.Do(req)
		s.Require().NoError(err)
		s.Require().NoError(resp.Body.Close())
		s.Equal(http.StatusUnauthorized, resp.StatusCode, path)
	}
}

// failingKeyring makes every operation fail with a store error so the 500
// mapping is covered.
type failingKeyring struct{ err error }

func (f failingKeyring) Statuses(context.Context) ([]keys.KeypairStatus, error) { return nil, f.err }

func (f failingKeyring) Retire(context.Context, string, ...keys.RetireOption) (keys.Keypair, error) {
	return keys.Keypair{}, f.err
}

func (s *SigningKeysSuite) TestStoreErrorsAre500() {
	h := admin.NewSigningKeys(failingKeyring{err: errors.New("disk on fire")})
	g := admin.NewGuard(
		admin.WithTokenDigests(mustDigests(s.T(), digestHex(guardToken))),
		admin.WithAllowedHosts([]string{"127.0.0.1"}),
	)
	mux, _ := newGuardedAPI(g, h.Register)
	s.srv = httptest.NewServer(mux)
	s.T().Cleanup(s.srv.Close)

	status, _ := s.do(http.MethodGet, admin.SigningKeysPath)
	s.Equal(http.StatusInternalServerError, status)
	status, _ = s.retire("kid")
	s.Equal(http.StatusInternalServerError, status)
}

func (s *SigningKeysSuite) TestConstructorsRejectNil() {
	s.Panics(func() { admin.NewSigningKeys(nil) })
	s.Panics(func() { admin.WithSigningKeysLogger(nil) })
}
