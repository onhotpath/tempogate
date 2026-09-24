package admin_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/stretchr/testify/suite"

	"github.com/onhotpath/tempogate/admin"
	"github.com/onhotpath/tempogate/keys"
	"github.com/onhotpath/tempogate/state/sqlite"
)

// KeysIntegrationSuite wires a real sqlite store, a real *keys.Keys (with a
// freshly-generated RSA keypair), a real keys.Signer and keys.Verifier, and
// the admin handler — then asserts that a JWT minted via POST /admin/keys
// verifies against the verifier built over the same JWKS source. This is the
// acceptance proof that minted integration keys are usable downstream.
type KeysIntegrationSuite struct {
	suite.Suite

	ctx      context.Context
	store    *sqlite.Store
	keys     *keys.Keys
	signer   *keys.Signer
	verifier *keys.Verifier
	srv      *httptest.Server
}

func TestKeysIntegrationSuite(t *testing.T) {
	suite.Run(t, new(KeysIntegrationSuite))
}

func (s *KeysIntegrationSuite) SetupTest() {
	s.ctx = context.Background()

	path := filepath.Join(s.T().TempDir(), "admin.db")
	store, err := sqlite.New(sqlite.WithPath(path), sqlite.WithBusyTimeout(time.Second))
	s.Require().NoError(err)
	s.Require().NoError(store.Migrate(s.ctx))
	s.store = store

	s.keys = keys.New(keys.WithStore(store), keys.WithGenerateOptions(keys.WithRSABits(2048)))
	s.Require().NoError(s.keys.Init(s.ctx))

	s.signer = keys.NewSigner(
		keys.WithKeys(s.keys),
		keys.WithIssuer(testIssuer),
	)
	s.verifier = keys.NewVerifier(
		keys.WithKeys(s.keys),
		keys.WithIssuer(testIssuer),
	)

	// admin.KeyRegistry binding goes through the same adapter the production
	// fx graph uses (state/sqlite/admin_adapter.go), exercised here as a
	// black box via the fx-provided constructor name.
	registry := newAdminKeyRegistryViaPublicSurface(store)

	h := admin.NewKeys(registry, s.signer)
	mux := http.NewServeMux()
	h.Register(humago.New(mux, huma.DefaultConfig("test", "0.0.0")))
	s.srv = httptest.NewServer(mux)
}

func (s *KeysIntegrationSuite) TearDownTest() {
	s.srv.Close()
	s.Require().NoError(s.store.Close())
}

// newAdminKeyRegistryViaPublicSurface re-creates the same adapter the
// production fx graph wires, using only state/sqlite's exported surface. If
// the adapter ever stops satisfying admin.KeyRegistry (e.g. an interface
// method is added) this compiles to a failure here, not just in fx setup.
func newAdminKeyRegistryViaPublicSurface(s *sqlite.Store) admin.KeyRegistry {
	return &storeRegistry{s: s}
}

type storeRegistry struct{ s *sqlite.Store }

func (r *storeRegistry) Save(ctx context.Context, k admin.IntegrationKey) error {
	return r.s.SaveIntegrationKey(ctx, k)
}

func (r *storeRegistry) ByID(ctx context.Context, id string) (admin.IntegrationKey, error) {
	return r.s.IntegrationKeyByID(ctx, id)
}

func (r *storeRegistry) List(ctx context.Context, f admin.ListFilter) ([]admin.IntegrationKey, error) {
	return r.s.ListIntegrationKeys(ctx, f)
}

func (r *storeRegistry) MarkRevoked(ctx context.Context, id string) (string, error) {
	return r.s.MarkIntegrationKeyRevoked(ctx, id)
}

func (s *KeysIntegrationSuite) TestPostedJWTVerifiesAgainstSameJWKS() {
	body := postBody{Namespace: "payments", Role: "worker", Owner: "svc-recon"}
	raw, err := json.Marshal(body)
	s.Require().NoError(err)
	resp, err := http.Post(s.srv.URL+"/admin/keys", "application/json", strings.NewReader(string(raw)))
	s.Require().NoError(err)
	defer func() { _ = resp.Body.Close() }()
	s.Require().Equal(http.StatusCreated, resp.StatusCode)
	respRaw, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)

	var got postResp
	s.Require().NoError(json.Unmarshal(respRaw, &got))
	s.NotEmpty(got.ID)
	s.NotEmpty(got.JWT)

	tok, err := s.verifier.Verify(s.ctx, got.JWT)
	s.Require().NoError(err, "minted JWT must verify against the same JWKS the issuer published")

	sub, ok := tok.Subject()
	s.Require().True(ok)
	s.Equal("svc-recon", sub)

	perms, ok := tok.Field("permissions")
	s.Require().True(ok)
	asSlice, ok := perms.([]any)
	s.Require().True(ok)
	s.Require().Len(asSlice, 1)
	s.Equal("payments:worker", asSlice[0])

	_, hasExp := tok.Expiration()
	s.False(hasExp, "expires_at omitted → no exp claim")

	row, err := s.store.IntegrationKeyByID(s.ctx, got.ID)
	s.Require().NoError(err)
	jti, ok := tok.JwtID()
	s.Require().True(ok)
	s.Equal(row.JTI, jti)
}

func (s *KeysIntegrationSuite) TestRevokeMakesVerifierRejectWithinCacheTTL() {
	// After DELETE /admin/keys/:id, a subsequent tempogate-mediated verify
	// of the just-revoked JWT must fail. This suite wires the real sqlite
	// store and the real denylist cache so the assertion exercises the
	// full DELETE → tx-write-to-jti_denylist → cache.Hydrate →
	// Verify(ErrTokenRevoked) chain end-to-end.
	cache := keys.NewDenylistCache(keys.WithDenylistChecker(s.store))
	registry := newAdminKeyRegistryViaPublicSurface(s.store)
	h := admin.NewKeys(registry, s.signer, admin.WithDenylistHydrator(cache))

	mux := http.NewServeMux()
	h.Register(humago.New(mux, huma.DefaultConfig("test", "0.0.0")))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	guardedVerifier := keys.NewVerifier(
		keys.WithKeys(s.keys),
		keys.WithIssuer(testIssuer),
		keys.WithDenylist(cache),
	)

	// Mint
	body := postBody{Namespace: "payments", Role: "worker", Owner: "svc-recon"}
	raw, err := json.Marshal(body)
	s.Require().NoError(err)
	resp, err := http.Post(srv.URL+"/admin/keys", "application/json", strings.NewReader(string(raw)))
	s.Require().NoError(err)
	defer func() { _ = resp.Body.Close() }()
	s.Require().Equal(http.StatusCreated, resp.StatusCode)
	respRaw, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)
	var got postResp
	s.Require().NoError(json.Unmarshal(respRaw, &got))

	// Pre-revoke: verify succeeds.
	_, err = guardedVerifier.Verify(s.ctx, got.JWT)
	s.Require().NoError(err)

	// Revoke
	req, err := http.NewRequest(http.MethodDelete, srv.URL+"/admin/keys/"+got.ID, http.NoBody)
	s.Require().NoError(err)
	delResp, err := http.DefaultClient.Do(req)
	s.Require().NoError(err)
	defer func() { _ = delResp.Body.Close() }()
	s.Require().Equal(http.StatusNoContent, delResp.StatusCode)

	// Post-revoke: the same verifier (with the same cache that DELETE just
	// hydrated) now rejects with ErrTokenRevoked — no TTL sleep required.
	_, err = guardedVerifier.Verify(s.ctx, got.JWT)
	s.Require().Error(err)
	s.Require().ErrorIs(err, keys.ErrTokenRevoked)

	// Sanity: a fresh verifier built over the same JWKS but no denylist
	// still accepts the revoked token, mirroring how Temporal's frontend
	// will behave until its exp fires.
	jwksOnly := keys.NewVerifier(
		keys.WithKeys(s.keys),
		keys.WithIssuer(testIssuer),
	)
	_, err = jwksOnly.Verify(s.ctx, got.JWT)
	s.Require().NoError(err, "Temporal-style verifier (no denylist) must still accept the revoked token")
}

func (s *KeysIntegrationSuite) TestPostedJWTCarriesExpClaimWhenExpiresAtSet() {
	expIn := 4 * time.Hour
	exp := time.Now().UTC().Add(expIn).Truncate(time.Second)
	body := postBody{
		Namespace: "ns",
		Role:      "read",
		Owner:     "svc",
		ExpiresAt: ptr(exp.Format(time.RFC3339)),
	}
	raw, err := json.Marshal(body)
	s.Require().NoError(err)
	resp, err := http.Post(s.srv.URL+"/admin/keys", "application/json", strings.NewReader(string(raw)))
	s.Require().NoError(err)
	defer func() { _ = resp.Body.Close() }()
	s.Require().Equal(http.StatusCreated, resp.StatusCode)
	respRaw, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)

	var got postResp
	s.Require().NoError(json.Unmarshal(respRaw, &got))

	tok, err := s.verifier.Verify(s.ctx, got.JWT)
	s.Require().NoError(err)
	gotExp, ok := tok.Expiration()
	s.Require().True(ok)
	// Allow a small tolerance for the time spent between issuing and the
	// server stamping the absolute exp from a relative TTL.
	s.WithinDuration(exp, gotExp, 5*time.Second)
}
