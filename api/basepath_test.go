package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/onhotpath/tempogate/api"
	"github.com/onhotpath/tempogate/keys"
)

// newKeys builds a keypair-backed JWKS source for WithWellKnown, reusing the
// in-memory store stub from wellknown_test.go (same api_test package).
func newKeys(t *testing.T) *keys.Keys {
	t.Helper()
	k := keys.New(keys.WithStore(&memKeyStore{}), keys.WithGenerateOptions(keys.WithRSABits(2048)))
	require.NoError(t, k.Init(context.Background()))
	return k
}

// servePublic binds an httptest server to the *public* Surface, then constructs
// the API with an issuer that embeds basePath, mirroring real deployment (the
// discovery doc's issuer must equal the URL relying parties fetch it from).
// Extra Options let individual tests add registrars (e.g. an admin fixture).
func servePublic(t *testing.T, basePath string, extra ...api.Option) (*httptest.Server, *api.Servers, string) {
	t.Helper()
	srv := httptest.NewUnstartedServer(nil)
	issuer := "http://" + srv.Listener.Addr().String() + basePath
	opts := []api.Option{
		api.WithBasePath(basePath),
		api.WithWellKnown(newKeys(t), issuer),
	}
	opts = append(opts, extra...)
	res := api.New(api.NewReadiness(), opts...)
	srv.Config.Handler = res.Public.Handler
	srv.Start()
	t.Cleanup(srv.Close)
	return srv, res, issuer
}

// adminProbe is a test-only Huma registrar standing in for the real admin
// registrar: it registers a single `GET /admin/probe` so the surface-split
// tests can assert location without depending on the admin package (an
// import would cycle: admin → state/sqlite → … and api wires admin's
// registrars in production via the same Option machinery exercised here).
func adminProbe(a huma.API) {
	type out struct {
		Body struct {
			OK bool `json:"ok"`
		}
	}
	huma.Register(a, huma.Operation{
		OperationID: "admin-probe",
		Method:      http.MethodGet,
		Path:        "/admin/probe",
		Summary:     "probe",
		Tags:        []string{"admin"},
	}, func(_ context.Context, _ *struct{}) (*out, error) {
		o := &out{}
		o.Body.OK = true
		return o, nil
	})
}

// TestBasePathMode: with a non-empty base path the OIDC surface is served
// under it on the public listener, the discovery doc advertises
// issuer-relative (prefixed) endpoints, and /healthz / /readyz stay at root
// (k8s-probe-only, never path-routed).
func TestBasePathMode(t *testing.T) {
	t.Parallel()
	srv, _, issuer := servePublic(t, "/idp")

	code, body := get(t, srv.URL+"/idp/.well-known/openid-configuration")
	require.Equal(t, http.StatusOK, code)
	var doc struct {
		Issuer                string `json:"issuer"`
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
		JwksURI               string `json:"jwks_uri"`
	}
	require.NoError(t, json.Unmarshal(body, &doc))
	assert.Equal(t, issuer, doc.Issuer)
	assert.Equal(t, issuer+"/authorize", doc.AuthorizationEndpoint)
	assert.Equal(t, issuer+"/token", doc.TokenEndpoint)
	assert.Equal(t, issuer+"/.well-known/jwks.json", doc.JwksURI)

	jc, _ := get(t, srv.URL+"/idp/.well-known/jwks.json")
	assert.Equal(t, http.StatusOK, jc, "JWKS served under the prefix")

	// Health stays at root regardless of the prefix.
	hc, _ := get(t, srv.URL+"/healthz")
	assert.Equal(t, http.StatusOK, hc, "/healthz must stay at root")

	// The OIDC surface must NOT answer at root, and health must NOT move
	// under the prefix.
	rc, _ := get(t, srv.URL+"/.well-known/openid-configuration")
	assert.Equal(t, http.StatusNotFound, rc, "discovery must not be at root in base-path mode")
	ph, _ := get(t, srv.URL+"/idp/healthz")
	assert.Equal(t, http.StatusNotFound, ph, "/healthz must not move under the prefix")
}

// TestRootModeUnchanged: an empty base path is byte-identical to today —
// OIDC + health both at root on the public listener (regression guard for
// existing deployments).
func TestRootModeUnchanged(t *testing.T) {
	t.Parallel()
	srv, _, issuer := servePublic(t, "")

	code, body := get(t, srv.URL+"/.well-known/openid-configuration")
	require.Equal(t, http.StatusOK, code)
	var doc struct {
		Issuer                string `json:"issuer"`
		AuthorizationEndpoint string `json:"authorization_endpoint"`
	}
	require.NoError(t, json.Unmarshal(body, &doc))
	assert.Equal(t, issuer, doc.Issuer)
	assert.Equal(t, issuer+"/authorize", doc.AuthorizationEndpoint)

	hc, _ := get(t, srv.URL+"/healthz")
	assert.Equal(t, http.StatusOK, hc)
}

// TestAdminSurfaceIsolatedFromPublic locks the structural-isolation contract:
// a route added via WithAdminRegistrar is reachable only on the admin Surface
// and the public Surface mux has no entry for it at all. Holds in both root
// and base-path modes — the public mux being "small" is what makes 404 a
// structural property and not a middleware decision.
func TestAdminSurfaceIsolatedFromPublic(t *testing.T) {
	t.Parallel()
	for _, basePath := range []string{"", "/idp"} {
		t.Run("basePath="+basePath, func(t *testing.T) {
			t.Parallel()
			publicSrv, servers, _ := servePublic(t, basePath, api.WithAdminRegistrar(adminProbe))

			// Public listener has no admin handlers: any /admin/* request 404s.
			code, _ := get(t, publicSrv.URL+"/admin/probe")
			assert.Equal(t, http.StatusNotFound, code,
				"public listener must not expose /admin/* (no handler entry, not a middleware decision)")
			prefixed, _ := get(t, publicSrv.URL+basePath+"/admin/probe")
			assert.Equal(t, http.StatusNotFound, prefixed,
				"public listener must not expose /admin/* under the OIDC base path either")

			// Admin Surface, bound to its own httptest server, answers.
			adminSrv := httptest.NewServer(servers.Admin.Handler)
			t.Cleanup(adminSrv.Close)
			ac, _ := get(t, adminSrv.URL+"/admin/probe")
			assert.Equal(t, http.StatusOK, ac, "admin listener serves /admin/probe")

			// And the admin surface's own liveness probe.
			hc, _ := get(t, adminSrv.URL+"/admin/healthz")
			assert.Equal(t, http.StatusOK, hc, "admin listener serves /admin/healthz")
		})
	}
}
