package api_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/onhotpath/tempogate/api"
)

const wantDefaultCSP = "default-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

// do issues a GET and returns the response with its body drained, so header
// assertions do not have to manage the body.
func do(t *testing.T, url string) (*http.Response, []byte) {
	t.Helper()
	resp, err := http.Get(url) //nolint:noctx // test-only loopback
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp, body
}

func assertAntiFramingHeaders(t *testing.T, resp *http.Response) {
	t.Helper()
	assert.Equal(t, "DENY", resp.Header.Get("X-Frame-Options"), "X-Frame-Options on %s", resp.Request.URL.Path)
	assert.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"), "X-Content-Type-Options on %s", resp.Request.URL.Path)
	assert.Equal(t, "no-referrer", resp.Header.Get("Referrer-Policy"), "Referrer-Policy on %s", resp.Request.URL.Path)
	assert.Contains(t, resp.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'", "CSP on %s", resp.Request.URL.Path)
}

func assertSecurityHeaders(t *testing.T, resp *http.Response) {
	t.Helper()
	assertAntiFramingHeaders(t, resp)
	assert.Equal(t, wantDefaultCSP, resp.Header.Get("Content-Security-Policy"), "CSP on %s", resp.Request.URL.Path)
}

// TestSecurityHeadersOnBothListeners: every response either listener
// produces, Huma operation or plain mux 404, carries the anti-framing and
// no-sniff headers. A <meta> CSP cannot express frame-ancestors, so only the
// header stops a same-site page from framing the device approval UI.
func TestSecurityHeadersOnBothListeners(t *testing.T) {
	t.Parallel()
	for _, basePath := range []string{"", "/idp"} {
		t.Run("basePath="+basePath, func(t *testing.T) {
			t.Parallel()
			publicSrv, servers, _ := servePublic(t, basePath, api.WithAdminRegistrar(adminProbe))
			adminSrv := httptest.NewServer(servers.Admin.Handler)
			t.Cleanup(adminSrv.Close)

			for _, u := range []string{
				publicSrv.URL + "/healthz",
				publicSrv.URL + "/readyz",
				publicSrv.URL + basePath + "/.well-known/openid-configuration",
				publicSrv.URL + basePath + "/.well-known/jwks.json",
				publicSrv.URL + "/no-such-route",
				publicSrv.URL + basePath + "/openapi.json",
				adminSrv.URL + "/admin/healthz",
				adminSrv.URL + "/admin/probe",
				adminSrv.URL + "/no-such-route",
			} {
				resp, _ := do(t, u)
				assertSecurityHeaders(t, resp)
			}
		})
	}
}

// TestAPIDocsDisabledByDefault: the OpenAPI document, the docs page and the
// per-type schemas are an unauthenticated map of the API, so neither
// listener serves them unless API_DOCS_ENABLED opts in.
func TestAPIDocsDisabledByDefault(t *testing.T) {
	t.Parallel()
	for _, basePath := range []string{"", "/idp"} {
		t.Run("basePath="+basePath, func(t *testing.T) {
			t.Parallel()
			publicSrv, servers, _ := servePublic(t, basePath)
			adminSrv := httptest.NewServer(servers.Admin.Handler)
			t.Cleanup(adminSrv.Close)

			for _, base := range []string{publicSrv.URL, publicSrv.URL + basePath, adminSrv.URL} {
				for _, p := range docsPaths {
					resp, _ := do(t, base+p)
					assert.Equal(t, http.StatusNotFound, resp.StatusCode, "%s%s must 404 with docs disabled", base, p)
				}
			}

			// Without a schemas route, a $schema link in a body would point
			// at a 404, so response bodies carry none.
			for _, u := range []string{
				publicSrv.URL + "/healthz",
				publicSrv.URL + basePath + "/.well-known/openid-configuration",
				adminSrv.URL + "/admin/healthz",
			} {
				_, body := do(t, u)
				assert.NotContains(t, string(body), `"$schema"`, "%s must not link a schema that is not served", u)
			}
		})
	}
}

// docsPaths are every route that describes an API: the OpenAPI documents,
// the docs page and a per-type JSON schema.
var docsPaths = []string{"/openapi.json", "/openapi.yaml", "/openapi-3.0.json", "/docs", "/schemas/HealthBody.json"}

// TestAPIDocsEnabled: with docs opted in, the public listener serves the spec
// and docs page under the OIDC base path, still under the security headers.
// Huma's docs page loads its renderer from a CDN and sets its own,
// route-specific CSP; that policy replaces the default one but keeps
// frame-ancestors 'none'.
func TestAPIDocsEnabled(t *testing.T) {
	t.Parallel()
	for _, basePath := range []string{"", "/idp"} {
		t.Run("basePath="+basePath, func(t *testing.T) {
			t.Parallel()
			publicSrv, _, _ := servePublic(t, basePath, api.WithDocs(true))
			base := publicSrv.URL + basePath

			spec, _ := do(t, base+"/openapi.json")
			assert.Equal(t, http.StatusOK, spec.StatusCode, "%s/openapi.json", base)
			assertSecurityHeaders(t, spec)

			schema, _ := do(t, base+"/schemas/HealthBody.json")
			assert.Equal(t, http.StatusOK, schema.StatusCode, "%s/schemas/HealthBody.json", base)

			docs, body := do(t, base+"/docs")
			assert.Equal(t, http.StatusOK, docs.StatusCode, "%s/docs", base)
			assertAntiFramingHeaders(t, docs)
			assert.Contains(t, docs.Header.Get("Content-Security-Policy"), "script-src https://unpkg.com/",
				"docs page keeps Huma's route-specific CSP so its renderer loads")
			assert.True(t, strings.Contains(string(body), "unpkg.com"), "sanity: docs page loads its renderer from the CDN")

			_, body = do(t, base+"/.well-known/openid-configuration")
			assert.Contains(t, string(body), `"$schema"`, "schema links come back with the schemas route")
		})
	}
}

// TestAPIDocsNeverOnAdminListener: the admin docs routes would sit outside
// the admin bearer token and Host allowlist that guard /admin/*, describing
// the admin API to anyone who can reach the port. So the admin listener never
// serves them, whatever API_DOCS_ENABLED says; `tempogate gen-oas --admin`
// emits the admin spec instead.
func TestAPIDocsNeverOnAdminListener(t *testing.T) {
	t.Parallel()
	for _, docs := range []bool{false, true} {
		t.Run(fmt.Sprintf("docs=%t", docs), func(t *testing.T) {
			t.Parallel()
			_, servers, _ := servePublic(t, "", api.WithDocs(docs), api.WithAdminRegistrar(adminProbe))
			adminSrv := httptest.NewServer(servers.Admin.Handler)
			t.Cleanup(adminSrv.Close)

			for _, p := range docsPaths {
				resp, _ := do(t, adminSrv.URL+p)
				assert.Equal(t, http.StatusNotFound, resp.StatusCode, "admin %s must 404", p)
			}
			for _, p := range []string{"/admin/healthz", "/admin/probe"} {
				_, body := do(t, adminSrv.URL+p)
				assert.NotContains(t, string(body), `"$schema"`, "admin %s must not link a schema that is not served", p)
			}
		})
	}
}

// TestPublicHealthzOmitsVersion: the public probe answers liveness only; the
// build version stays on the private admin probe and `tempogate version`.
func TestPublicHealthzOmitsVersion(t *testing.T) {
	t.Parallel()
	publicSrv, servers, _ := servePublic(t, "")
	adminSrv := httptest.NewServer(servers.Admin.Handler)
	t.Cleanup(adminSrv.Close)

	_, body := do(t, publicSrv.URL+"/healthz")
	var pub map[string]any
	require.NoError(t, json.Unmarshal(body, &pub))
	assert.Equal(t, "ok", pub["status"])
	assert.NotContains(t, pub, "version", "public /healthz must not reveal the build version")

	_, body = do(t, adminSrv.URL+"/admin/healthz")
	var adm map[string]any
	require.NoError(t, json.Unmarshal(body, &adm))
	assert.Equal(t, "ok", adm["status"])
	assert.NotEmpty(t, adm["version"], "admin /admin/healthz keeps the build version")
}
