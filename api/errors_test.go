package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/onhotpath/tempogate/api"
	"github.com/onhotpath/tempogate/api/requestid"
)

// leakyDetail stands in for a storage failure: the raw driver text and the
// on-disk path are exactly what must never reach an anonymous client.
const leakyDetail = "sqlite: SQL logic error: no such table: auth_requests (/var/lib/tempogate/state.db)"

type problem struct {
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

// gatewayError is a 5xx StatusError that is not a huma.ErrorModel, the shape a
// handler-defined error type takes.
type gatewayError struct{}

func (gatewayError) Error() string  { return leakyDetail }
func (gatewayError) GetStatus() int { return http.StatusBadGateway }

func registerFailing(path string, err error) func(huma.API) {
	return func(a huma.API) {
		huma.Register(a, huma.Operation{
			OperationID: "fail" + path,
			Method:      http.MethodGet,
			Path:        path,
		}, func(context.Context, *struct{}) (*struct{}, error) {
			return nil, err
		})
	}
}

func getProblem(t *testing.T, h http.Handler, path string) (*httptest.ResponseRecorder, problem) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, http.NoBody))
	var p problem
	require.NoErrorf(t, json.Unmarshal(rec.Body.Bytes(), &p), "body: %s", rec.Body.String())
	return rec, p
}

func TestServerErrorsAreSanitizedAndLogged(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		err    error
		status int
	}{
		{"plain handler error", errors.New(leakyDetail), http.StatusInternalServerError},
		{"explicit 500 with cause", huma.Error500InternalServerError("jwks unavailable", errors.New(leakyDetail)), http.StatusInternalServerError},
		{"503 with cause", huma.Error503ServiceUnavailable(leakyDetail), http.StatusServiceUnavailable},
		{"custom status error", gatewayError{}, http.StatusBadGateway},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			core, logs := observer.New(zapcore.DebugLevel)
			srv := api.New(api.NewReadiness(),
				api.WithLogger(zap.New(core)),
				api.WithRegistrar(registerFailing("/boom", tc.err)),
				api.WithAdminRegistrar(registerFailing("/admin/boom", tc.err)),
			)

			for _, h := range []struct {
				handler http.Handler
				path    string
			}{{srv.Public.Handler, "/boom"}, {srv.Admin.Handler, "/admin/boom"}} {
				rec, p := getProblem(t, h.handler, h.path)
				reqID := rec.Header().Get(requestid.Header)
				require.NotEmpty(t, reqID, "every response carries a request id")

				assert.Equal(t, tc.status, rec.Code)
				assert.Equal(t, tc.status, p.Status)
				assert.NotContains(t, rec.Body.String(), "sqlite")
				assert.NotContains(t, rec.Body.String(), "no such table")
				assert.NotContains(t, rec.Body.String(), "/var/lib/tempogate")
				assert.Empty(t, p.Errors)
				assert.Contains(t, p.Detail, reqID, "the generic body names the request id so operators can find the log line")

				entries := logs.FilterField(zap.String("request_id", reqID)).All()
				require.Len(t, entries, 1, "one error line per failed request")
				e := entries[0]
				assert.Equal(t, zapcore.ErrorLevel, e.Level)
				assert.Contains(t, e.ContextMap()["error"], "no such table", "the detail is kept server-side")
				assert.Equal(t, h.path, e.ContextMap()["path"])
				assert.EqualValues(t, tc.status, e.ContextMap()["status"])
			}
		})
	}
}

// oauthGatewayError is a 5xx whose body was written for the client.
type oauthGatewayError struct {
	Code string `json:"error"`
}

func (oauthGatewayError) Error() string  { return "upstream_error: " + leakyDetail }
func (oauthGatewayError) GetStatus() int { return http.StatusBadGateway }
func (oauthGatewayError) ClientSafe()    {}

// TestClientSafeServerErrorKeepsItsBody pins the opt-out: a 5xx type that
// declares its body client-safe (the OAuth error shape) is not rewritten, but
// is still logged under the request id.
func TestClientSafeServerErrorKeepsItsBody(t *testing.T) {
	t.Parallel()
	core, logs := observer.New(zapcore.DebugLevel)
	srv := api.New(api.NewReadiness(),
		api.WithLogger(zap.New(core)),
		api.WithRegistrar(registerFailing("/upstream", oauthGatewayError{Code: "upstream_error"})),
	)

	rec := httptest.NewRecorder()
	srv.Public.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/upstream", http.NoBody))
	assert.Equal(t, http.StatusBadGateway, rec.Code)
	assert.JSONEq(t, `{"error":"upstream_error"}`, rec.Body.String())
	reqID := rec.Header().Get(requestid.Header)
	require.NotEmpty(t, reqID)
	assert.Len(t, logs.FilterField(zap.String("request_id", reqID)).All(), 1)
}

// TestClientErrorsAreUntouched pins that the sanitizer only rewrites 5xx:
// 4xx bodies are written for the caller and must keep their detail.
func TestClientErrorsAreUntouched(t *testing.T) {
	t.Parallel()
	core, logs := observer.New(zapcore.DebugLevel)
	srv := api.New(api.NewReadiness(),
		api.WithLogger(zap.New(core)),
		api.WithRegistrar(registerFailing("/bad", huma.Error400BadRequest("cursor is not a valid id"))),
	)

	rec, p := getProblem(t, srv.Public.Handler, "/bad")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "cursor is not a valid id", p.Detail)
	assert.Zero(t, logs.Len(), "client errors are not logged as server failures")
}

func TestRequestIDsAreUniquePerRequest(t *testing.T) {
	t.Parallel()
	srv := api.New(api.NewReadiness())
	seen := map[string]bool{}
	for range 5 {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/healthz", http.NoBody)
		// A client-supplied id must not be echoed: it would let callers
		// forge log correlation (and inject into log lines).
		req.Header.Set(requestid.Header, "forged")
		srv.Public.Handler.ServeHTTP(rec, req)
		id := rec.Header().Get(requestid.Header)
		require.NotEmpty(t, id)
		assert.NotEqual(t, "forged", id)
		assert.False(t, seen[id], "request id %q reused", id)
		seen[id] = true
	}
}
