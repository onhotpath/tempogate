package api_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/onhotpath/tempogate/api"
	"github.com/onhotpath/tempogate/api/requestid"
	"github.com/onhotpath/tempogate/config"
)

// TestFxWiresAPIDocsEnabled follows API_DOCS_ENABLED from the environment
// through config.Fx into the Servers api.Fx builds: it switches the public
// docs, and the admin listener serves none either way.
func TestFxWiresAPIDocsEnabled(t *testing.T) {
	for _, tc := range []struct {
		env  string
		want int
	}{
		{"false", http.StatusNotFound},
		{"true", http.StatusOK},
	} {
		t.Run("API_DOCS_ENABLED="+tc.env, func(t *testing.T) {
			t.Setenv("API_DOCS_ENABLED", tc.env)
			var servers *api.Servers
			app := fxtest.New(t,
				config.Fx(),
				api.Fx(),
				fx.Supply(newKeys(t)),
				fx.Populate(&servers),
			)
			app.RequireStart()
			t.Cleanup(app.RequireStop)

			for _, h := range []struct {
				name    string
				handler http.Handler
				want    int
			}{
				{"public", servers.Public.Handler, tc.want},
				{"admin", servers.Admin.Handler, http.StatusNotFound},
			} {
				srv := httptest.NewServer(h.handler)
				for _, p := range docsPaths {
					resp, _ := do(t, srv.URL+p)
					assert.Equal(t, h.want, resp.StatusCode, "%s %s", h.name, p)
				}
				srv.Close()
			}
		})
	}
}

// TestFxLogsServerErrorsToTheAppLogger proves api.Fx hands the app's zap
// logger to the 5xx sanitizer: a failing registrar contributed through the
// fx group yields a generic body, and the cause lands in the "http" logger
// under the response's request id.
func TestFxLogsServerErrorsToTheAppLogger(t *testing.T) {
	core, logs := observer.New(zapcore.DebugLevel)
	var servers *api.Servers
	app := fxtest.New(t,
		config.Fx(),
		api.Fx(),
		fx.Supply(newKeys(t), zap.New(core)),
		fx.Provide(fx.Annotate(
			func() func(huma.API) { return registerFailing("/boom", errors.New(leakyDetail)) },
			fx.ResultTags(`group:"api_registrars"`),
		)),
		fx.Populate(&servers),
	)
	app.RequireStart()
	t.Cleanup(app.RequireStop)

	rec, p := getProblem(t, servers.Public.Handler, "/boom")
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.NotContains(t, rec.Body.String(), "no such table")
	reqID := rec.Header().Get(requestid.Header)
	assert.Contains(t, p.Detail, reqID)

	entries := logs.FilterField(zap.String("request_id", reqID)).All()
	require.Len(t, entries, 1)
	assert.Equal(t, "http", entries[0].LoggerName)
	assert.Contains(t, entries[0].ContextMap()["error"], "no such table")
}
