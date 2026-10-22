package api_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"

	"github.com/onhotpath/tempogate/api"
	"github.com/onhotpath/tempogate/config"
)

// TestFxWiresAPIDocsEnabled follows API_DOCS_ENABLED from the environment
// through config.Fx into the Servers api.Fx builds.
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

			for _, h := range []http.Handler{servers.Public.Handler, servers.Admin.Handler} {
				srv := httptest.NewServer(h)
				resp, _ := do(t, srv.URL+"/openapi.json")
				srv.Close()
				assert.Equal(t, tc.want, resp.StatusCode)
			}
		})
	}
}
