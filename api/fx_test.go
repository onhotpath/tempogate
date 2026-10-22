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
