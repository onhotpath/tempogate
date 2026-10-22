package api_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/stretchr/testify/require"
	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/onhotpath/tempogate/api"
	"github.com/onhotpath/tempogate/keys"
)

// TestFxMountsMetricsOutsideTheAdminGuard proves api.Fx mounts the
// metrics_handler at GET /metrics on the admin surface only, outside the
// admin middleware (a scraper carries no admin token) but inside the
// listener-wide security headers, and that readiness logs probe failures
// through the graph's logger.
func TestFxMountsMetricsOutsideTheAdminGuard(t *testing.T) {
	deny := func(a huma.API) {
		a.UseMiddleware(func(ctx huma.Context, _ func(huma.Context)) {
			_ = huma.WriteErr(a, ctx, http.StatusTeapot, "guarded")
		})
	}
	metrics := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "tempogate_build_info 1\n")
	})
	core, logs := observer.New(zapcore.WarnLevel)
	failing := probeFunc(func(context.Context) error { return errors.New("disk gone") })

	var (
		servers   *api.Servers
		readiness *api.Readiness
	)
	fxtest.New(t,
		api.Fx(),
		fx.Provide(
			func() *keys.Keys { return keys.New(keys.WithStore(&memKeyStore{})) },
			func() api.StoreProbe { return failing },
			fx.Annotate(func() http.Handler { return metrics }, fx.ResultTags(`name:"metrics_handler"`)),
		),
		fx.Supply(
			zap.New(core),
			fx.Annotate("http://127.0.0.1:8000", fx.ResultTags(`name:"oidc_issuer"`)),
			fx.Annotate("", fx.ResultTags(`name:"oidc_base_path"`)),
			fx.Annotate(false, fx.ResultTags(`name:"api_docs_enabled"`)),
			fx.Annotate(deny, fx.ResultTags(`group:"admin_middlewares"`)),
		),
		fx.Populate(&servers, &readiness),
	).RequireStart().RequireStop()

	admin := httptest.NewServer(servers.Admin.Handler)
	defer admin.Close()
	resp, err := http.Get(admin.URL + "/metrics")
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, string(body), "tempogate_build_info")
	require.Equal(t, "DENY", resp.Header.Get("X-Frame-Options"))

	public := httptest.NewServer(servers.Public.Handler)
	defer public.Close()
	code, _ := get(t, public.URL+"/metrics")
	require.Equal(t, http.StatusNotFound, code, "/metrics is never on the public listener")

	readiness.Mark()
	require.Error(t, readiness.Check(context.Background()))
	require.Equal(t, 1, logs.FilterMessage("readiness: state store probe failed").Len())
}
