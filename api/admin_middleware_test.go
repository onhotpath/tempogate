package api_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/stretchr/testify/require"
	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"

	"github.com/onhotpath/tempogate/api"
	"github.com/onhotpath/tempogate/keys"
)

// TestAdminMiddlewareWrapsRegistrarsButNotHealthz pins the ordering contract
// the admin guard relies on: middleware contributed via WithAdminMiddleware
// wraps every admin registrar's routes, and never the liveness probe.
func TestAdminMiddlewareWrapsRegistrarsButNotHealthz(t *testing.T) {
	deny := func(a huma.API) {
		a.UseMiddleware(func(ctx huma.Context, _ func(huma.Context)) {
			_ = huma.WriteErr(a, ctx, http.StatusTeapot, "guarded")
		})
	}
	probe := func(a huma.API) {
		huma.Register(a, huma.Operation{
			OperationID: "admin-probe",
			Method:      http.MethodGet,
			Path:        "/admin/probe",
		}, func(_ context.Context, _ *struct{}) (*struct{}, error) { return &struct{}{}, nil })
	}
	// Registrar listed before the middleware on purpose: the order options
	// are passed in must not decide what gets guarded.
	servers := api.New(api.NewReadiness(), api.WithAdminRegistrar(probe), api.WithAdminMiddleware(deny))
	srv := httptest.NewServer(servers.Admin.Handler)
	defer srv.Close()

	code, _ := get(t, srv.URL+"/admin/healthz")
	require.Equal(t, http.StatusOK, code)
	code, _ = get(t, srv.URL+"/admin/probe")
	require.Equal(t, http.StatusTeapot, code)
}

// TestFxAppliesAdminMiddlewareGroup proves api.Fx feeds the
// "admin_middlewares" group into the admin Surface: the admin package's guard
// reaches the served routes only through this wiring.
func TestFxAppliesAdminMiddlewareGroup(t *testing.T) {
	deny := func(a huma.API) {
		a.UseMiddleware(func(ctx huma.Context, _ func(huma.Context)) {
			_ = huma.WriteErr(a, ctx, http.StatusTeapot, "guarded")
		})
	}
	probe := func(a huma.API) {
		huma.Register(a, huma.Operation{
			OperationID: "admin-probe",
			Method:      http.MethodGet,
			Path:        "/admin/probe",
		}, func(_ context.Context, _ *struct{}) (*struct{}, error) { return &struct{}{}, nil })
	}
	var servers *api.Servers
	fxtest.New(t,
		api.Fx(),
		fx.Provide(func() *keys.Keys { return keys.New(keys.WithStore(&memKeyStore{})) }),
		fx.Supply(
			fx.Annotate("http://127.0.0.1:8000", fx.ResultTags(`name:"oidc_issuer"`)),
			fx.Annotate("", fx.ResultTags(`name:"oidc_base_path"`)),
			fx.Annotate(false, fx.ResultTags(`name:"api_docs_enabled"`)),
			fx.Annotate(probe, fx.ResultTags(`group:"admin_registrars"`)),
			fx.Annotate(deny, fx.ResultTags(`group:"admin_middlewares"`)),
		),
		fx.Populate(&servers),
	).RequireStart().RequireStop()

	srv := httptest.NewServer(servers.Admin.Handler)
	defer srv.Close()
	code, _ := get(t, srv.URL+"/admin/probe")
	require.Equal(t, http.StatusTeapot, code)
	code, _ = get(t, srv.URL+"/admin/healthz")
	require.Equal(t, http.StatusOK, code)
}
