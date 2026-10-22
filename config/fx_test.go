package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"
)

// TestFxProjectsAPIDocsEnabled: the api package reads the docs switch as the
// named bool, not the whole *Config.
func TestFxProjectsAPIDocsEnabled(t *testing.T) {
	t.Setenv("API_DOCS_ENABLED", "true")
	var got struct {
		fx.In

		DocsEnabled bool `name:"api_docs_enabled"`
	}
	app := fxtest.New(t, Fx(), fx.Populate(&got))
	app.RequireStart()
	t.Cleanup(app.RequireStop)
	assert.True(t, got.DocsEnabled)
}

// TestProjectsIssuerPlainHTTP: whether the issuer is plain http is decided
// once, here, for every consumer (the session cookie's Secure flag, serve's
// API docs check). Anything but an http scheme, an unparseable issuer
// included, counts as not plain http, the safe side for both.
func TestProjectsIssuerPlainHTTP(t *testing.T) {
	for _, tc := range []struct {
		issuer string
		want   bool
	}{
		{"http://127.0.0.1:8000", true},
		{"http://tempogate:8000/idp", true},
		{"HTTP://tempogate:8000", true},
		{" http://tempogate:8000 ", true},
		{"https://tempogate.example.com", false},
		{"https://shared.example.com/idp", false},
		{"", false},
		{"tempogate:8000", false},
		{"://nonsense", false},
	} {
		t.Run(tc.issuer, func(t *testing.T) {
			cfg := defaultConfig()
			cfg.OIDC.Issuer = tc.issuer
			var got struct {
				fx.In

				PlainHTTP bool `name:"oidc_issuer_plain_http"`
			}
			fxtest.New(t, Supply(cfg), fx.Populate(&got)).RequireStart().RequireStop()
			assert.Equal(t, tc.want, got.PlainHTTP)
		})
	}
}

// TestSupplyProjectsLikeFx guards the sub-graph seam: a graph built from an
// already-loaded *Config must see the same named values as the root graph.
func TestSupplyProjectsLikeFx(t *testing.T) {
	cfg := defaultConfig()
	cfg.State.Sqlite.Path = "/tmp/state.db"
	cfg.OIDC.Issuer = "https://tempogate.example.com/idp"

	type projected struct {
		fx.In

		SqlitePath   string `name:"sqlite_path"`
		OIDCBasePath string `name:"oidc_base_path"`
	}
	var got projected
	fxtest.New(t,
		Supply(cfg),
		fx.Invoke(func(p projected) { got = p }),
	).RequireStart().RequireStop()

	require.Equal(t, "/tmp/state.db", got.SqlitePath)
	require.Equal(t, "/idp", got.OIDCBasePath)
}

// TestProjectsKeyLifetimes guards the names the admin handler, the keypair
// aggregate and serve's reload loop inject.
func TestProjectsKeyLifetimes(t *testing.T) {
	cfg := defaultConfig()
	cfg.Admin.Keys.MaxTTL = 24 * time.Hour
	cfg.Keys.RetirementGrace = time.Minute
	cfg.Keys.ReloadInterval = time.Second
	cfg.Keys.PublishDelay = 3 * time.Minute

	type projected struct {
		fx.In

		MaxTTL          time.Duration `name:"admin_keys_max_ttl"`
		RetirementGrace time.Duration `name:"keys_retirement_grace"`
		ReloadInterval  time.Duration `name:"keys_reload_interval"`
		PublishDelay    time.Duration `name:"keys_publish_delay"`
	}
	var got projected
	fxtest.New(t,
		Supply(cfg),
		fx.Invoke(func(p projected) { got = p }),
	).RequireStart().RequireStop()

	require.Equal(t, 24*time.Hour, got.MaxTTL)
	require.Equal(t, time.Minute, got.RetirementGrace)
	require.Equal(t, time.Second, got.ReloadInterval)
	require.Equal(t, 3*time.Minute, got.PublishDelay)
}
