package config

import (
	"testing"

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
