package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
