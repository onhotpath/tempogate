package app_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/suite"
	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"

	"github.com/onhotpath/tempogate/app"
)

type AppSuite struct {
	suite.Suite
}

func TestAppSuite(t *testing.T) {
	suite.Run(t, new(AppSuite))
}

// TestNew proves the fx graph resolves end-to-end (config + log + cmd + the
// server subcommands) and that lifecycle hooks fire. The server stack itself
// is built per subcommand when it runs, so no OIDC configuration is needed
// here (subcommands_test.go covers running each subcommand).
func (s *AppSuite) TestNew() {
	s.T().Setenv("STATE_SQLITE_PATH", filepath.Join(s.T().TempDir(), "state.db"))

	ran := false
	a := fxtest.New(s.T(),
		app.New(),
		fx.Invoke(func() { ran = true }),
	)
	a.RequireStart().RequireStop()
	s.True(ran)
}
