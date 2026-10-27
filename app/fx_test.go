package app_test

import (
	"context"
	"os"
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

// TestInvalidLogConfig: an invalid LOG_FORMAT or LOG_LEVEL fails before the
// logger exists. It must still come out as one line on stderr, not as fx's
// console logger's provide events and the dig chain.
func (s *AppSuite) TestInvalidLogConfig() {
	for env, want := range map[string]string{
		"LOG_FORMAT": `tempogate: invalid config: LOG_FORMAT must be "auto", "json" or "pretty", got "bogus"` + "\n",
		"LOG_LEVEL":  `tempogate: invalid config: LOG_LEVEL must be "debug", "info", "warn" or "error", got "bogus"` + "\n",
	} {
		s.Run(env, func() {
			s.T().Setenv(env, "bogus")
			stderr, err := os.Create(filepath.Join(s.T().TempDir(), "stderr"))
			s.Require().NoError(err)
			orig := os.Stderr
			os.Stderr = stderr
			a := fx.New(app.New())
			os.Stderr = orig

			s.Require().Error(a.Start(context.Background()))
			s.Require().NoError(stderr.Close())
			out, err := os.ReadFile(stderr.Name())
			s.Require().NoError(err)
			s.Equal(want, string(out))
		})
	}
}
