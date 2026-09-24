package app_test

import (
	"encoding/base64"
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

// TestNew proves the fx graph resolves end-to-end (config + log + sqlite +
// api + cmd) and that lifecycle hooks fire. The default subcommand prints
// help and triggers Shutdown, so the schema-check inside `serve` is not
// invoked here.
//
// The device-flow verification UI (oidc.NewDeviceUI) pulls *SessionManager
// into the api_registrars group, which in turn requires
// OIDC__SESSION_SIGNING_KEY at graph construction. Two OIDC client
// registrations (tempogate-device-ui plus its secret) are also required
// so newDeviceUIRegistrar's internal-client validation passes. Stubbing
// both here keeps the app-graph smoke test self-contained without taking
// on the rest of the deployment surface area.
func (s *AppSuite) TestNew() {
	// Synthetic 32-byte placeholder — same pattern oidc/session_test.go
	// and oidc/fx_test.go use, kept visibly synthetic so a future reader
	// (or secret-scanner) can tell at a glance this is fixture data, not
	// a leaked key.
	const fixtureSessionKey = "0123456789abcdef0123456789abcdef"
	s.T().Setenv("STATE__SQLITE__PATH", filepath.Join(s.T().TempDir(), "state.db"))
	s.T().Setenv("OIDC__SESSION_SIGNING_KEY", base64.RawURLEncoding.EncodeToString([]byte(fixtureSessionKey)))
	s.T().Setenv("OIDC__CLIENTS", "tempogate-device-ui:https://tempogate.example.com/idp/device/sso-callback")
	s.T().Setenv("OIDC__CLIENT_SECRETS", "tempogate-device-ui:app-test-secret")
	s.T().Setenv("OIDC__ISSUER", "https://tempogate.example.com/idp")

	ran := false
	a := fxtest.New(s.T(),
		app.New(),
		fx.Invoke(func() { ran = true }),
	)
	a.RequireStart().RequireStop()
	s.True(ran)
}
