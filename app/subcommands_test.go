package app_test

import (
	"bytes"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"

	"github.com/onhotpath/tempogate/app"
)

// SubcommandsSuite runs the real composition root (app.New) the way main does,
// with nothing but STATE_SQLITE_PATH configured. Only `serve` needs the OIDC
// configuration; every other subcommand (and --help) must run without it, or
// a fresh deployment's migrate step fails before `serve` ever gets a chance.
type SubcommandsSuite struct {
	suite.Suite

	dbPath string
}

func TestSubcommandsSuite(t *testing.T) {
	suite.Run(t, new(SubcommandsSuite))
}

func (s *SubcommandsSuite) SetupTest() {
	s.dbPath = filepath.Join(s.T().TempDir(), "state.db")
	s.T().Setenv("STATE_SQLITE_PATH", s.dbPath)
	// Blank anything the host environment might carry so the test proves the
	// "no server config" case regardless of where it runs.
	for _, k := range []string{
		"OIDC_ISSUER", "OIDC_CLIENTS", "OIDC_CLIENT_SECRETS",
		"OIDC_SESSION_SIGNING_KEY", "OIDC_ALLOWED_DOMAINS",
	} {
		s.T().Setenv(k, "")
	}
}

// run executes `tempogate <args...>` through app.New and returns the process
// exit code the dispatcher requested plus everything logged.
func (s *SubcommandsSuite) run(args ...string) (int, string) {
	orig := os.Args
	os.Args = append([]string{"tempogate"}, args...)
	defer func() { os.Args = orig }()

	var logs bytes.Buffer
	a := fxtest.New(s.T(),
		app.New(app.With(fx.Provide(func() io.Writer { return &logs }))),
	)
	a.RequireStart()
	var sig fx.ShutdownSignal
	select {
	case sig = <-a.Wait():
	case <-time.After(30 * time.Second):
		s.FailNow("command did not finish", strings.Join(args, " "))
	}
	a.RequireStop()
	return sig.ExitCode, logs.String()
}

func (s *SubcommandsSuite) TestRunsWithoutServerConfig() {
	cases := [][]string{
		{"version"},
		{"--help"},
		{"serve", "--help"},
		{"migrate", "--help"},
		{"keys", "--help"},
		{"keys", "generate", "--help"},
		{"sessions", "--help"},
		{"gen-oas", "--help"},
		{"migrate"},
		// After migrate, against the same database.
		{"keys", "generate"},
		{"sessions", "list"},
	}
	for _, args := range cases {
		code, logs := s.run(args...)
		s.Equalf(0, code, "tempogate %s must exit 0 with only STATE_SQLITE_PATH set; logs:\n%s",
			strings.Join(args, " "), logs)
	}
}

func (s *SubcommandsSuite) TestServeFailsFastWithoutOIDCConfig() {
	code, _ := s.run("migrate")
	s.Require().Equal(0, code)

	code, logs := s.run("serve")
	s.Equal(1, code)
	s.Contains(logs, "OIDC_SESSION_SIGNING_KEY is required")
}

// serveGraph runs `gen-oas`, which builds the same server graph as `serve`
// (client registrations included) without binding listeners, and discards
// the emitted spec.
func (s *SubcommandsSuite) serveGraph() (int, string) {
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	s.Require().NoError(err)
	orig := os.Stdout
	os.Stdout = devNull
	defer func() { os.Stdout = orig; _ = devNull.Close() }()
	return s.run("gen-oas")
}

// TestDocumentedClientsBuildServerGraph is the H6(a) acceptance proof: the
// client registrations the docs and examples tell operators to use (loopback
// CLI, device-only CLI with an empty value, the internal device-ui client)
// must build the real server graph.
func (s *SubcommandsSuite) TestDocumentedClientsBuildServerGraph() {
	const fixtureSessionKey = "0123456789abcdef0123456789abcdef"
	s.T().Setenv("OIDC_SESSION_SIGNING_KEY", base64.RawURLEncoding.EncodeToString([]byte(fixtureSessionKey)))
	s.T().Setenv("OIDC_CLIENTS", "temporal-ui:https://temporal.example.com/auth/sso/callback,"+
		"tempogate-cli:http://127.0.0.1/callback,"+
		"tempogate-device:,"+
		"tempogate-device-ui:https://tempogate.example.com/idp/device/sso-callback")
	s.T().Setenv("OIDC_CLIENT_SECRETS", "temporal-ui:ui-secret,tempogate-device-ui:app-test-secret")
	s.T().Setenv("OIDC_ISSUER", "https://tempogate.example.com/idp")

	code, logs := s.serveGraph()
	s.Equalf(0, code, "logs:\n%s", logs)
}

// TestPrefixRegistrationFailsServerGraph proves the pre-C1 prefix form fails
// the real server graph at startup rather than booting with a matcher that
// either never matches or matches attacker hosts.
func (s *SubcommandsSuite) TestPrefixRegistrationFailsServerGraph() {
	const fixtureSessionKey = "0123456789abcdef0123456789abcdef"
	s.T().Setenv("OIDC_SESSION_SIGNING_KEY", base64.RawURLEncoding.EncodeToString([]byte(fixtureSessionKey)))
	s.T().Setenv("OIDC_CLIENTS", "tempogate-cli:http://127.0.0.1:,"+
		"tempogate-device-ui:https://tempogate.example.com/idp/device/sso-callback")
	s.T().Setenv("OIDC_CLIENT_SECRETS", "tempogate-device-ui:app-test-secret")
	s.T().Setenv("OIDC_ISSUER", "https://tempogate.example.com/idp")

	code, logs := s.serveGraph()
	s.Equal(1, code)
	s.Contains(logs, "tempogate-cli")
}
