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
		"OIDC_ISSUER", "OIDC_ALLOW_INSECURE_ISSUER", "OIDC_CLIENTS", "OIDC_CLIENT_SECRETS",
		"OIDC_SESSION_SIGNING_KEY", "OIDC_ALLOWED_DOMAINS", "TEMPOGATE_CONFIG",
	} {
		s.T().Setenv(k, "") // restores the original value on cleanup
		s.Require().NoError(os.Unsetenv(k))
	}
}

// withArgs sets os.Args for the duration of fn, the way main sees them.
func withArgs(args []string, fn func()) {
	orig := os.Args
	os.Args = append([]string{"tempogate"}, args...)
	defer func() { os.Args = orig }()
	fn()
}

// run executes `tempogate <args...>` through app.New and returns the process
// exit code the dispatcher requested plus everything logged.
func (s *SubcommandsSuite) run(args ...string) (int, string) {
	var (
		logs bytes.Buffer
		sig  fx.ShutdownSignal
	)
	withArgs(args, func() {
		a := fxtest.New(s.T(),
			app.New(app.With(fx.Provide(func() io.Writer { return &logs }))),
		)
		a.RequireStart()
		select {
		case sig = <-a.Wait():
		case <-time.After(30 * time.Second):
			s.FailNow("command did not finish", strings.Join(args, " "))
		}
		a.RequireStop()
	})
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

// writeConfig writes an application yaml pointing the state store at a fresh
// path, so a subcommand that honours it leaves a database there.
func (s *SubcommandsSuite) writeConfig() (cfgPath, dbPath string) {
	dir := s.T().TempDir()
	dbPath = filepath.Join(dir, "from-config.db")
	cfgPath = filepath.Join(dir, "tempogate.yaml")
	s.Require().NoError(os.WriteFile(cfgPath,
		[]byte("log:\n  level: debug\nstate:\n  sqlite:\n    path: "+dbPath+"\n"), 0o600))
	s.Require().NoError(os.Unsetenv("STATE_SQLITE_PATH"))
	return cfgPath, dbPath
}

func (s *SubcommandsSuite) TestConfigFlagIsHonouredByEverySubcommand() {
	for _, args := range [][]string{
		{"migrate", "--config", "CFG"},
		{"--config", "CFG", "migrate"},
		{"migrate", "--config=CFG"},
	} {
		cfg, db := s.writeConfig()
		for i := range args {
			args[i] = strings.ReplaceAll(args[i], "CFG", cfg)
		}
		code, logs := s.run(args...)
		s.Require().Equalf(0, code, "tempogate %v; logs:\n%s", args, logs)
		s.FileExistsf(db, "tempogate %v must use the state path from --config", args)
		s.Contains(logs, "loaded config file")
		s.Contains(logs, cfg)

		// The same file applies to the other subcommands too, including the
		// store-only graph of `sessions` against the database it migrated.
		for _, rest := range [][]string{{"keys", "generate"}, {"keys", "list"}, {"sessions", "list"}, {"version"}} {
			code, logs = s.run(append(rest, "--config", cfg)...)
			s.Equalf(0, code, "tempogate %v --config; logs:\n%s", rest, logs)
			s.Contains(logs, "loaded config file")
		}
	}
}

// serve and gen-oas build the server graph; an issuer that only the file sets
// reaching the issuer check proves they read --config too.
func (s *SubcommandsSuite) TestConfigFlagIsHonouredByServerSubcommands() {
	cfg := filepath.Join(s.T().TempDir(), "tempogate.yaml")
	s.Require().NoError(os.WriteFile(cfg,
		[]byte("oidc:\n  issuer: http://from-config.example:8000\n"), 0o600))
	code, _ := s.run("migrate")
	s.Require().Equal(0, code)

	for _, sub := range []string{"serve", "gen-oas"} {
		code, logs := s.run(sub, "--config", cfg)
		s.Equalf(1, code, "tempogate %s --config; logs:\n%s", sub, logs)
		s.Contains(logs, `OIDC_ISSUER \"http://from-config.example:8000\" must use https`)
	}
}

func (s *SubcommandsSuite) TestConfigEnvironmentVariableIsHonoured() {
	cfg, db := s.writeConfig()
	s.T().Setenv("TEMPOGATE_CONFIG", cfg)
	code, logs := s.run("migrate")
	s.Require().Equalf(0, code, "logs:\n%s", logs)
	s.FileExists(db)
}

// An explicitly requested file that cannot be read is fatal for every
// subcommand: silently falling back to defaults would run with a config the
// operator did not ask for.
func (s *SubcommandsSuite) TestUnreadableConfigFlagIsFatal() {
	missing := filepath.Join(s.T().TempDir(), "missing.yaml")
	for _, args := range [][]string{
		{"version", "--config", missing},
		{"migrate", "--config", missing},
	} {
		withArgs(args, func() {
			err := fx.New(app.New(app.With(fx.Provide(func() io.Writer { return io.Discard })))).Err()
			s.Require().Errorf(err, "tempogate %v", args)
			s.ErrorIs(err, os.ErrNotExist)
			s.Contains(err.Error(), missing)
		})
	}
}

// The image's cwd (/home/nonroot) is unreadable under any uid other than the
// default; the implicit ./application.yaml lookup must log and move on.
func (s *SubcommandsSuite) TestUnreadableWorkingDirectoryIsSkipped() {
	if os.Geteuid() == 0 {
		s.T().Skip("permission checks do not apply to root")
	}
	dir := s.T().TempDir()
	s.T().Chdir(dir)
	s.Require().NoError(os.Chmod(dir, 0))
	s.T().Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	for _, args := range [][]string{{"version"}, {"migrate"}} {
		code, logs := s.run(args...)
		s.Equalf(0, code, "tempogate %v; logs:\n%s", args, logs)
		s.Contains(logs, "skipping unreadable config file")
	}
}

func (s *SubcommandsSuite) TestServeRequiresHTTPSIssuer() {
	code, _ := s.run("migrate")
	s.Require().Equal(0, code)

	s.T().Setenv("OIDC_ISSUER", "http://tempogate:8000")
	code, logs := s.run("serve")
	s.Equal(1, code)
	// zap escapes the quotes inside the logged error.
	s.Contains(logs, `OIDC_ISSUER \"http://tempogate:8000\" must use https`)
	s.NotContains(logs, "OIDC_SESSION_SIGNING_KEY", "the issuer check runs before the server stack is built")

	code, logs = s.run("gen-oas")
	s.Equal(1, code)
	s.Contains(logs, "must use https")

	// The insecure issuer only matters to the server: migrate, keys and
	// version never build it.
	for _, args := range [][]string{{"migrate"}, {"keys", "generate"}, {"version"}} {
		code, logs = s.run(args...)
		s.Equalf(0, code, "tempogate %v; logs:\n%s", args, logs)
	}

	// The development opt-in lets serve past the issuer check (it then
	// fails on the next missing setting).
	s.T().Setenv("OIDC_ALLOW_INSECURE_ISSUER", "true")
	code, logs = s.run("serve")
	s.Equal(1, code)
	s.NotContains(logs, "must use https")
	s.Contains(logs, "insecure OIDC issuer allowed")
	s.Contains(logs, "OIDC_SESSION_SIGNING_KEY is required")
}
