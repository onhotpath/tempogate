package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"

	"github.com/onhotpath/tempogate/cli"
)

type LoginCmdSuite struct {
	suite.Suite

	origRunner func(context.Context, ...cli.Option) (cli.Token, error)
}

func TestLoginCmdSuite(t *testing.T) {
	suite.Run(t, new(LoginCmdSuite))
}

func (s *LoginCmdSuite) SetupTest() {
	s.origRunner = loginRunner
}

func (s *LoginCmdSuite) TearDownTest() {
	loginRunner = s.origRunner
}

func (s *LoginCmdSuite) TestDefaultRunnerDelegatesToFlow() {
	// Exercise the production seam (not the test stub): an empty issuer must
	// fail fast in cli.Flow without opening a browser or hitting the network.
	_, err := loginRunner(context.Background(), cli.WithIssuer(""))
	s.Require().Error(err)
	s.Contains(err.Error(), "issuer is required")
}

func (s *LoginCmdSuite) TestRequiresIssuer() {
	s.T().Setenv("TEMPOGATE__ISSUER", "")

	cmd := newLoginCmd(zap.NewNop())
	cmd.SetOut(new(testWriter))
	cmd.SetErr(new(testWriter))

	err := cmd.ExecuteContext(context.Background())
	s.Require().Error(err)
	s.Contains(err.Error(), "issuer is required")
	s.Contains(err.Error(), "TEMPOGATE__ISSUER")
}

func (s *LoginCmdSuite) TestEnvIssuerPrintsTokenAndPersists() {
	s.T().Setenv("TEMPOGATE__ISSUER", "https://tempogate.example.com")
	expiry := time.Date(2031, 1, 2, 3, 4, 5, 0, time.UTC)
	loginRunner = func(_ context.Context, _ ...cli.Option) (cli.Token, error) {
		return cli.Token{AccessToken: "header.payload.sig", RefreshToken: "r-1", ExpiresAt: expiry}, nil
	}
	path := filepath.Join(s.T().TempDir(), "nested", "token.json")

	var out, errOut bytes.Buffer
	cmd := newLoginCmd(zap.NewNop())
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs([]string{"--token-file", path})

	s.Require().NoError(cmd.ExecuteContext(context.Background()))
	s.Equal("header.payload.sig\n", out.String(), "stdout carries only the token")
	s.Contains(errOut.String(), "Signed in. Token saved to "+path)
	s.Contains(errOut.String(), "valid until 2031-01-02T03:04:05Z")

	persisted, err := cli.Load(path)
	s.Require().NoError(err)
	s.Equal("header.payload.sig", persisted.AccessToken)
	s.Equal("r-1", persisted.RefreshToken)
}

func (s *LoginCmdSuite) TestTokenPersistenceFailurePropagates() {
	s.T().Setenv("TEMPOGATE__ISSUER", "https://tempogate.example.com")
	loginRunner = func(_ context.Context, _ ...cli.Option) (cli.Token, error) {
		return cli.Token{AccessToken: "t", RefreshToken: "r"}, nil
	}
	notADir := filepath.Join(s.T().TempDir(), "afile")
	s.Require().NoError(os.WriteFile(notADir, []byte("x"), 0o600))

	cmd := newLoginCmd(zap.NewNop())
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(new(testWriter))
	cmd.SetArgs([]string{"--token-file", filepath.Join(notADir, "token.json")})

	err := cmd.ExecuteContext(context.Background())
	s.Require().Error(err)
	s.Contains(err.Error(), "create token dir")
	s.Empty(out.String(), "the token must not be printed if it could not be persisted")
}

func (s *LoginCmdSuite) TestTokenPathResolutionFailurePropagates() {
	s.T().Setenv("TEMPOGATE__ISSUER", "https://tempogate.example.com")
	s.T().Setenv("HOME", "")
	s.T().Setenv("USERPROFILE", "")

	cmd := newLoginCmd(zap.NewNop())
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetOut(new(testWriter))
	cmd.SetErr(new(testWriter))
	cmd.SetArgs([]string{}) // no --token-file ⇒ must resolve the default

	err := cmd.ExecuteContext(context.Background())
	s.Require().Error(err)
	s.Contains(err.Error(), "home directory")
}

func (s *LoginCmdSuite) TestFlagIssuerOverridesEnvAndErrorsPropagate() {
	s.T().Setenv("TEMPOGATE__ISSUER", "https://from-env.example.com")
	loginRunner = func(_ context.Context, _ ...cli.Option) (cli.Token, error) {
		return cli.Token{}, errors.New("cli: token exchange rejected (invalid_grant): nope")
	}

	var out, errOut bytes.Buffer
	cmd := newLoginCmd(zap.NewNop())
	// Mirror production, where login runs under NewRootCmd (SilenceUsage/
	// SilenceErrors), so an error does not spray usage onto stdout.
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs([]string{"--issuer", "https://from-flag.example.com"})

	err := cmd.ExecuteContext(context.Background())
	s.Require().Error(err)
	s.Contains(err.Error(), "invalid_grant")
	s.Empty(out.String(), "no token is printed on failure")
}

// DeviceLoginDispatchSuite covers the --device / TEMPOGATE_LOGIN_MODE dispatch
// table. Kept in a sibling suite so SetupTest captures both runner seams
// without burdening the loopback tests with state they do not exercise.
type DeviceLoginDispatchSuite struct {
	suite.Suite

	origLoginRunner  func(context.Context, ...cli.Option) (cli.Token, error)
	origDeviceRunner func(context.Context, ...cli.DeviceOption) (cli.Token, error)
}

func TestDeviceLoginDispatchSuite(t *testing.T) {
	suite.Run(t, new(DeviceLoginDispatchSuite))
}

func (s *DeviceLoginDispatchSuite) SetupTest() {
	s.origLoginRunner = loginRunner
	s.origDeviceRunner = deviceRunner
}

func (s *DeviceLoginDispatchSuite) TearDownTest() {
	loginRunner = s.origLoginRunner
	deviceRunner = s.origDeviceRunner
}

func (s *DeviceLoginDispatchSuite) TestDispatchTable() {
	cases := []struct {
		name       string
		args       []string
		envMode    string
		wantDevice bool
	}{
		{
			name:       "flag dispatches to device path",
			args:       []string{"--device"},
			envMode:    "",
			wantDevice: true,
		},
		{
			name:       "env dispatches to device path",
			args:       nil,
			envMode:    "device",
			wantDevice: true,
		},
		{
			name:       "neither flag nor env dispatches to loopback",
			args:       nil,
			envMode:    "",
			wantDevice: false,
		},
		{
			name:       "explicit --device=false overrides env=device",
			args:       []string{"--device=false"},
			envMode:    "device",
			wantDevice: false,
		},
		{
			name:       "unrelated env value does not flip dispatch",
			args:       nil,
			envMode:    "loopback",
			wantDevice: false,
		},
	}

	for _, tc := range cases {
		s.Run(tc.name, func() {
			s.T().Setenv("TEMPOGATE__ISSUER", "https://tempogate.example.com")
			s.T().Setenv("TEMPOGATE_LOGIN_MODE", tc.envMode)

			var loopbackCalls, deviceCalls int
			loginRunner = func(_ context.Context, _ ...cli.Option) (cli.Token, error) {
				loopbackCalls++
				return cli.Token{AccessToken: "loopback-token"}, nil
			}
			deviceRunner = func(_ context.Context, _ ...cli.DeviceOption) (cli.Token, error) {
				deviceCalls++
				return cli.Token{AccessToken: "device-token"}, nil
			}

			path := filepath.Join(s.T().TempDir(), "token.json")
			args := append([]string{"--token-file", path}, tc.args...)

			var out, errOut bytes.Buffer
			cmd := newLoginCmd(zap.NewNop())
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
			cmd.SetOut(&out)
			cmd.SetErr(&errOut)
			cmd.SetArgs(args)

			s.Require().NoError(cmd.ExecuteContext(context.Background()))

			if tc.wantDevice {
				s.Equal(1, deviceCalls, "device runner must be invoked")
				s.Zero(loopbackCalls, "loopback runner must not be invoked")
				s.Equal("device-token\n", out.String())
			} else {
				s.Equal(1, loopbackCalls, "loopback runner must be invoked")
				s.Zero(deviceCalls, "device runner must not be invoked")
				s.Equal("loopback-token\n", out.String())
			}
		})
	}
}

func (s *DeviceLoginDispatchSuite) TestDevicePathPersistsTokenAndPrintsSignedIn() {
	s.T().Setenv("TEMPOGATE__ISSUER", "https://tempogate.example.com")
	expiry := time.Date(2031, 6, 7, 8, 9, 10, 0, time.UTC)
	deviceRunner = func(_ context.Context, _ ...cli.DeviceOption) (cli.Token, error) {
		return cli.Token{AccessToken: "dev.payload.sig", RefreshToken: "dev-r-1", ExpiresAt: expiry}, nil
	}
	loginRunner = func(_ context.Context, _ ...cli.Option) (cli.Token, error) {
		s.FailNow("loopback runner must not run on the device path")
		return cli.Token{}, nil
	}
	path := filepath.Join(s.T().TempDir(), "nested", "token.json")

	var out, errOut bytes.Buffer
	cmd := newLoginCmd(zap.NewNop())
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs([]string{"--device", "--token-file", path})

	s.Require().NoError(cmd.ExecuteContext(context.Background()))
	s.Equal("dev.payload.sig\n", out.String(), "stdout carries only the token")
	s.Contains(errOut.String(), "Signed in. Token saved to "+path)
	s.Contains(errOut.String(), "valid until 2031-06-07T08:09:10Z")

	persisted, err := cli.Load(path)
	s.Require().NoError(err)
	s.Equal("dev.payload.sig", persisted.AccessToken)
	s.Equal("dev-r-1", persisted.RefreshToken)
}

func (s *DeviceLoginDispatchSuite) TestDeviceRunnerErrorPropagates() {
	s.T().Setenv("TEMPOGATE__ISSUER", "https://tempogate.example.com")
	deviceRunner = func(_ context.Context, _ ...cli.DeviceOption) (cli.Token, error) {
		return cli.Token{}, errors.New("cli: user denied the device authorization")
	}

	var out bytes.Buffer
	cmd := newLoginCmd(zap.NewNop())
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetOut(&out)
	cmd.SetErr(new(testWriter))
	cmd.SetArgs([]string{"--device", "--token-file", filepath.Join(s.T().TempDir(), "t.json")})

	err := cmd.ExecuteContext(context.Background())
	s.Require().Error(err)
	s.Contains(err.Error(), "user denied")
	s.Empty(out.String(), "no token is printed on device-flow failure")
}

func (s *DeviceLoginDispatchSuite) TestDefaultDeviceRunnerDelegatesToDeviceFlow() {
	_, err := deviceRunner(context.Background(), cli.WithDeviceIssuer(""))
	s.Require().Error(err)
	s.Contains(err.Error(), "issuer is required")
}

// TestDevicePollDeadlineFlagAppendsOption asserts the new
// --device-poll-deadline flag actually adds a DeviceOption when set (and
// omits one when left at its zero value, so the default 15-minute
// expires_in path keeps working for laptop users). The runner stub captures
// the options list because counting it is enough to prove the wiring — the
// option's effect is covered by cli's own DeviceFlow tests.
func (s *DeviceLoginDispatchSuite) TestDevicePollDeadlineFlagAppendsOption() {
	s.T().Setenv("TEMPOGATE__ISSUER", "https://tempogate.example.com")

	cases := []struct {
		name    string
		args    []string
		wantLen int
	}{
		{
			name:    "flag set appends WithDevicePollDeadline",
			args:    []string{"--device", "--device-poll-deadline", "7s"},
			wantLen: 4, // issuer + client-id + output + poll-deadline
		},
		{
			name:    "flag unset omits WithDevicePollDeadline",
			args:    []string{"--device"},
			wantLen: 3, // issuer + client-id + output only
		},
	}

	for _, tc := range cases {
		s.Run(tc.name, func() {
			var capturedLen int
			deviceRunner = func(_ context.Context, opts ...cli.DeviceOption) (cli.Token, error) {
				capturedLen = len(opts)
				return cli.Token{AccessToken: "device-token"}, nil
			}

			var out, errOut bytes.Buffer
			cmd := newLoginCmd(zap.NewNop())
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
			cmd.SetOut(&out)
			cmd.SetErr(&errOut)
			cmd.SetArgs(append(tc.args, "--token-file", filepath.Join(s.T().TempDir(), "t.json")))

			s.Require().NoError(cmd.ExecuteContext(context.Background()))
			s.Equal(tc.wantLen, capturedLen)
		})
	}
}

// TestDevicePollDeadlineRejectsNegative asserts a negative duration is
// surfaced as a clear validation error rather than silently treated like
// the unset default — a user passing --device-poll-deadline=-5s would
// otherwise see the full issuer expires_in time out before figuring out
// their flag was ignored.
func (s *DeviceLoginDispatchSuite) TestDevicePollDeadlineRejectsNegative() {
	s.T().Setenv("TEMPOGATE__ISSUER", "https://tempogate.example.com")
	deviceRunner = func(_ context.Context, _ ...cli.DeviceOption) (cli.Token, error) {
		s.FailNow("deviceRunner must not run when the flag fails validation")
		return cli.Token{}, nil
	}

	cmd := newLoginCmd(zap.NewNop())
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetOut(new(testWriter))
	cmd.SetErr(new(testWriter))
	cmd.SetArgs([]string{
		"--device", "--device-poll-deadline", "-5s",
		"--token-file", filepath.Join(s.T().TempDir(), "t.json"),
	})

	err := cmd.ExecuteContext(context.Background())
	s.Require().Error(err)
	s.Contains(err.Error(), "--device-poll-deadline must be non-negative")
}
