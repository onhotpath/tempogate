package cmd

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"

	"github.com/onhotpath/tempogate/cli"
)

type TokenCmdSuite struct {
	suite.Suite

	orig func(context.Context, string, string) (cli.Token, error)
}

func TestTokenCmdSuite(t *testing.T) {
	suite.Run(t, new(TokenCmdSuite))
}

func (s *TokenCmdSuite) SetupTest() {
	s.orig = tokenRefresher
}

func (s *TokenCmdSuite) TearDownTest() {
	tokenRefresher = s.orig
}

func (s *TokenCmdSuite) TestDefaultRefresherDelegatesToEnsureFresh() {
	// Exercise the production seam (not the test stub): a missing token file
	// must surface ErrNoToken without any network.
	missing := filepath.Join(s.T().TempDir(), "nope.json")
	_, err := tokenRefresher(context.Background(), missing, "https://tempogate.example.com")
	s.Require().Error(err)
	s.ErrorIs(err, cli.ErrNoToken)
}

func (s *TokenCmdSuite) TestRequiresIssuer() {
	s.T().Setenv("TEMPOGATE_ISSUER", "")

	cmd := newTokenCmd(zap.NewNop())
	cmd.SetOut(new(testWriter))
	cmd.SetErr(new(testWriter))

	err := cmd.ExecuteContext(context.Background())
	s.Require().Error(err)
	s.Contains(err.Error(), "issuer is required")
}

func (s *TokenCmdSuite) TestPrintsAccessTokenOnly() {
	s.T().Setenv("TEMPOGATE_ISSUER", "https://tempogate.example.com")
	tokenRefresher = func(_ context.Context, _, issuer string) (cli.Token, error) {
		s.Equal("https://tempogate.example.com", issuer, "env issuer must reach EnsureFresh")
		return cli.Token{AccessToken: "fresh.jwt.token", RefreshToken: "r"}, nil
	}

	var out, errOut bytes.Buffer
	cmd := newTokenCmd(zap.NewNop())
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs([]string{})

	s.Require().NoError(cmd.ExecuteContext(context.Background()))
	s.Equal("fresh.jwt.token\n", out.String(), "stdout carries only the access token")
}

func (s *TokenCmdSuite) TestTokenPathResolutionFailurePropagates() {
	s.T().Setenv("TEMPOGATE_ISSUER", "https://tempogate.example.com")
	s.T().Setenv("HOME", "")
	s.T().Setenv("USERPROFILE", "")

	cmd := newTokenCmd(zap.NewNop())
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetOut(new(testWriter))
	cmd.SetErr(new(testWriter))
	cmd.SetArgs([]string{})

	err := cmd.ExecuteContext(context.Background())
	s.Require().Error(err)
	s.Contains(err.Error(), "home directory")
}

func (s *TokenCmdSuite) TestRefreshErrorPropagates() {
	s.T().Setenv("TEMPOGATE_ISSUER", "https://tempogate.example.com")
	tokenRefresher = func(_ context.Context, _, _ string) (cli.Token, error) {
		return cli.Token{}, errors.New("cli: no token file; run `tempogate login` first")
	}

	var out, errOut bytes.Buffer
	cmd := newTokenCmd(zap.NewNop())
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs([]string{})

	err := cmd.ExecuteContext(context.Background())
	s.Require().Error(err)
	s.Contains(err.Error(), "no token file")
	s.Empty(out.String())
}
