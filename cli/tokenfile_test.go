package cli_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	"github.com/onhotpath/tempogate/cli"
)

type TokenFileSuite struct {
	suite.Suite

	dir string
}

func TestTokenFileSuite(t *testing.T) {
	suite.Run(t, new(TokenFileSuite))
}

func (s *TokenFileSuite) SetupTest() {
	s.dir = s.T().TempDir()
}

func (s *TokenFileSuite) TestSaveCreates0600FileUnder0700Dir() {
	path := filepath.Join(s.dir, ".tempogate", "token.json")
	tok := cli.Token{
		AccessToken:  "a.b.c",
		RefreshToken: "refresh-xyz",
		ExpiresAt:    time.Date(2030, 6, 1, 12, 0, 0, 0, time.UTC),
	}

	s.Require().NoError(cli.Save(path, tok))

	fi, err := os.Stat(path)
	s.Require().NoError(err)
	s.Equal(os.FileMode(0o600), fi.Mode().Perm(), "token file must be -rw-------")

	di, err := os.Stat(filepath.Dir(path))
	s.Require().NoError(err)
	s.Equal(os.FileMode(0o700), di.Mode().Perm(), "token dir must be drwx------")
}

func (s *TokenFileSuite) TestRoundTrip() {
	path := filepath.Join(s.dir, "token.json")
	want := cli.Token{
		AccessToken:  "header.payload.sig",
		RefreshToken: "r-1",
		ExpiresAt:    time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC),
	}

	s.Require().NoError(cli.Save(path, want))
	got, err := cli.Load(path)
	s.Require().NoError(err)
	s.Equal(want.AccessToken, got.AccessToken)
	s.Equal(want.RefreshToken, got.RefreshToken)
	s.True(want.ExpiresAt.Equal(got.ExpiresAt), "expiry must round-trip")
}

func (s *TokenFileSuite) TestLoadFromEmptyIsErrNoToken() {
	_, err := cli.Load(filepath.Join(s.dir, "does-not-exist.json"))
	s.Require().Error(err)
	s.ErrorIs(err, cli.ErrNoToken)
}

func (s *TokenFileSuite) TestLoadCorruptIsNotErrNoToken() {
	path := filepath.Join(s.dir, "token.json")
	s.Require().NoError(os.WriteFile(path, []byte("{ this is not json"), 0o600))

	_, err := cli.Load(path)
	s.Require().Error(err)
	s.NotErrorIs(err, cli.ErrNoToken, "a corrupt file must not look like 'not logged in'")
	s.Contains(err.Error(), "decode token file")
}

func (s *TokenFileSuite) TestDefaultTokenPath() {
	p, err := cli.DefaultTokenPath()
	s.Require().NoError(err)
	s.True(filepath.IsAbs(p))
	s.Equal(filepath.Join(".tempogate", "token.json"), filepath.Join(filepath.Base(filepath.Dir(p)), filepath.Base(p)))
}

func (s *TokenFileSuite) TestDefaultTokenPathErrorsWithoutHome() {
	s.T().Setenv("HOME", "")        // unix: os.UserHomeDir fails on empty $HOME
	s.T().Setenv("USERPROFILE", "") // windows equivalent

	_, err := cli.DefaultTokenPath()
	s.Require().Error(err)
	s.Contains(err.Error(), "home directory")
}

func (s *TokenFileSuite) TestSaveFailsWhenParentIsAFile() {
	notADir := filepath.Join(s.dir, "regular-file")
	s.Require().NoError(os.WriteFile(notADir, []byte("x"), 0o600))

	err := cli.Save(filepath.Join(notADir, "token.json"), cli.Token{AccessToken: "a"})
	s.Require().Error(err)
	s.Contains(err.Error(), "create token dir")
}

func (s *TokenFileSuite) TestLoadDirectoryIsErrorNotErrNoToken() {
	_, err := cli.Load(s.dir) // a directory, not a token file
	s.Require().Error(err)
	s.NotErrorIs(err, cli.ErrNoToken)
	s.Contains(err.Error(), "read token file")
}

func (s *TokenFileSuite) TestSaveFailsWhenPathIsADirectory() {
	asDir := filepath.Join(s.dir, "token.json")
	s.Require().NoError(os.Mkdir(asDir, 0o700))

	err := cli.Save(asDir, cli.Token{AccessToken: "a"})
	s.Require().Error(err)
	s.Contains(err.Error(), "replace token file", "rename over a directory must fail")
}

func (s *TokenFileSuite) TestSaveFailsWhenDirIsReadOnly() {
	if os.Geteuid() == 0 {
		s.T().Skip("read-only directory permissions do not constrain root")
	}
	roDir := filepath.Join(s.dir, "ro")
	s.Require().NoError(os.Mkdir(roDir, 0o500))

	err := cli.Save(filepath.Join(roDir, "token.json"), cli.Token{AccessToken: "a"})
	s.Require().Error(err)
	s.Contains(err.Error(), "create temp token file")
}

func (s *TokenFileSuite) TestSaveOverwritesAtomically() {
	path := filepath.Join(s.dir, "token.json")
	s.Require().NoError(cli.Save(path, cli.Token{AccessToken: "old"}))
	s.Require().NoError(cli.Save(path, cli.Token{AccessToken: "new", RefreshToken: "r2"}))

	got, err := cli.Load(path)
	s.Require().NoError(err)
	s.Equal("new", got.AccessToken)
	s.Equal("r2", got.RefreshToken)

	// The temp file used for the atomic rename must not linger.
	entries, err := os.ReadDir(s.dir)
	s.Require().NoError(err)
	s.Len(entries, 1)
}
