package servercmd

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	"github.com/onhotpath/tempogate/oidc"
	"github.com/onhotpath/tempogate/state/sqlite"
)

type SessionsCmdSuite struct {
	suite.Suite

	ctx   context.Context
	store *sqlite.Store
}

func TestSessionsCmdSuite(t *testing.T) {
	suite.Run(t, new(SessionsCmdSuite))
}

func (s *SessionsCmdSuite) SetupTest() {
	s.ctx = context.Background()
	store, err := sqlite.New(sqlite.WithPath(filepath.Join(s.T().TempDir(), "state.db")))
	s.Require().NoError(err)
	s.store = store
}

func (s *SessionsCmdSuite) TearDownTest() {
	if s.store != nil {
		s.Require().NoError(s.store.Close())
		s.store = nil
	}
}

func (s *SessionsCmdSuite) seed(token, family, email string) {
	now := time.Now().UTC()
	s.Require().NoError(s.store.SaveRefresh(s.ctx, oidc.Refresh{
		Token: token, JTI: "jti-" + token, ClientID: "tempogate-cli", Subject: "google-sub-" + family, Email: email,
		FamilyID: family, AuthTime: now.Add(-time.Hour), CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}))
}

func (s *SessionsCmdSuite) run(args ...string) (string, error) {
	var out bytes.Buffer
	root := newSessionsCmd(supply(sessionsParams{Store: s.store, Sessions: sqlite.NewAdminSessionStore(s.store)}))
	root.SetArgs(args)
	root.SetOut(&out)
	root.SetErr(new(testWriter))
	err := root.ExecuteContext(s.ctx)
	return out.String(), err
}

func (s *SessionsCmdSuite) live(token string) bool {
	_, err := s.store.ConsumeRefresh(s.ctx, token, "tempogate-cli", time.Now().UTC())
	if errors.Is(err, oidc.ErrRefreshNotFound) {
		return false
	}
	s.Require().NoError(err)
	return true
}

func (s *SessionsCmdSuite) TestRejectsStaleSchema() {
	_, err := s.run("list")
	s.Require().Error(err)
	s.Contains(err.Error(), "tempogate migrate")

	_, err = s.run("revoke", "--email", "alice@example.com")
	s.Require().Error(err)
	s.Contains(err.Error(), "tempogate migrate")
}

func (s *SessionsCmdSuite) TestRejectsUnreachableStore() {
	s.Require().NoError(s.store.Close())
	_, err := s.run("list")
	s.Require().Error(err)
	s.Contains(err.Error(), "state store unreachable")
	s.store = nil
}

func (s *SessionsCmdSuite) TestListShowsSessionsButNeverTokens() {
	s.Require().NoError(s.store.Migrate(s.ctx))
	s.seed("secret-token-a", "fam-a", "alice@example.com")
	s.seed("secret-token-b", "fam-b", "bob@example.com")

	out, err := s.run("list")
	s.Require().NoError(err)
	for _, want := range []string{"FAMILY_ID", "CLIENT_ID", "EMAIL", "SUBJECT", "AUTH_TIME", "LAST_ROTATION", "EXPIRES_AT", "fam-a", "fam-b", "alice@example.com", "google-sub-fam-a", "tempogate-cli"} {
		s.Contains(out, want)
	}
	s.NotContains(out, "secret-token", "token values are never printed")

	out, err = s.run("list", "--email", "bob@example.com")
	s.Require().NoError(err)
	s.Contains(out, "fam-b")
	s.NotContains(out, "fam-a")

	out, err = s.run("list", "--subject", "google-sub-fam-a")
	s.Require().NoError(err)
	s.Contains(out, "fam-a")
	s.NotContains(out, "fam-b")
}

func (s *SessionsCmdSuite) TestRevokeByEmail() {
	s.Require().NoError(s.store.Migrate(s.ctx))
	s.seed("a1", "fam-a", "alice@example.com")
	s.seed("a2", "fam-a2", "alice@example.com")
	s.seed("b1", "fam-b", "bob@example.com")

	out, err := s.run("revoke", "--email", "alice@example.com")
	s.Require().NoError(err)
	s.Contains(out, "revoked 2 session(s)")
	s.False(s.live("a1"))
	s.False(s.live("a2"))
	s.True(s.live("b1"))
}

func (s *SessionsCmdSuite) TestRevokeByFamily() {
	s.Require().NoError(s.store.Migrate(s.ctx))
	s.seed("a1", "fam-a", "alice@example.com")
	s.seed("a2", "fam-a2", "alice@example.com")

	out, err := s.run("revoke", "--family", "fam-a")
	s.Require().NoError(err)
	s.Contains(out, "revoked 1 session(s)")
	s.False(s.live("a1"))
	s.True(s.live("a2"))
}

func (s *SessionsCmdSuite) TestRevokeBySubject() {
	s.Require().NoError(s.store.Migrate(s.ctx))
	s.seed("a1", "fam-a", "alice@example.com")
	s.seed("b1", "fam-b", "bob@example.com")

	out, err := s.run("revoke", "--subject", "google-sub-fam-a")
	s.Require().NoError(err)
	s.Contains(out, "revoked 1 session(s)")
	s.False(s.live("a1"))
	s.True(s.live("b1"))
}

func (s *SessionsCmdSuite) TestRevokeUnknownFamilyFails() {
	s.Require().NoError(s.store.Migrate(s.ctx))
	_, err := s.run("revoke", "--family", "no-such-family")
	s.Require().Error(err, "a mistyped family id must not report success")
	s.Contains(err.Error(), "session not found")
}

func (s *SessionsCmdSuite) TestRevokeNeedsExactlyOneSelector() {
	s.Require().NoError(s.store.Migrate(s.ctx))
	_, err := s.run("revoke")
	s.Require().Error(err)

	_, err = s.run("revoke", "--email", "a@example.com", "--family", "f")
	s.Require().Error(err)

	_, err = s.run("revoke", "--email", "a@example.com", "--subject", "s")
	s.Require().Error(err)

	_, err = s.run("revoke", "--email", "")
	s.Require().Error(err, "an empty selector must not match anything by accident")
}
