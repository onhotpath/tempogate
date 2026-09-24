package servercmd

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"

	"github.com/onhotpath/tempogate/state/sqlite"
)

type MigrateCmdSuite struct {
	suite.Suite

	ctx   context.Context
	store *sqlite.Store
	path  string
	out   *bytes.Buffer
}

func TestMigrateCmdSuite(t *testing.T) {
	suite.Run(t, new(MigrateCmdSuite))
}

func (s *MigrateCmdSuite) SetupTest() {
	s.ctx = context.Background()
	s.path = filepath.Join(s.T().TempDir(), "state.db")

	store, err := sqlite.New(sqlite.WithPath(s.path))
	s.Require().NoError(err)
	s.store = store
	s.out = &bytes.Buffer{}
}

func (s *MigrateCmdSuite) TearDownTest() {
	if s.store != nil {
		s.Require().NoError(s.store.Close())
		s.store = nil
	}
}

func (s *MigrateCmdSuite) params() migrateParams {
	return migrateParams{
		Logger:     zap.NewNop(),
		Store:      s.store,
		SqlitePath: s.path,
	}
}

func (s *MigrateCmdSuite) TestRun() {
	cases := []struct {
		name    string
		prepare func()
	}{
		{
			name:    "empty database",
			prepare: func() {},
		},
		{
			name:    "already migrated is a no-op",
			prepare: func() { s.Require().NoError(s.store.Migrate(s.ctx)) },
		},
	}

	for _, tc := range cases {
		s.Run(tc.name, func() {
			s.SetupTest()
			defer s.TearDownTest()

			tc.prepare()

			cmd := newMigrateCmd(s.params())
			cmd.SetOut(s.out)
			cmd.SetErr(s.out)
			s.Require().NoError(cmd.ExecuteContext(s.ctx))

			s.Require().NoError(s.store.IsCurrent(s.ctx))
		})
	}
}

func (s *MigrateCmdSuite) TestRunReturnsErrorOnClosedStore() {
	s.Require().NoError(s.store.Close())

	cmd := newMigrateCmd(s.params())
	cmd.SetOut(s.out)
	cmd.SetErr(s.out)
	s.Require().Error(cmd.ExecuteContext(s.ctx))

	s.store = nil
}
