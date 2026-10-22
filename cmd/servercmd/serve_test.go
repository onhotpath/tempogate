package servercmd

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"

	"github.com/onhotpath/tempogate/state/sqlite"
)

type ServeCmdSuite struct {
	suite.Suite

	ctx   context.Context
	store *sqlite.Store
	path  string
}

func TestServeCmdSuite(t *testing.T) {
	suite.Run(t, new(ServeCmdSuite))
}

func (s *ServeCmdSuite) SetupTest() {
	s.ctx = context.Background()
	s.path = filepath.Join(s.T().TempDir(), "state.db")

	store, err := sqlite.New(sqlite.WithPath(s.path))
	s.Require().NoError(err)
	s.store = store
}

func (s *ServeCmdSuite) TearDownTest() {
	if s.store != nil {
		s.Require().NoError(s.store.Close())
		s.store = nil
	}
}

func (s *ServeCmdSuite) TestRejectsStaleSchema() {
	cmd := newServeCmd(serveParams{
		Logger: zap.NewNop(),
		Store:  s.store,
	})
	cmd.SetOut(new(testWriter))
	cmd.SetErr(new(testWriter))

	err := cmd.ExecuteContext(s.ctx)
	s.Require().Error(err)
	s.Contains(err.Error(), "schema version 0, expected 9")
	s.Contains(err.Error(), "tempogate migrate")
}

func (s *ServeCmdSuite) TestRejectsSchemaWithGap() {
	s.Require().NoError(s.store.Migrate(s.ctx))

	// Simulate a migration merged out of numeric order: a lower version is
	// unapplied while the highest one is recorded.
	db, err := sql.Open("sqlite", s.path)
	s.Require().NoError(err)
	_, err = db.ExecContext(s.ctx, `DELETE FROM schema_migrations WHERE version = 3`)
	s.Require().NoError(err)
	s.Require().NoError(db.Close())

	cmd := newServeCmd(serveParams{
		Logger: zap.NewNop(),
		Store:  s.store,
	})
	cmd.SetOut(new(testWriter))
	cmd.SetErr(new(testWriter))

	err = cmd.ExecuteContext(s.ctx)
	s.Require().Error(err)
	s.Contains(err.Error(), "schema is missing migrations 3")
	s.Contains(err.Error(), "tempogate migrate")
}

func (s *ServeCmdSuite) TestRejectsUnreachableStore() {
	s.Require().NoError(s.store.Close())

	cmd := newServeCmd(serveParams{
		Logger: zap.NewNop(),
		Store:  s.store,
	})
	cmd.SetOut(new(testWriter))
	cmd.SetErr(new(testWriter))

	err := cmd.ExecuteContext(s.ctx)
	s.Require().Error(err)
	s.Contains(err.Error(), "state store unreachable")

	s.store = nil
}
