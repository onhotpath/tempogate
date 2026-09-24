package servercmd

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/suite"

	"github.com/onhotpath/tempogate/keys"
	"github.com/onhotpath/tempogate/state/sqlite"
)

type KeysCmdSuite struct {
	suite.Suite

	ctx   context.Context
	store *sqlite.Store
	path  string
}

func TestKeysCmdSuite(t *testing.T) {
	suite.Run(t, new(KeysCmdSuite))
}

func (s *KeysCmdSuite) SetupTest() {
	s.ctx = context.Background()
	s.path = filepath.Join(s.T().TempDir(), "state.db")

	store, err := sqlite.New(sqlite.WithPath(s.path))
	s.Require().NoError(err)
	s.store = store
}

func (s *KeysCmdSuite) TearDownTest() {
	if s.store != nil {
		s.Require().NoError(s.store.Close())
		s.store = nil
	}
}

// generateCmd builds the `keys` root and points it at the `generate`
// subcommand, so the test exercises newKeysCmd's wiring and
// newKeysGenerateCmd's RunE together (mirroring how the dispatcher invokes it).
func (s *KeysCmdSuite) generateCmd(out *bytes.Buffer) *cobra.Command {
	root := newKeysCmd(keysParams{
		Store: s.store,
		Keys:  keys.New(keys.WithStore(s.store)),
	})
	root.SetArgs([]string{"generate"})
	if out != nil {
		root.SetOut(out)
	} else {
		root.SetOut(new(testWriter))
	}
	root.SetErr(new(testWriter))
	return root
}

func (s *KeysCmdSuite) TestRejectsUnreachableStore() {
	s.Require().NoError(s.store.Close())

	err := s.generateCmd(nil).ExecuteContext(s.ctx)
	s.Require().Error(err)
	s.Contains(err.Error(), "state store unreachable")

	s.store = nil
}

func (s *KeysCmdSuite) TestRejectsStaleSchema() {
	// Fresh store, never migrated: generate must refuse before touching keys.
	err := s.generateCmd(nil).ExecuteContext(s.ctx)
	s.Require().Error(err)
	s.Contains(err.Error(), "schema version 0, expected 9")
	s.Contains(err.Error(), "tempogate migrate")
}

func (s *KeysCmdSuite) TestGeneratesKeypairOnMigratedStore() {
	s.Require().NoError(s.store.Migrate(s.ctx))

	var out bytes.Buffer
	err := s.generateCmd(&out).ExecuteContext(s.ctx)
	s.Require().NoError(err)
	s.Contains(out.String(), "generated keypair: kid=")

	kps, err := s.store.LoadKeypairs(s.ctx)
	s.Require().NoError(err)
	s.Len(kps, 1, "the generated keypair must be persisted")
}
