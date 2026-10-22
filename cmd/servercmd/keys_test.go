package servercmd

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

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
	s.Contains(err.Error(), "schema version 0, expected ")
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

func (s *KeysCmdSuite) encryptCmd(k *keys.Keys, out *bytes.Buffer) *cobra.Command {
	root := newKeysCmd(keysParams{Store: s.store, Keys: k})
	root.SetArgs([]string{"encrypt"})
	root.SetOut(out)
	root.SetErr(new(testWriter))
	return root
}

func (s *KeysCmdSuite) TestEncryptRewritesPlaintextKeypairs() {
	s.Require().NoError(s.store.Migrate(s.ctx))
	s.Require().NoError(keys.New(keys.WithStore(s.store), keys.WithGenerateOptions(keys.WithRSABits(2048))).Init(s.ctx))

	kek := bytes.Repeat([]byte{1}, 32)
	withKEK := keys.New(keys.WithStore(s.store), keys.WithEncryptionKey(kek))
	var out bytes.Buffer
	s.Require().NoError(s.encryptCmd(withKEK, &out).ExecuteContext(s.ctx))
	s.Contains(out.String(), "encrypted 1 keypair(s)")

	kps, err := s.store.LoadKeypairs(s.ctx)
	s.Require().NoError(err)
	s.Require().Len(kps, 1)
	s.NotContains(string(kps[0].PrivatePEM), "PRIVATE KEY")
	s.Require().NoError(keys.New(keys.WithStore(s.store), keys.WithEncryptionKey(kek)).Init(s.ctx),
		"the encrypted row loads with the key")

	out.Reset()
	s.Require().NoError(s.encryptCmd(withKEK, &out).ExecuteContext(s.ctx))
	s.Contains(out.String(), "encrypted 0 keypair(s)")
}

func (s *KeysCmdSuite) TestEncryptWithoutKeyFails() {
	s.Require().NoError(s.store.Migrate(s.ctx))
	err := s.encryptCmd(keys.New(keys.WithStore(s.store)), new(bytes.Buffer)).ExecuteContext(s.ctx)
	s.Require().ErrorIs(err, keys.ErrNoEncryptionKey)
}

func (s *KeysCmdSuite) TestEncryptRejectsStaleSchema() {
	err := s.encryptCmd(keys.New(keys.WithStore(s.store)), new(bytes.Buffer)).ExecuteContext(s.ctx)
	s.Require().ErrorContains(err, "tempogate migrate")
}

func (s *KeysCmdSuite) TestServeWarnsAboutUnencryptedKeys() {
	s.Require().NoError(s.store.Migrate(s.ctx))
	s.Require().NoError(keys.New(keys.WithStore(s.store), keys.WithGenerateOptions(keys.WithRSABits(2048))).Init(s.ctx))

	core, logs := observer.New(zap.WarnLevel)
	plain := keys.New(keys.WithStore(s.store))
	s.Require().NoError(plain.Init(s.ctx))
	warnUnencryptedKeys(zap.New(core), plain)
	s.Zero(logs.Len(), "no KEK configured: nothing to warn about")

	withKEK := keys.New(keys.WithStore(s.store), keys.WithEncryptionKey(bytes.Repeat([]byte{1}, 32)))
	s.Require().NoError(withKEK.Init(s.ctx))
	warnUnencryptedKeys(zap.New(core), withKEK)
	s.Equal(1, logs.FilterMessageSnippet("keys encrypt").Len())
}
