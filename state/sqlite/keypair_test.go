package sqlite

import (
	"time"

	"github.com/onhotpath/tempogate/keys"
)

const keypairRetirementVersion = 13

// TestKeypairRetirementMigrationKeepsExistingKeys applies every migration
// before 0013, stores a keypair the old way, then migrates: the row must
// survive with no retirement stamp. Only versions below 0013 are applied
// first, so the test holds whichever unrelated migrations sit between.
func (s *StoreSuite) TestKeypairRetirementMigrationKeepsExistingKeys() {
	store, err := New(WithPath(s.T().TempDir()+"/pre.db"), WithBusyTimeout(time.Second))
	s.Require().NoError(err)
	defer func() { s.Require().NoError(store.Close()) }()

	_, err = store.db.ExecContext(s.ctx, schemaVersionDDL)
	s.Require().NoError(err)
	migs, err := loadMigrations()
	s.Require().NoError(err)
	found := false
	for _, m := range migs {
		if m.Version == keypairRetirementVersion {
			found = true
		}
		if m.Version < keypairRetirementVersion {
			s.Require().NoError(applyMigration(s.ctx, store.db, m))
		}
	}
	s.Require().True(found, "migration 0013 must be embedded")

	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	_, err = store.db.ExecContext(s.ctx,
		`INSERT INTO keypairs (kid, alg, private_pem, public_pem, created_at) VALUES (?, ?, ?, ?, ?)`,
		"legacy", "RS256", []byte("priv"), []byte("pub"), created)
	s.Require().NoError(err)

	s.Require().NoError(store.Migrate(s.ctx))
	s.Require().NoError(store.IsCurrent(s.ctx))

	got, err := store.LoadKeypairs(s.ctx)
	s.Require().NoError(err)
	s.Require().Len(got, 1)
	s.Equal("legacy", got[0].Kid)
	s.True(created.Equal(got[0].CreatedAt))
	s.Nil(got[0].RetiredAt, "keys that predate retirement load as active")
}

func (s *StoreSuite) TestRetireKeypair() {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	save := func(kid string, offset time.Duration) {
		s.Require().NoError(s.store.SaveKeypair(s.ctx, keys.Keypair{
			Kid: kid, Alg: "RS256", PrivatePEM: []byte("priv"), PublicPEM: []byte("pub"),
			CreatedAt: base.Add(offset),
		}))
	}

	_, err := s.store.RetireKeypair(s.ctx, "missing", base)
	s.Require().ErrorIs(err, keys.ErrKeypairNotFound)

	save("old", 0)
	_, err = s.store.RetireKeypair(s.ctx, "old", base)
	s.Require().ErrorIs(err, keys.ErrLastActiveKeypair, "the only active key cannot be retired")

	save("new", time.Hour)
	at := base.Add(2 * time.Hour)
	got, err := s.store.RetireKeypair(s.ctx, "old", at)
	s.Require().NoError(err)
	s.Equal("old", got.Kid)
	s.Require().NotNil(got.RetiredAt)
	s.True(at.Equal(*got.RetiredAt))

	again, err := s.store.RetireKeypair(s.ctx, "old", at.Add(time.Hour))
	s.Require().NoError(err, "retiring a retired key is a no-op")
	s.True(at.Equal(*again.RetiredAt), "a repeat retire keeps the first stamp")

	_, err = s.store.RetireKeypair(s.ctx, "new", at)
	s.Require().ErrorIs(err, keys.ErrLastActiveKeypair, "retired keys do not count as active")

	loaded, err := s.store.LoadKeypairs(s.ctx)
	s.Require().NoError(err)
	s.Require().Len(loaded, 2)
	s.Require().NotNil(loaded[0].RetiredAt)
	s.True(at.Equal(*loaded[0].RetiredAt))
	s.Nil(loaded[1].RetiredAt)
}
