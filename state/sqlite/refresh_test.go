package sqlite

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/onhotpath/tempogate/oidc"
)

// saveFamily saves a chain of tokens in one family, consuming all but the
// last, the way a session that rotated len(tokens)-1 times looks on disk.
func (s *StoreSuite) saveFamily(family, email string, tokens ...string) {
	for i, tok := range tokens {
		r := s.refresh(tok)
		r.FamilyID = family
		r.Email = email
		s.Require().NoError(s.store.SaveRefresh(s.ctx, r))
		if i < len(tokens)-1 {
			_, err := s.store.ConsumeRefresh(s.ctx, tok, r.ClientID, time.Now().UTC())
			s.Require().NoError(err)
		}
	}
}

func (s *StoreSuite) TestRevokeRefreshFamily() {
	s.saveFamily("fam-a", "alice@example.com", "a1", "a2")
	s.saveFamily("fam-b", "alice@example.com", "b1")

	n, err := s.store.RevokeRefreshFamily(s.ctx, "fam-a", time.Now().UTC())
	s.Require().NoError(err)
	s.Equal(1, n, "one live token (a2) was revoked")

	_, err = s.store.ConsumeRefresh(s.ctx, "a2", "ui", time.Now().UTC())
	s.Truef(errors.Is(err, oidc.ErrRefreshNotFound), "a revoked token is a plain miss, got %v", err)

	// The consumed tombstone still reports reuse after revocation.
	_, err = s.store.ConsumeRefresh(s.ctx, "a1", "ui", time.Now().UTC())
	s.Truef(errors.Is(err, oidc.ErrRefreshReused), "got %v", err)

	_, err = s.store.ConsumeRefresh(s.ctx, "b1", "ui", time.Now().UTC())
	s.NoError(err, "other families are untouched")

	n, err = s.store.RevokeRefreshFamily(s.ctx, "fam-a", time.Now().UTC())
	s.Require().NoError(err)
	s.Zero(n, "revoking twice revokes nothing new")
}

// TestSaveRefreshIntoRevokedFamilyFails closes the rotate-vs-revoke race: a
// rotation that consumed its parent before the family was revoked must not
// be able to persist the child afterwards.
func (s *StoreSuite) TestSaveRefreshIntoRevokedFamilyFails() {
	s.saveFamily("fam", "alice@example.com", "p")
	_, err := s.store.ConsumeRefresh(s.ctx, "p", "ui", time.Now().UTC())
	s.Require().NoError(err)

	_, err = s.store.RevokeRefreshFamily(s.ctx, "fam", time.Now().UTC())
	s.Require().NoError(err)

	child := s.refresh("child")
	child.FamilyID = "fam"
	err = s.store.SaveRefresh(s.ctx, child)
	s.Truef(errors.Is(err, oidc.ErrRefreshFamilyRevoked), "got %v", err)

	var n int
	s.Require().NoError(s.store.db.QueryRowContext(s.ctx,
		`SELECT count(*) FROM refresh_tokens WHERE token_hash = ?`, sha256Hex("child")).Scan(&n))
	s.Zero(n)
}

// TestConcurrentConsumeHasOneWinner: the conditional UPDATE is the single
// point of serialisation, so of N concurrent presentations of one live token
// exactly one rotates it and every other one is reported as reuse.
func (s *StoreSuite) TestConcurrentConsumeHasOneWinner() {
	s.saveFamily("fam", "alice@example.com", "hot")

	const n = 16
	var (
		wg              sync.WaitGroup
		mu              sync.Mutex
		wins, reuses    int
		unexpectedError error
	)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.store.ConsumeRefresh(s.ctx, "hot", "ui", time.Now().UTC())
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				wins++
			case errors.Is(err, oidc.ErrRefreshReused):
				reuses++
			default:
				unexpectedError = err
			}
		}()
	}
	wg.Wait()
	s.Require().NoError(unexpectedError)
	s.Equal(1, wins)
	s.Equal(n-1, reuses)
}

func (s *StoreSuite) TestRevokeRefreshByEmail() {
	s.saveFamily("fam-a", "alice@example.com", "a1", "a2")
	s.saveFamily("fam-b", "Alice@Example.com", "b1")
	s.saveFamily("fam-c", "carol@example.com", "c1")

	n, err := s.store.RevokeRefreshByEmail(s.ctx, "ALICE@example.com", time.Now().UTC())
	s.Require().NoError(err)
	s.Equal(2, n, "both of alice's sessions, matched case-insensitively")

	for _, tok := range []string{"a2", "b1"} {
		_, err = s.store.ConsumeRefresh(s.ctx, tok, "ui", time.Now().UTC())
		s.Truef(errors.Is(err, oidc.ErrRefreshNotFound), "%s: got %v", tok, err)
	}
	_, err = s.store.ConsumeRefresh(s.ctx, "c1", "ui", time.Now().UTC())
	s.NoError(err)
}

func (s *StoreSuite) TestListRefreshSessions() {
	now := time.Now().UTC()
	s.saveFamily("fam-a", "alice@example.com", "a1", "a2")
	s.saveFamily("fam-b", "bob@example.com", "b1")
	s.saveFamily("fam-revoked", "alice@example.com", "r1")
	_, err := s.store.RevokeRefreshFamily(s.ctx, "fam-revoked", now)
	s.Require().NoError(err)
	expired := s.refresh("e1")
	expired.FamilyID = "fam-expired"
	expired.ExpiresAt = now.Add(-time.Minute)
	s.Require().NoError(s.store.SaveRefresh(s.ctx, expired))

	all, err := s.store.ListRefreshSessions(s.ctx, "", now)
	s.Require().NoError(err)
	s.Require().Len(all, 2, "only live sessions: not revoked, not expired, one row per family")
	byFamily := map[string]RefreshSession{}
	for _, rs := range all {
		byFamily[rs.FamilyID] = rs
	}
	a := byFamily["fam-a"]
	s.Equal("alice@example.com", a.Email)
	s.Equal("google-sub-alice", a.Subject)
	s.Equal("ui", a.ClientID)
	s.True(a.AuthTime.Before(a.RotatedAt), "auth_time is the sign-in, before the last rotation")
	s.True(a.ExpiresAt.After(now))
	s.Contains(byFamily, "fam-b")

	alice, err := s.store.ListRefreshSessions(s.ctx, "ALICE@example.com", now)
	s.Require().NoError(err)
	s.Require().Len(alice, 1)
	s.Equal("fam-a", alice[0].FamilyID)
}

// TestMigration0011BackfillsRefreshLineage applies the migrations up to 0009
// (independent of whatever 0010 a parallel change adds), seeds refresh rows
// in the pre-0011 shape, then migrates to 0011 and checks the backfill: auth_time is
// the row's created_at (so existing sessions are capped at created_at +
// OIDC_REFRESH_MAX_LIFETIME) and every row gets its own family.
func TestMigration0011BackfillsRefreshLineage(t *testing.T) {
	ctx := context.Background()
	store, err := New(WithPath(filepath.Join(t.TempDir(), "legacy.db")))
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	migrateTo(t, store, 9)

	created := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	for _, tok := range []string{"legacy-1", "legacy-2"} {
		_, err = store.db.ExecContext(ctx,
			`INSERT INTO refresh_tokens (token, jti, client_id, email, created_at, expires_at)
			 VALUES (?, ?, 'tempogate-cli', 'alice@example.com', ?, ?)`,
			tok, "jti-"+tok, created, created.Add(30*24*time.Hour))
		require.NoError(t, err)
	}

	// Stop at 0011: 0012 drops refresh rows (they held raw tokens).
	migrateTo(t, store, 11)

	families := map[string]bool{}
	for _, tok := range []string{"legacy-1", "legacy-2"} {
		var (
			authTime time.Time
			familyID string
		)
		require.NoError(t, store.db.QueryRowContext(ctx,
			`SELECT auth_time, family_id FROM refresh_tokens WHERE token = ? AND consumed_at IS NULL`, tok,
		).Scan(&authTime, &familyID), "a backfilled row is live")
		require.True(t, authTime.Equal(created), "auth_time backfilled from created_at, got %s", authTime)
		require.NotEmpty(t, familyID)
		families[familyID] = true
	}
	require.Len(t, families, 2, "each legacy row is its own family")
}
