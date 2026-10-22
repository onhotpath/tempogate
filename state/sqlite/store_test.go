package sqlite

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"

	"github.com/onhotpath/tempogate/config"
	"github.com/onhotpath/tempogate/keys"
	tlog "github.com/onhotpath/tempogate/log"
	"github.com/onhotpath/tempogate/oidc"
)

type StoreSuite struct {
	suite.Suite

	ctx   context.Context
	store *Store
	path  string
}

func TestStoreSuite(t *testing.T) {
	suite.Run(t, new(StoreSuite))
}

func (s *StoreSuite) SetupTest() {
	s.ctx = context.Background()
	s.path = filepath.Join(s.T().TempDir(), "test.db")

	store, err := New(WithPath(s.path), WithBusyTimeout(time.Second))
	s.Require().NoError(err)
	s.Require().NoError(store.Migrate(s.ctx))

	s.store = store
}

func (s *StoreSuite) TearDownTest() {
	if s.store != nil {
		s.Require().NoError(s.store.Close())
		s.store = nil
	}
}

// latestVersion is the highest embedded migration, so schema assertions do
// not need editing whenever a migration lands.
func (s *StoreSuite) latestVersion() int {
	migs, err := loadMigrations()
	s.Require().NoError(err)
	return migs[len(migs)-1].version
}

func (s *StoreSuite) TestNewRejectsEmptyPath() {
	_, err := New(WithPath(""))
	s.Require().Error(err)
}

func (s *StoreSuite) TestIsCurrent() {
	// SetupTest already ran Migrate; current state should be clean.
	s.Require().NoError(s.store.IsCurrent(s.ctx))

	_, err := s.store.db.ExecContext(s.ctx, `DELETE FROM schema_migrations`)
	s.Require().NoError(err)

	err = s.store.IsCurrent(s.ctx)
	s.Require().Error(err)
	s.Contains(err.Error(), fmt.Sprintf("schema version 0, expected %d", s.latestVersion()))
	s.Contains(err.Error(), "tempogate migrate")
}

func (s *StoreSuite) TestIsCurrentRejectsGapBelowMax() {
	// Migrations merged out of numeric order leave a lower embedded version
	// unapplied while the max is recorded; MAX(version) alone hides that.
	_, err := s.store.db.ExecContext(s.ctx, `DELETE FROM schema_migrations WHERE version IN (3, 5)`)
	s.Require().NoError(err)

	err = s.store.IsCurrent(s.ctx)
	s.Require().Error(err)
	s.Contains(err.Error(), "schema is missing migrations 3, 5")
	s.Contains(err.Error(), "tempogate migrate")
}

func (s *StoreSuite) TestIsCurrentAllowsUnknownNewerVersions() {
	// A newer binary migrated this DB; an older binary must still serve.
	_, err := s.store.db.ExecContext(s.ctx,
		`INSERT INTO schema_migrations (version, name) VALUES (999, 'from_newer_binary')`)
	s.Require().NoError(err)

	s.Require().NoError(s.store.IsCurrent(s.ctx))
}

func (s *StoreSuite) TestIsCurrentOnFreshDB() {
	fresh, err := New(WithPath(filepath.Join(s.T().TempDir(), "fresh.db")))
	s.Require().NoError(err)
	defer func() { _ = fresh.Close() }()

	err = fresh.IsCurrent(s.ctx)
	s.Require().Error(err)
	s.Contains(err.Error(), fmt.Sprintf("schema version 0, expected %d", s.latestVersion()))
}

func (s *StoreSuite) TestMigrateIsIdempotent() {
	s.Require().NoError(s.store.Migrate(s.ctx))
	s.Require().NoError(s.store.Migrate(s.ctx))

	var versions int
	row := s.store.db.QueryRowContext(s.ctx, `SELECT count(*) FROM schema_migrations`)
	s.Require().NoError(row.Scan(&versions))
	migs, err := loadMigrations()
	s.Require().NoError(err)
	s.Equal(len(migs), versions, "each embedded migration is recorded exactly once")

	for _, want := range []string{"keypairs", "auth_requests", "auth_codes", "refresh_tokens", "integration_keys", "jti_denylist", "device_codes", "browser_sessions"} {
		var table string
		row = s.store.db.QueryRowContext(s.ctx,
			`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, want)
		s.Require().NoError(row.Scan(&table))
		s.Equal(want, table)
	}
}

func (s *StoreSuite) TestKeypairRoundTrip() {
	now := time.Now().UTC().Truncate(time.Microsecond)
	kp := func(kid string, offset time.Duration) keys.Keypair {
		return keys.Keypair{
			Kid:        kid,
			Alg:        "RS256",
			PrivatePEM: []byte("priv-" + kid),
			PublicPEM:  []byte("pub-" + kid),
			CreatedAt:  now.Add(offset),
		}
	}

	cases := []struct {
		name string
		save []keys.Keypair
	}{
		{"empty store returns nothing", nil},
		{"single keypair", []keys.Keypair{kp("kid-1", 0)}},
		{"multiple keypairs ordered by created_at", []keys.Keypair{
			kp("kid-a", 0),
			kp("kid-b", time.Second),
			kp("kid-c", 2*time.Second),
		}},
	}

	for _, tc := range cases {
		s.Run(tc.name, func() {
			s.SetupTest()
			defer s.TearDownTest()

			for _, kp := range tc.save {
				s.Require().NoError(s.store.SaveKeypair(s.ctx, kp))
			}

			got, err := s.store.LoadKeypairs(s.ctx)
			s.Require().NoError(err)
			s.Require().Len(got, len(tc.save))

			for i, want := range tc.save {
				s.Equal(want.Kid, got[i].Kid)
				s.Equal(want.Alg, got[i].Alg)
				s.Equal(want.PrivatePEM, got[i].PrivatePEM)
				s.Equal(want.PublicPEM, got[i].PublicPEM)
				s.True(want.CreatedAt.Equal(got[i].CreatedAt),
					"createdAt mismatch: want %v, got %v", want.CreatedAt, got[i].CreatedAt)
			}
		})
	}
}

func (s *StoreSuite) TestSaveKeypairDuplicateKid() {
	kp := keys.Keypair{
		Kid:        "kid-dup",
		Alg:        "RS256",
		PrivatePEM: []byte("priv"),
		PublicPEM:  []byte("pub"),
		CreatedAt:  time.Now().UTC().Truncate(time.Microsecond),
	}

	s.Require().NoError(s.store.SaveKeypair(s.ctx, kp))

	err := s.store.SaveKeypair(s.ctx, kp)
	s.Require().Error(err)
	s.Truef(errors.Is(err, ErrDuplicateKid),
		"expected ErrDuplicateKid, got %v", err)
}

func (s *StoreSuite) authRequest(internalState string) oidc.AuthRequest {
	now := time.Now().UTC().Truncate(time.Microsecond)
	return oidc.AuthRequest{
		InternalState:       internalState,
		ClientID:            "ui",
		RedirectURI:         "https://app.example.com/cb",
		Scope:               "openid email",
		ClientState:         "client-xyz",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
		Nonce:               "n-once",
		CreatedAt:           now,
		ExpiresAt:           now.Add(5 * time.Minute),
	}
}

func (s *StoreSuite) TestSaveAuthRequestRoundTrip() {
	ar := s.authRequest("istate-1")
	s.Require().NoError(s.store.SaveAuthRequest(s.ctx, ar))

	var got oidc.AuthRequest
	row := s.store.db.QueryRowContext(s.ctx,
		`SELECT internal_state, client_id, redirect_uri, scope, client_state,
		        code_challenge, code_challenge_method, nonce, created_at, expires_at
		 FROM auth_requests WHERE internal_state = ?`, ar.InternalState)
	s.Require().NoError(row.Scan(
		&got.InternalState, &got.ClientID, &got.RedirectURI, &got.Scope, &got.ClientState,
		&got.CodeChallenge, &got.CodeChallengeMethod, &got.Nonce, &got.CreatedAt, &got.ExpiresAt,
	))

	s.Equal(ar.InternalState, got.InternalState)
	s.Equal(ar.ClientID, got.ClientID)
	s.Equal(ar.RedirectURI, got.RedirectURI)
	s.Equal(ar.Scope, got.Scope)
	s.Equal(ar.ClientState, got.ClientState)
	s.Equal(ar.CodeChallenge, got.CodeChallenge)
	s.Equal(ar.CodeChallengeMethod, got.CodeChallengeMethod)
	s.Equal(ar.Nonce, got.Nonce)
	s.True(ar.CreatedAt.Equal(got.CreatedAt), "createdAt: want %v got %v", ar.CreatedAt, got.CreatedAt)
	s.True(ar.ExpiresAt.Equal(got.ExpiresAt), "expiresAt: want %v got %v", ar.ExpiresAt, got.ExpiresAt)
}

func (s *StoreSuite) TestSaveAuthRequestDuplicateInternalState() {
	ar := s.authRequest("dup-state")
	s.Require().NoError(s.store.SaveAuthRequest(s.ctx, ar))

	err := s.store.SaveAuthRequest(s.ctx, ar)
	s.Require().Error(err)
	s.Truef(errors.Is(err, ErrDuplicateInternalState),
		"expected ErrDuplicateInternalState, got %v", err)
}

func (s *StoreSuite) TestConsumeAuthRequestRoundTripAndSingleUse() {
	ar := s.authRequest("consume-1")
	s.Require().NoError(s.store.SaveAuthRequest(s.ctx, ar))

	got, err := s.store.ConsumeAuthRequest(s.ctx, ar.InternalState)
	s.Require().NoError(err)
	s.Equal(ar.InternalState, got.InternalState)
	s.Equal(ar.ClientID, got.ClientID)
	s.Equal(ar.RedirectURI, got.RedirectURI)
	s.Equal(ar.Scope, got.Scope)
	s.Equal(ar.ClientState, got.ClientState)
	s.Equal(ar.CodeChallenge, got.CodeChallenge)
	s.Equal(ar.CodeChallengeMethod, got.CodeChallengeMethod)
	s.Equal(ar.Nonce, got.Nonce)
	s.True(ar.CreatedAt.Equal(got.CreatedAt))
	s.True(ar.ExpiresAt.Equal(got.ExpiresAt))

	_, err = s.store.ConsumeAuthRequest(s.ctx, ar.InternalState)
	s.Require().Error(err)
	s.Truef(errors.Is(err, oidc.ErrAuthRequestNotFound),
		"second consume should be ErrAuthRequestNotFound, got %v", err)

	var remaining int
	row := s.store.db.QueryRowContext(s.ctx,
		`SELECT count(*) FROM auth_requests WHERE internal_state = ?`, ar.InternalState)
	s.Require().NoError(row.Scan(&remaining))
	s.Zero(remaining)
}

func (s *StoreSuite) TestConsumeAuthRequestNotFound() {
	_, err := s.store.ConsumeAuthRequest(s.ctx, "never-saved")
	s.Require().Error(err)
	s.Truef(errors.Is(err, oidc.ErrAuthRequestNotFound),
		"expected ErrAuthRequestNotFound, got %v", err)
}

func (s *StoreSuite) authCode(code string) oidc.AuthCode {
	now := time.Now().UTC().Truncate(time.Microsecond)
	return oidc.AuthCode{
		Code:                code,
		ClientID:            "ui",
		RedirectURI:         "https://app.example.com/cb",
		Subject:             "google-sub-alice",
		Email:               "alice@example.com",
		Scope:               "openid email",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
		Nonce:               "n-once",
		CreatedAt:           now,
		ExpiresAt:           now.Add(time.Minute),
	}
}

func (s *StoreSuite) TestSaveAuthCodeRoundTrip() {
	ac := s.authCode("code-1")
	s.Require().NoError(s.store.SaveAuthCode(s.ctx, ac))

	var got oidc.AuthCode
	row := s.store.db.QueryRowContext(s.ctx,
		`SELECT code_hash, client_id, redirect_uri, subject, email, scope,
		        code_challenge, code_challenge_method, nonce, created_at, expires_at
		 FROM auth_codes WHERE code_hash = ?`, sha256Hex(ac.Code))
	s.Require().NoError(row.Scan(
		&got.Code, &got.ClientID, &got.RedirectURI, &got.Subject, &got.Email, &got.Scope,
		&got.CodeChallenge, &got.CodeChallengeMethod, &got.Nonce, &got.CreatedAt, &got.ExpiresAt,
	))

	s.Equal(sha256Hex(ac.Code), got.Code, "only the code's hash is stored")
	s.Equal(ac.ClientID, got.ClientID)
	s.Equal(ac.RedirectURI, got.RedirectURI)
	s.Equal(ac.Subject, got.Subject)
	s.Equal(ac.Email, got.Email)
	s.Equal(ac.Scope, got.Scope)
	s.Equal(ac.CodeChallenge, got.CodeChallenge)
	s.Equal(ac.CodeChallengeMethod, got.CodeChallengeMethod)
	s.Equal(ac.Nonce, got.Nonce)
	s.True(ac.CreatedAt.Equal(got.CreatedAt), "createdAt: want %v got %v", ac.CreatedAt, got.CreatedAt)
	s.True(ac.ExpiresAt.Equal(got.ExpiresAt), "expiresAt: want %v got %v", ac.ExpiresAt, got.ExpiresAt)
}

func (s *StoreSuite) TestSaveAuthCodeDuplicate() {
	ac := s.authCode("dup-code")
	s.Require().NoError(s.store.SaveAuthCode(s.ctx, ac))

	err := s.store.SaveAuthCode(s.ctx, ac)
	s.Require().Error(err)
	s.Truef(errors.Is(err, ErrDuplicateAuthCode),
		"expected ErrDuplicateAuthCode, got %v", err)
}

func (s *StoreSuite) TestConsumeAuthCodeRoundTripAndSingleUse() {
	ac := s.authCode("consume-code-1")
	s.Require().NoError(s.store.SaveAuthCode(s.ctx, ac))

	at := ac.CreatedAt.Add(10 * time.Second)
	got, err := s.store.ConsumeAuthCode(s.ctx, ac.Code, "fam-1", at)
	s.Require().NoError(err)
	s.Equal(ac.Code, got.Code)
	s.Equal(ac.ClientID, got.ClientID)
	s.Equal(ac.RedirectURI, got.RedirectURI)
	s.Equal(ac.Subject, got.Subject)
	s.Equal(ac.Email, got.Email)
	s.Equal(ac.Scope, got.Scope)
	s.Equal(ac.CodeChallenge, got.CodeChallenge)
	s.Equal(ac.CodeChallengeMethod, got.CodeChallengeMethod)
	s.Equal(ac.Nonce, got.Nonce)
	s.Equal("fam-1", got.FamilyID)
	s.True(ac.CreatedAt.Equal(got.CreatedAt))
	s.True(ac.ExpiresAt.Equal(got.ExpiresAt))

	// A replay is refused and names the family the first redemption
	// started, so the caller can revoke what that redemption issued. The
	// replay's own family id is not recorded.
	again, err := s.store.ConsumeAuthCode(s.ctx, ac.Code, "fam-2", at.Add(time.Second))
	s.Require().ErrorIs(err, oidc.ErrAuthCodeReused)
	s.Equal("fam-1", again.FamilyID)
	s.Equal(ac.ClientID, again.ClientID)

	// The consumed code stays behind as a tombstone (until the reaper
	// removes it at expiry), still keyed by hash only.
	var familyID string
	var consumedAt time.Time
	row := s.store.db.QueryRowContext(s.ctx,
		`SELECT family_id, consumed_at FROM auth_codes WHERE code_hash = ?`, sha256Hex(ac.Code))
	s.Require().NoError(row.Scan(&familyID, &consumedAt))
	s.Equal("fam-1", familyID)
	s.True(at.Equal(consumedAt))
}

func (s *StoreSuite) TestConsumeAuthCodeNotFound() {
	_, err := s.store.ConsumeAuthCode(s.ctx, "never-saved", "fam", time.Now())
	s.Require().Error(err)
	s.Truef(errors.Is(err, oidc.ErrAuthCodeNotFound),
		"expected ErrAuthCodeNotFound, got %v", err)
}

func (s *StoreSuite) refresh(token string) oidc.Refresh {
	now := time.Now().UTC().Truncate(time.Microsecond)
	return oidc.Refresh{
		Token:     token,
		JTI:       "jti-" + token,
		ClientID:  "ui",
		Subject:   "google-sub-alice",
		Email:     "alice@example.com",
		FamilyID:  "family-" + token,
		AuthTime:  now.Add(-time.Hour),
		CreatedAt: now,
		ExpiresAt: now.Add(7 * 24 * time.Hour),
	}
}

func (s *StoreSuite) TestSaveRefreshRoundTrip() {
	r := s.refresh("refresh-1")
	s.Require().NoError(s.store.SaveRefresh(s.ctx, r))

	var got oidc.Refresh
	row := s.store.db.QueryRowContext(s.ctx,
		`SELECT token_hash, jti, client_id, subject, email, family_id, auth_time, created_at, expires_at
		 FROM refresh_tokens WHERE token_hash = ?`, sha256Hex(r.Token))
	s.Require().NoError(row.Scan(
		&got.Token, &got.JTI, &got.ClientID, &got.Subject, &got.Email, &got.FamilyID, &got.AuthTime, &got.CreatedAt, &got.ExpiresAt,
	))
	s.Equal(r.FamilyID, got.FamilyID)
	s.True(r.AuthTime.Equal(got.AuthTime), "authTime: want %v got %v", r.AuthTime, got.AuthTime)

	s.Equal(sha256Hex(r.Token), got.Token, "only the token's hash is stored")
	s.Equal(r.JTI, got.JTI)
	s.Equal(r.ClientID, got.ClientID)
	s.Equal(r.Subject, got.Subject)
	s.Equal(r.Email, got.Email)
	s.True(r.CreatedAt.Equal(got.CreatedAt), "createdAt: want %v got %v", r.CreatedAt, got.CreatedAt)
	s.True(r.ExpiresAt.Equal(got.ExpiresAt), "expiresAt: want %v got %v", r.ExpiresAt, got.ExpiresAt)
}

func (s *StoreSuite) TestSaveRefreshDuplicate() {
	r := s.refresh("dup-refresh")
	s.Require().NoError(s.store.SaveRefresh(s.ctx, r))

	err := s.store.SaveRefresh(s.ctx, r)
	s.Require().Error(err)
	s.Truef(errors.Is(err, ErrDuplicateRefreshToken),
		"expected ErrDuplicateRefreshToken, got %v", err)
}

func (s *StoreSuite) TestConsumeRefreshRoundTripAndRotation() {
	r := s.refresh("consume-refresh-1")
	s.Require().NoError(s.store.SaveRefresh(s.ctx, r))

	got, err := s.store.ConsumeRefresh(s.ctx, r.Token, r.ClientID, time.Now().UTC())
	s.Require().NoError(err)
	s.Equal(r.Token, got.Token)
	s.Equal(r.JTI, got.JTI)
	s.Equal(r.ClientID, got.ClientID)
	s.Equal(r.Subject, got.Subject)
	s.Equal(r.Email, got.Email)
	s.Equal(r.FamilyID, got.FamilyID)
	s.True(r.AuthTime.Equal(got.AuthTime))
	s.True(r.CreatedAt.Equal(got.CreatedAt))
	s.True(r.ExpiresAt.Equal(got.ExpiresAt))

	// The row stays behind as a tombstone, so a second presentation is
	// recognised as reuse and returns the row for family revocation.
	again, err := s.store.ConsumeRefresh(s.ctx, r.Token, r.ClientID, time.Now().UTC())
	s.Require().Error(err)
	s.Truef(errors.Is(err, oidc.ErrRefreshReused),
		"second consume should be ErrRefreshReused, got %v", err)
	s.Equal(r.FamilyID, again.FamilyID)
	s.Equal(r.Email, again.Email)

	var consumed int
	row := s.store.db.QueryRowContext(s.ctx,
		`SELECT count(*) FROM refresh_tokens WHERE token_hash = ? AND consumed_at IS NOT NULL`, sha256Hex(r.Token))
	s.Require().NoError(row.Scan(&consumed))
	s.Equal(1, consumed)
}

// TestConsumeRefreshOtherClientLeavesRow: the client binding is part of the
// single atomic DELETE, so a token presented by the wrong client is reported
// missing and stays redeemable by the client it was issued to.
func (s *StoreSuite) TestConsumeRefreshOtherClientLeavesRow() {
	r := s.refresh("bound-refresh")
	s.Require().NoError(s.store.SaveRefresh(s.ctx, r))

	_, err := s.store.ConsumeRefresh(s.ctx, r.Token, "someone-else", time.Now().UTC())
	s.Require().Error(err)
	s.Truef(errors.Is(err, oidc.ErrRefreshNotFound),
		"cross-client consume should be ErrRefreshNotFound, got %v", err)

	got, err := s.store.ConsumeRefresh(s.ctx, r.Token, r.ClientID, time.Now().UTC())
	s.Require().NoError(err)
	s.Equal(r.ClientID, got.ClientID)
}

func (s *StoreSuite) TestConsumeRefreshNotFound() {
	_, err := s.store.ConsumeRefresh(s.ctx, "never-saved", "ui", time.Now().UTC())
	s.Require().Error(err)
	s.Truef(errors.Is(err, oidc.ErrRefreshNotFound),
		"expected ErrRefreshNotFound, got %v", err)
}

func (s *StoreSuite) TestPingAfterClose() {
	store, err := New(WithPath(filepath.Join(s.T().TempDir(), "ping.db")))
	s.Require().NoError(err)
	s.Require().NoError(store.Ping(s.ctx))
	s.Require().NoError(store.Close())
	s.Require().Error(store.Ping(s.ctx))
}

func (s *StoreSuite) TestErrorsAfterClose() {
	s.Require().NoError(s.store.Close())

	cases := []struct {
		name string
		op   func() error
	}{
		{"SaveKeypair", func() error {
			return s.store.SaveKeypair(s.ctx, keys.Keypair{
				Kid: "x", Alg: "RS256", CreatedAt: time.Now().UTC(),
			})
		}},
		{"LoadKeypairs", func() error {
			_, err := s.store.LoadKeypairs(s.ctx)
			return err
		}},
		{"RetireKeypair", func() error {
			_, err := s.store.RetireKeypair(s.ctx, "x", time.Now().UTC())
			return err
		}},
		{"SaveAuthRequest", func() error {
			return s.store.SaveAuthRequest(s.ctx, s.authRequest("closed"))
		}},
		{"ConsumeAuthRequest", func() error {
			_, err := s.store.ConsumeAuthRequest(s.ctx, "closed")
			return err
		}},
		{"SaveAuthCode", func() error {
			return s.store.SaveAuthCode(s.ctx, s.authCode("closed"))
		}},
		{"ConsumeAuthCode", func() error {
			_, err := s.store.ConsumeAuthCode(s.ctx, "closed", "fam", time.Now())
			return err
		}},
		{"SaveRefresh", func() error {
			return s.store.SaveRefresh(s.ctx, s.refresh("closed"))
		}},
		{"ConsumeRefresh", func() error {
			_, err := s.store.ConsumeRefresh(s.ctx, "closed", "ui", time.Now().UTC())
			return err
		}},
		{"RevokeRefreshFamily", func() error {
			_, err := s.store.RevokeRefreshFamily(s.ctx, "closed", time.Now().UTC())
			return err
		}},
		{"RevokeRefreshByEmail", func() error {
			_, err := s.store.RevokeRefreshByEmail(s.ctx, "closed@example.com", time.Now().UTC())
			return err
		}},
		{"RevokeRefreshBySubject", func() error {
			_, err := s.store.RevokeRefreshBySubject(s.ctx, "closed", time.Now().UTC())
			return err
		}},
		{"ListRefreshSessions", func() error {
			_, err := s.store.ListRefreshSessions(s.ctx, RefreshSessionFilter{}, time.Now().UTC())
			return err
		}},
		{"SaveDeviceCode", func() error {
			return s.store.SaveDeviceCode(s.ctx, s.deviceCode("closed-dc", "CLOSEDDC"))
		}},
		{"LookupDeviceCodeByDeviceCode", func() error {
			_, err := s.store.LookupDeviceCodeByDeviceCode(s.ctx, "closed")
			return err
		}},
		{"LookupDeviceCodeByUserCode", func() error {
			_, err := s.store.LookupDeviceCodeByUserCode(s.ctx, "CLOSEDUC")
			return err
		}},
		{"PollDeviceCode", func() error {
			_, err := s.store.PollDeviceCode(s.ctx, "closed", time.Now().UTC())
			return err
		}},
		{"ApproveDeviceCode", func() error {
			return s.store.ApproveDeviceCode(s.ctx, "CLOSEDUC", oidc.Identity{Subject: "sub-alice", Email: "alice@example.com"}, time.Now().UTC())
		}},
		{"DenyDeviceCode", func() error {
			return s.store.DenyDeviceCode(s.ctx, "CLOSEDUC", time.Now().UTC())
		}},
		{"ConsumeDeviceCode", func() error {
			_, err := s.store.ConsumeDeviceCode(s.ctx, "closed")
			return err
		}},
		{"SaveBrowserSession", func() error {
			return s.store.SaveBrowserSession(s.ctx, s.browserSession("closed-sid"))
		}},
		{"LookupBrowserSession", func() error {
			_, err := s.store.LookupBrowserSession(s.ctx, "closed-sid")
			return err
		}},
		{"DeleteBrowserSession", func() error {
			return s.store.DeleteBrowserSession(s.ctx, "closed-sid")
		}},
		{"Migrate", func() error { return s.store.Migrate(s.ctx) }},
	}

	for _, tc := range cases {
		s.Run(tc.name, func() {
			err := tc.op()
			s.Require().Error(err)
			s.Falsef(errors.Is(err, ErrDuplicateKid),
				"closed-db error should not look like ErrDuplicateKid: %v", err)
		})
	}

	s.store = nil
}

func (s *StoreSuite) TestParseMigration() {
	cases := []struct {
		name    string
		fname   string
		wantErr bool
		wantVer int
	}{
		{"valid", "0001_keypairs.sql", false, 1},
		{"three digits", "042_foo.sql", false, 42},
		{"no underscore", "0001.sql", true, 0},
		{"underscore at start", "_keypairs.sql", true, 0},
		{"non-numeric prefix", "abcd_foo.sql", true, 0},
	}

	for _, tc := range cases {
		s.Run(tc.name, func() {
			m, err := parseMigration(tc.fname)
			if tc.wantErr {
				s.Require().Error(err)
				return
			}
			s.Require().NoError(err)
			s.Equal(tc.wantVer, m.version)
		})
	}
}

func (s *StoreSuite) TestFxRejectsEmptyPath() {
	app := fx.New(
		fx.NopLogger,
		fx.Supply(
			fx.Annotated{Name: "sqlite_path", Target: ""},
			fx.Annotated{Name: "sqlite_max_conns", Target: 1},
			fx.Annotated{Name: "sqlite_busy_timeout", Target: time.Second},
		),
		Fx(),
		fx.Invoke(func(*Store) {}),
	)
	s.Require().Error(app.Err())
}

func (s *StoreSuite) TestFxComposition() {
	path := filepath.Join(s.T().TempDir(), "fx.db")
	s.T().Setenv("STATE_SQLITE_PATH", path)
	s.T().Setenv("STATE_SQLITE_BUSY_TIMEOUT", "1s")
	s.T().Setenv("STATE_SQLITE_MAX_CONNS", "1")

	var (
		injected      *Store
		reaper        *Reaper
		asDeviceStr   oidc.DeviceCodeStore
		asBrowserSess oidc.BrowserSessionStore
	)
	a := fxtest.New(s.T(),
		config.Fx(),
		tlog.Fx(),
		Fx(),
		fx.Populate(&injected, &reaper, &asDeviceStr, &asBrowserSess),
	)
	a.RequireStart()
	defer a.RequireStop()

	s.Require().NotNil(injected)
	s.Require().NoError(injected.Migrate(s.ctx))
	// fx.As(new(oidc.DeviceCodeStore)) binding regression guard: the
	// composition root depends on this interface being satisfied by
	// *Store; a refactor that drops the binding would silently break
	// /device_authorization graph construction in production.
	s.Require().NotNil(asDeviceStr)
	// fx.As(new(oidc.BrowserSessionStore)) binding regression guard: the
	// composition root depends on this interface being satisfied by
	// *Store; a refactor that drops the binding would silently break
	// SessionManager graph construction in production.
	s.Require().NotNil(asBrowserSess)
	s.Require().NotNil(reaper)
	s.Equal(defaultReapInterval, reaper.interval, "STATE_REAPER_INTERVAL default reaches the reaper")
	s.Equal(7*24*time.Hour, reaper.refreshMaxLifetime, "OIDC_REFRESH_MAX_LIFETIME reaches the reaper")
}

func (s *StoreSuite) TestFxRejectsNegativeReaperInterval() {
	s.T().Setenv("STATE_SQLITE_PATH", filepath.Join(s.T().TempDir(), "fx.db"))
	s.T().Setenv("STATE_REAPER_INTERVAL", "-1m")
	app := fx.New(fx.NopLogger, config.Fx(), tlog.Fx(), Fx(), fx.Invoke(func(*Reaper) {}))
	s.Require().Error(app.Err())
	s.Contains(app.Err().Error(), "STATE_REAPER_INTERVAL")
}
