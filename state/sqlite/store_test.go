package sqlite

import (
	"context"
	"errors"
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
	s.Contains(err.Error(), "schema version 0, expected 9")
	s.Contains(err.Error(), "tempogate migrate")
}

func (s *StoreSuite) TestIsCurrentOnFreshDB() {
	fresh, err := New(WithPath(filepath.Join(s.T().TempDir(), "fresh.db")))
	s.Require().NoError(err)
	defer func() { _ = fresh.Close() }()

	err = fresh.IsCurrent(s.ctx)
	s.Require().Error(err)
	s.Contains(err.Error(), "schema version 0, expected 9")
}

func (s *StoreSuite) TestMigrateIsIdempotent() {
	s.Require().NoError(s.store.Migrate(s.ctx))
	s.Require().NoError(s.store.Migrate(s.ctx))

	var versions int
	row := s.store.db.QueryRowContext(s.ctx, `SELECT count(*) FROM schema_migrations`)
	s.Require().NoError(row.Scan(&versions))
	s.Equal(9, versions)

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
		`SELECT code, client_id, redirect_uri, email, scope,
		        code_challenge, code_challenge_method, nonce, created_at, expires_at
		 FROM auth_codes WHERE code = ?`, ac.Code)
	s.Require().NoError(row.Scan(
		&got.Code, &got.ClientID, &got.RedirectURI, &got.Email, &got.Scope,
		&got.CodeChallenge, &got.CodeChallengeMethod, &got.Nonce, &got.CreatedAt, &got.ExpiresAt,
	))

	s.Equal(ac.Code, got.Code)
	s.Equal(ac.ClientID, got.ClientID)
	s.Equal(ac.RedirectURI, got.RedirectURI)
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

	got, err := s.store.ConsumeAuthCode(s.ctx, ac.Code)
	s.Require().NoError(err)
	s.Equal(ac.Code, got.Code)
	s.Equal(ac.ClientID, got.ClientID)
	s.Equal(ac.RedirectURI, got.RedirectURI)
	s.Equal(ac.Email, got.Email)
	s.Equal(ac.Scope, got.Scope)
	s.Equal(ac.CodeChallenge, got.CodeChallenge)
	s.Equal(ac.CodeChallengeMethod, got.CodeChallengeMethod)
	s.Equal(ac.Nonce, got.Nonce)
	s.True(ac.CreatedAt.Equal(got.CreatedAt))
	s.True(ac.ExpiresAt.Equal(got.ExpiresAt))

	_, err = s.store.ConsumeAuthCode(s.ctx, ac.Code)
	s.Require().Error(err)
	s.Truef(errors.Is(err, oidc.ErrAuthCodeNotFound),
		"second consume should be ErrAuthCodeNotFound, got %v", err)

	var remaining int
	row := s.store.db.QueryRowContext(s.ctx,
		`SELECT count(*) FROM auth_codes WHERE code = ?`, ac.Code)
	s.Require().NoError(row.Scan(&remaining))
	s.Zero(remaining)
}

func (s *StoreSuite) TestConsumeAuthCodeNotFound() {
	_, err := s.store.ConsumeAuthCode(s.ctx, "never-saved")
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
		Email:     "alice@example.com",
		CreatedAt: now,
		ExpiresAt: now.Add(30 * 24 * time.Hour),
	}
}

func (s *StoreSuite) TestSaveRefreshRoundTrip() {
	r := s.refresh("refresh-1")
	s.Require().NoError(s.store.SaveRefresh(s.ctx, r))

	var got oidc.Refresh
	row := s.store.db.QueryRowContext(s.ctx,
		`SELECT token, jti, client_id, email, created_at, expires_at
		 FROM refresh_tokens WHERE token = ?`, r.Token)
	s.Require().NoError(row.Scan(
		&got.Token, &got.JTI, &got.ClientID, &got.Email, &got.CreatedAt, &got.ExpiresAt,
	))

	s.Equal(r.Token, got.Token)
	s.Equal(r.JTI, got.JTI)
	s.Equal(r.ClientID, got.ClientID)
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

	got, err := s.store.ConsumeRefresh(s.ctx, r.Token)
	s.Require().NoError(err)
	s.Equal(r.Token, got.Token)
	s.Equal(r.JTI, got.JTI)
	s.Equal(r.ClientID, got.ClientID)
	s.Equal(r.Email, got.Email)
	s.True(r.CreatedAt.Equal(got.CreatedAt))
	s.True(r.ExpiresAt.Equal(got.ExpiresAt))

	_, err = s.store.ConsumeRefresh(s.ctx, r.Token)
	s.Require().Error(err)
	s.Truef(errors.Is(err, oidc.ErrRefreshNotFound),
		"second consume should be ErrRefreshNotFound, got %v", err)

	var remaining int
	row := s.store.db.QueryRowContext(s.ctx,
		`SELECT count(*) FROM refresh_tokens WHERE token = ?`, r.Token)
	s.Require().NoError(row.Scan(&remaining))
	s.Zero(remaining)
}

func (s *StoreSuite) TestConsumeRefreshNotFound() {
	_, err := s.store.ConsumeRefresh(s.ctx, "never-saved")
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
			_, err := s.store.ConsumeAuthCode(s.ctx, "closed")
			return err
		}},
		{"SaveRefresh", func() error {
			return s.store.SaveRefresh(s.ctx, s.refresh("closed"))
		}},
		{"ConsumeRefresh", func() error {
			_, err := s.store.ConsumeRefresh(s.ctx, "closed")
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
		{"TouchDeviceCodePoll", func() error {
			return s.store.TouchDeviceCodePoll(s.ctx, "closed", time.Now().UTC(), false)
		}},
		{"ApproveDeviceCode", func() error {
			return s.store.ApproveDeviceCode(s.ctx, "CLOSEDUC", "alice@example.com", time.Now().UTC())
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
		asDeviceStr   oidc.DeviceCodeStore
		asBrowserSess oidc.BrowserSessionStore
	)
	a := fxtest.New(s.T(),
		config.Fx(),
		tlog.Fx(),
		Fx(),
		fx.Populate(&injected, &asDeviceStr, &asBrowserSess),
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
}
