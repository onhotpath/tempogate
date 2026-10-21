package sqlite

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/onhotpath/tempogate/oidc"
)

// device_codes_test.go extends StoreSuite with the RFC 8628 device-code
// contract: save → lookup (by both columns), approve/deny transitions, the
// server-enforced slow_down touch, and atomic consume on the token-mint path.
// SetupTest already migrates the embedded SQL, so each test starts from a
// clean schema and the real driver is exercised end-to-end.

func (s *StoreSuite) deviceCode(code, userCode string) oidc.DeviceCode {
	now := time.Now().UTC().Truncate(time.Microsecond)
	return oidc.DeviceCode{
		Code:            code,
		UserCode:        userCode,
		ClientID:        "tempogate-device",
		Scope:           "openid email",
		IntervalSeconds: 5,
		CreatedAt:       now,
		ExpiresAt:       now.Add(10 * time.Minute),
	}
}

func (s *StoreSuite) TestSaveDeviceCodeRoundTripByDeviceCode() {
	dc := s.deviceCode("dc-1", "BCDFGHJK")
	s.Require().NoError(s.store.SaveDeviceCode(s.ctx, dc))

	got, err := s.store.LookupDeviceCodeByDeviceCode(s.ctx, dc.Code)
	s.Require().NoError(err)
	s.Equal(dc.Code, got.Code)
	s.Equal(dc.UserCode, got.UserCode)
	s.Equal(dc.ClientID, got.ClientID)
	s.Equal(dc.Scope, got.Scope)
	s.Equal("", got.Email)
	s.Equal(5, got.IntervalSeconds)
	s.Nil(got.ApprovedAt)
	s.Nil(got.DeniedAt)
	s.Nil(got.LastPolledAt)
	s.True(dc.CreatedAt.Equal(got.CreatedAt))
	s.True(dc.ExpiresAt.Equal(got.ExpiresAt))
}

func (s *StoreSuite) TestLookupDeviceCodeByUserCodeReturnsSameRow() {
	dc := s.deviceCode("dc-2", "JKLMNPQR")
	s.Require().NoError(s.store.SaveDeviceCode(s.ctx, dc))

	got, err := s.store.LookupDeviceCodeByUserCode(s.ctx, dc.UserCode)
	s.Require().NoError(err)
	s.Equal(dc.Code, got.Code)
	s.Equal(dc.UserCode, got.UserCode)
}

func (s *StoreSuite) TestSaveDeviceCodeDuplicate() {
	dc := s.deviceCode("dup-dc", "QRSTVWXZ")
	s.Require().NoError(s.store.SaveDeviceCode(s.ctx, dc))

	err := s.store.SaveDeviceCode(s.ctx, dc)
	s.Require().Error(err)
	s.Truef(errors.Is(err, ErrDuplicateDeviceCode),
		"expected ErrDuplicateDeviceCode, got %v", err)
}

func (s *StoreSuite) TestLookupDeviceCodeByDeviceCodeUnknown() {
	_, err := s.store.LookupDeviceCodeByDeviceCode(s.ctx, "never-saved")
	s.Require().Error(err)
	s.Truef(errors.Is(err, ErrDeviceCodeNotFound),
		"expected ErrDeviceCodeNotFound, got %v", err)
}

func (s *StoreSuite) TestLookupDeviceCodeByUserCodeUnknown() {
	_, err := s.store.LookupDeviceCodeByUserCode(s.ctx, "NEVERSAVED")
	s.Require().Error(err)
	s.Truef(errors.Is(err, ErrDeviceCodeNotFound),
		"expected ErrDeviceCodeNotFound, got %v", err)
}

func (s *StoreSuite) TestPollDeviceCodeEnforcesInterval() {
	dc := s.deviceCode("dc-poll", "POLLPOLL")
	s.Require().NoError(s.store.SaveDeviceCode(s.ctx, dc))
	t0 := time.Now().UTC().Truncate(time.Microsecond)

	steps := []struct {
		name         string
		at           time.Time
		wantSlowDown bool
		wantInterval int
	}{
		{"first poll is never too fast", t0, false, 5},
		{"inside 5 s is slow_down and bumps", t0.Add(4 * time.Second), true, 10},
		{"inside the bumped 10 s is slow_down again", t0.Add(13 * time.Second), true, 15},
		{"after the interval is well-paced", t0.Add(29 * time.Second), false, 15},
	}
	for _, st := range steps {
		slowDown, err := s.store.PollDeviceCode(s.ctx, dc.Code, st.at)
		s.Require().NoError(err, st.name)
		s.Equal(st.wantSlowDown, slowDown, st.name)

		got, err := s.store.LookupDeviceCodeByDeviceCode(s.ctx, dc.Code)
		s.Require().NoError(err)
		s.Require().NotNil(got.LastPolledAt)
		s.True(st.at.Equal(*got.LastPolledAt), st.name)
		s.Equal(st.wantInterval, got.IntervalSeconds, st.name)
	}
}

func (s *StoreSuite) TestPollDeviceCodeUnknown() {
	_, err := s.store.PollDeviceCode(s.ctx, "never-saved", time.Now().UTC())
	s.Require().Error(err)
	s.Truef(errors.Is(err, ErrDeviceCodeNotFound),
		"expected ErrDeviceCodeNotFound, got %v", err)
}

func (s *StoreSuite) TestApproveDeviceCodeTransitionsRow() {
	dc := s.deviceCode("dc-approve", "APPROVEX")
	s.Require().NoError(s.store.SaveDeviceCode(s.ctx, dc))

	now := time.Now().UTC().Truncate(time.Microsecond)
	s.Require().NoError(s.store.ApproveDeviceCode(s.ctx, dc.UserCode, "alice@example.com", now))

	got, err := s.store.LookupDeviceCodeByUserCode(s.ctx, dc.UserCode)
	s.Require().NoError(err)
	s.Equal("alice@example.com", got.Email)
	s.Require().NotNil(got.ApprovedAt)
	s.True(now.Equal(*got.ApprovedAt))
	s.Nil(got.DeniedAt)
}

func (s *StoreSuite) TestApproveDeviceCodeAlreadyDecided() {
	cases := []struct {
		name string
		seed func(dc oidc.DeviceCode, now time.Time)
	}{
		{
			name: "already approved",
			seed: func(dc oidc.DeviceCode, now time.Time) {
				s.Require().NoError(s.store.ApproveDeviceCode(s.ctx, dc.UserCode, "first@example.com", now))
			},
		},
		{
			name: "already denied",
			seed: func(dc oidc.DeviceCode, now time.Time) {
				s.Require().NoError(s.store.DenyDeviceCode(s.ctx, dc.UserCode, now))
			},
		},
	}

	for _, tc := range cases {
		s.Run(tc.name, func() {
			s.SetupTest()
			defer s.TearDownTest()

			dc := s.deviceCode("dc-already-"+tc.name, "ALREADY"+tc.name[:1])
			s.Require().NoError(s.store.SaveDeviceCode(s.ctx, dc))
			now := time.Now().UTC().Truncate(time.Microsecond)
			tc.seed(dc, now)

			err := s.store.ApproveDeviceCode(s.ctx, dc.UserCode, "second@example.com", now.Add(time.Second))
			s.Require().Error(err)
			s.Truef(errors.Is(err, ErrDeviceCodeNotPending),
				"expected ErrDeviceCodeNotPending, got %v", err)
		})
	}
}

func (s *StoreSuite) TestApproveDeviceCodeUnknownUserCode() {
	now := time.Now().UTC().Truncate(time.Microsecond)
	err := s.store.ApproveDeviceCode(s.ctx, "NEVERSAVED", "alice@example.com", now)
	s.Require().Error(err)
	s.Truef(errors.Is(err, ErrDeviceCodeNotPending),
		"expected ErrDeviceCodeNotPending, got %v", err)
}

func (s *StoreSuite) TestDenyDeviceCodeTransitionsRow() {
	dc := s.deviceCode("dc-deny", "DENYDENY")
	s.Require().NoError(s.store.SaveDeviceCode(s.ctx, dc))

	now := time.Now().UTC().Truncate(time.Microsecond)
	s.Require().NoError(s.store.DenyDeviceCode(s.ctx, dc.UserCode, now))

	got, err := s.store.LookupDeviceCodeByUserCode(s.ctx, dc.UserCode)
	s.Require().NoError(err)
	s.Require().NotNil(got.DeniedAt)
	s.True(now.Equal(*got.DeniedAt))
	s.Nil(got.ApprovedAt)
}

func (s *StoreSuite) TestDenyDeviceCodeAlreadyDecided() {
	cases := []struct {
		name string
		seed func(dc oidc.DeviceCode, now time.Time)
	}{
		{
			name: "already approved",
			seed: func(dc oidc.DeviceCode, now time.Time) {
				s.Require().NoError(s.store.ApproveDeviceCode(s.ctx, dc.UserCode, "alice@example.com", now))
			},
		},
		{
			name: "already denied",
			seed: func(dc oidc.DeviceCode, now time.Time) {
				s.Require().NoError(s.store.DenyDeviceCode(s.ctx, dc.UserCode, now))
			},
		},
	}

	for _, tc := range cases {
		s.Run(tc.name, func() {
			s.SetupTest()
			defer s.TearDownTest()

			dc := s.deviceCode("dc-deny-already-"+tc.name, "DENYAL"+tc.name[:2])
			s.Require().NoError(s.store.SaveDeviceCode(s.ctx, dc))
			now := time.Now().UTC().Truncate(time.Microsecond)
			tc.seed(dc, now)

			err := s.store.DenyDeviceCode(s.ctx, dc.UserCode, now.Add(time.Second))
			s.Require().Error(err)
			s.Truef(errors.Is(err, ErrDeviceCodeNotPending),
				"expected ErrDeviceCodeNotPending, got %v", err)
		})
	}
}

func (s *StoreSuite) TestConsumeDeviceCodeRoundTripAndSingleUse() {
	dc := s.deviceCode("dc-consume", "CONSUMEX")
	s.Require().NoError(s.store.SaveDeviceCode(s.ctx, dc))

	approvedAt := time.Now().UTC().Truncate(time.Microsecond)
	s.Require().NoError(s.store.ApproveDeviceCode(s.ctx, dc.UserCode, "alice@example.com", approvedAt))

	got, err := s.store.ConsumeDeviceCode(s.ctx, dc.Code)
	s.Require().NoError(err)
	s.Equal(dc.Code, got.Code)
	s.Equal(dc.UserCode, got.UserCode)
	s.Equal("alice@example.com", got.Email)
	s.Require().NotNil(got.ApprovedAt)
	s.True(approvedAt.Equal(*got.ApprovedAt))

	var remaining int
	row := s.store.db.QueryRowContext(s.ctx,
		`SELECT count(*) FROM device_codes WHERE device_code = ?`, dc.Code)
	s.Require().NoError(row.Scan(&remaining))
	s.Zero(remaining)

	_, err = s.store.ConsumeDeviceCode(s.ctx, dc.Code)
	s.Require().Error(err)
	s.Truef(errors.Is(err, ErrDeviceCodeNotFound),
		"second consume should be ErrDeviceCodeNotFound, got %v", err)
}

func (s *StoreSuite) TestConsumeDeviceCodeUnknown() {
	_, err := s.store.ConsumeDeviceCode(s.ctx, "never-saved")
	s.Require().Error(err)
	s.Truef(errors.Is(err, ErrDeviceCodeNotFound),
		"expected ErrDeviceCodeNotFound, got %v", err)
}

// TestPollDeviceCodeConcurrentPollsGetOneAnswer is RFC 8628 §3.5 under
// parallel polling: N polls racing on one row inside a single interval must
// produce exactly one well-paced answer, every other poll is slow_down, and
// every slow_down bump lands. They must also serialise through the SQLite
// busy-timeout rather than deadlock.
func (s *StoreSuite) TestPollDeviceCodeConcurrentPollsGetOneAnswer() {
	dc := s.deviceCode("dc-concurrent", "CONCXX12")
	s.Require().NoError(s.store.SaveDeviceCode(s.ctx, dc))

	const n = 8
	ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
	defer cancel()

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		wellPace int
	)
	errCh := make(chan error, n)
	now := time.Now().UTC().Truncate(time.Microsecond)
	for range n {
		wg.Go(func() {
			slowDown, err := s.store.PollDeviceCode(ctx, dc.Code, now)
			if err != nil {
				errCh <- err
				return
			}
			if !slowDown {
				mu.Lock()
				wellPace++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		s.Require().NoError(err)
	}
	s.Equal(1, wellPace, "exactly one of %d parallel polls may pass as well-paced", n)

	got, err := s.store.LookupDeviceCodeByDeviceCode(s.ctx, dc.Code)
	s.Require().NoError(err)
	s.Equal(5+5*(n-1), got.IntervalSeconds, "every slow_down bump must land")
}

// TestDecideDeviceCodeRejectsExpiredRow: Approve and Deny refuse a row whose
// expires_at has passed, as defence in depth behind the /token expiry
// check. The row stays untouched so the polling client sees expired_token.
func (s *StoreSuite) TestDecideDeviceCodeRejectsExpiredRow() {
	decide := map[string]func(userCode string, now time.Time) error{
		"approve": func(userCode string, now time.Time) error {
			return s.store.ApproveDeviceCode(s.ctx, userCode, "alice@example.com", now)
		},
		"deny": func(userCode string, now time.Time) error {
			return s.store.DenyDeviceCode(s.ctx, userCode, now)
		},
	}
	for name, fn := range decide {
		s.Run(name, func() {
			s.SetupTest()
			defer s.TearDownTest()

			dc := s.deviceCode("dc-expired-"+name, "EXPIRED"+strings.ToUpper(name[:1]))
			s.Require().NoError(s.store.SaveDeviceCode(s.ctx, dc))

			for _, at := range []time.Time{dc.ExpiresAt, dc.ExpiresAt.Add(time.Second)} {
				err := fn(dc.UserCode, at)
				s.Require().Error(err)
				s.Truef(errors.Is(err, ErrDeviceCodeNotPending), "expected ErrDeviceCodeNotPending, got %v", err)
			}

			got, err := s.store.LookupDeviceCodeByUserCode(s.ctx, dc.UserCode)
			s.Require().NoError(err)
			s.Nil(got.ApprovedAt)
			s.Nil(got.DeniedAt)
			s.Empty(got.Email)
		})
	}
}
