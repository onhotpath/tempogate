package oidc_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/stretchr/testify/suite"

	"github.com/onhotpath/tempogate/oidc"
)

// fixedDeviceCode + fixedUserCode are the deterministic generator outputs the
// suite injects via functional options. UserCode is in its canonical (no
// dashes) form — the handler is responsible for formatting it as XXXX-XXXX
// in the wire response without ever mutating what it persisted.
const (
	fixedDeviceCode = "fixed-device-code-43chars-base64url-padding-x"
	fixedUserCode   = "BCDFGHJK"
)

var devNow = time.Unix(1700000000, 0).UTC()

// memDeviceCodeStore satisfies oidc.DeviceCodeStore structurally. Only the
// methods /device_authorization actually exercises are wired with state; the
// downstream handlers' methods are stubs that return ErrDeviceCodeNotFound so
// any drift from the contract surfaces immediately.
type memDeviceCodeStore struct {
	mu       sync.Mutex
	saved    []oidc.DeviceCode
	saveErr  error
	saveErrs []error // when non-nil, drained in order before falling back to saveErr
}

func (m *memDeviceCodeStore) SaveDeviceCode(_ context.Context, dc oidc.DeviceCode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.saveErrs) > 0 {
		err := m.saveErrs[0]
		m.saveErrs = m.saveErrs[1:]
		if err != nil {
			return err
		}
	} else if m.saveErr != nil {
		return m.saveErr
	}
	m.saved = append(m.saved, dc)
	return nil
}

func (m *memDeviceCodeStore) LookupDeviceCodeByDeviceCode(_ context.Context, _ string) (oidc.DeviceCode, error) {
	return oidc.DeviceCode{}, oidc.ErrDeviceCodeNotFound
}

func (m *memDeviceCodeStore) LookupDeviceCodeByUserCode(_ context.Context, _ string) (oidc.DeviceCode, error) {
	return oidc.DeviceCode{}, oidc.ErrDeviceCodeNotFound
}

func (m *memDeviceCodeStore) TouchDeviceCodePoll(_ context.Context, _ string, _ time.Time, _ bool) error {
	return oidc.ErrDeviceCodeNotFound
}

func (m *memDeviceCodeStore) ApproveDeviceCode(_ context.Context, _, _ string, _ time.Time) error {
	return oidc.ErrDeviceCodeNotPending
}

func (m *memDeviceCodeStore) DenyDeviceCode(_ context.Context, _ string, _ time.Time) error {
	return oidc.ErrDeviceCodeNotPending
}

func (m *memDeviceCodeStore) ConsumeDeviceCode(_ context.Context, _ string) (oidc.DeviceCode, error) {
	return oidc.DeviceCode{}, oidc.ErrDeviceCodeNotFound
}

func (m *memDeviceCodeStore) only() oidc.DeviceCode {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.saved[len(m.saved)-1]
}

func (m *memDeviceCodeStore) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.saved)
}

type DeviceAuthorizationSuite struct {
	suite.Suite

	store  *memDeviceCodeStore
	srv    *httptest.Server
	client *http.Client
}

func TestDeviceAuthorizationSuite(t *testing.T) {
	suite.Run(t, new(DeviceAuthorizationSuite))
}

func (s *DeviceAuthorizationSuite) SetupTest() {
	s.store = &memDeviceCodeStore{}
	s.srv = s.serverFor(s.store, testIssuer,
		oidc.WithDeviceAuthorizationClock(func() time.Time { return devNow }),
		oidc.WithDeviceCodeGenerator(func() (string, error) { return fixedDeviceCode, nil }),
		oidc.WithUserCodeGenerator(func() (string, error) { return fixedUserCode, nil }),
	)
	s.client = &http.Client{}
}

func (s *DeviceAuthorizationSuite) TearDownTest() {
	s.srv.Close()
}

// serverFor builds a /device_authorization server with `tempogate-device` as
// the registered public client and `webui` as a registered confidential one,
// so the "must be public" carve-out is exercised against the real registry.
func (s *DeviceAuthorizationSuite) serverFor(
	store oidc.DeviceCodeStore,
	issuer string,
	opts ...oidc.DeviceAuthorizationOption,
) *httptest.Server {
	reg, err := oidc.ParseClientRegistry("tempogate-device:cli,webui:" + testRedirectURI)
	s.Require().NoError(err)
	s.Require().NoError(reg.WithSecrets("webui:webui-secret"))

	h := oidc.NewDeviceAuthorization(store, reg, issuer, opts...)

	mux := http.NewServeMux()
	h.Register(humago.New(mux, huma.DefaultConfig("test", "0.0.0")))
	return httptest.NewServer(mux)
}

func (s *DeviceAuthorizationSuite) post(srv *httptest.Server, body string) *http.Response {
	resp, err := s.client.Post(srv.URL+"/device_authorization",
		"application/x-www-form-urlencoded",
		strings.NewReader(body))
	s.Require().NoError(err)
	return resp
}

func validDeviceForm() url.Values {
	f := url.Values{}
	f.Set("client_id", "tempogate-device")
	f.Set("scope", "openid email")
	return f
}

type deviceAuthorizationResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

func (s *DeviceAuthorizationSuite) decode(resp *http.Response) deviceAuthorizationResponse {
	var body deviceAuthorizationResponse
	s.Require().NoError(json.NewDecoder(resp.Body).Decode(&body))
	return body
}

func (s *DeviceAuthorizationSuite) decodeOAuthError(resp *http.Response) string {
	var body struct {
		Error string `json:"error"`
		Desc  string `json:"error_description"`
	}
	s.Require().NoError(json.NewDecoder(resp.Body).Decode(&body))
	s.NotEmpty(body.Desc, "every OAuth2 error must carry a description")
	return body.Error
}

// TestHappyPathReturnsRFC8628Shape is the acceptance proof: a request from
// `tempogate-device` yields the full §3.2 JSON shape, no-store headers, and a
// row persisted with the canonical (no-dashes) user_code while the response
// carries the dashed display form.
func (s *DeviceAuthorizationSuite) TestHappyPathReturnsRFC8628Shape() {
	resp := s.post(s.srv, validDeviceForm().Encode())
	defer resp.Body.Close()

	s.Require().Equal(http.StatusOK, resp.StatusCode)
	s.Equal("no-store", resp.Header.Get("Cache-Control"))
	s.Contains(resp.Header.Get("Content-Type"), "application/json")

	body := s.decode(resp)
	s.Equal(fixedDeviceCode, body.DeviceCode)
	s.Equal("BCDF-GHJK", body.UserCode, "wire form is the dashed display form")
	s.Equal(testIssuer+"/device", body.VerificationURI)
	s.Equal(testIssuer+"/device?user_code=BCDF-GHJK", body.VerificationURIComplete)
	s.Equal(900, body.ExpiresIn, "deviceCodeTTL is 15 minutes")
	s.Equal(5, body.Interval, "defaultPollInterval is the RFC 8628 §3.2 default of 5 seconds")

	s.Require().Equal(1, s.store.count())
	row := s.store.only()
	s.Equal(fixedDeviceCode, row.Code)
	s.Equal(fixedUserCode, row.UserCode, "row stores canonical (no dashes) form")
	s.Equal("tempogate-device", row.ClientID)
	s.Equal("openid email", row.Scope)
	s.Empty(row.Email)
	s.Nil(row.ApprovedAt)
	s.Nil(row.DeniedAt)
	s.Nil(row.LastPolledAt)
	s.Equal(5, row.IntervalSeconds)
	s.True(devNow.Equal(row.CreatedAt))
	s.Equal(15*time.Minute, row.ExpiresAt.Sub(row.CreatedAt))
}

// TestVerificationURIRespectsPathPrefix is the sub-path-hosting contract: a
// path-prefixed issuer (https://h/idp) must yield a /idp/device URL in the
// response, matching the precedent /authorize set for Google redirect_uri.
func (s *DeviceAuthorizationSuite) TestVerificationURIRespectsPathPrefix() {
	srv := s.serverFor(s.store, testIssuer+"/idp",
		oidc.WithDeviceAuthorizationClock(func() time.Time { return devNow }),
		oidc.WithDeviceCodeGenerator(func() (string, error) { return fixedDeviceCode, nil }),
		oidc.WithUserCodeGenerator(func() (string, error) { return fixedUserCode, nil }),
	)
	defer srv.Close()

	resp := s.post(srv, validDeviceForm().Encode())
	defer resp.Body.Close()

	s.Require().Equal(http.StatusOK, resp.StatusCode)
	body := s.decode(resp)
	s.Equal(testIssuer+"/idp/device", body.VerificationURI)
	s.Equal(testIssuer+"/idp/device?user_code=BCDF-GHJK", body.VerificationURIComplete)
}

// TestClientIDErrors covers the §3.1 client-validation error matrix: missing,
// unknown, and confidential all map to the right OAuth2 fields + statuses.
func (s *DeviceAuthorizationSuite) TestClientIDErrors() {
	cases := []struct {
		name     string
		clientID string
		wantCode string
		wantHTTP int
	}{
		{"missing client_id", "", "invalid_request", http.StatusBadRequest},
		{"unknown client_id", "some-other-client", "invalid_client", http.StatusUnauthorized},
		{"confidential client", "webui", "invalid_client", http.StatusUnauthorized},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			f := url.Values{}
			if tc.clientID != "" {
				f.Set("client_id", tc.clientID)
			} else {
				f.Set("filler", "x") // keep body non-empty
			}
			resp := s.post(s.srv, f.Encode())
			defer resp.Body.Close()

			s.Equal(tc.wantHTTP, resp.StatusCode)
			s.Equal(tc.wantCode, s.decodeOAuthError(resp))
			s.Zero(s.store.count(), "rejected requests must not persist a row")
		})
	}
}

// TestMalformedBodyIsInvalidRequest mirrors token_test.go's body-parse path:
// an unparseable application/x-www-form-urlencoded payload short-circuits to
// invalid_request without consulting the store.
func (s *DeviceAuthorizationSuite) TestMalformedBodyIsInvalidRequest() {
	resp := s.post(s.srv, "%zz=%")
	defer resp.Body.Close()

	s.Equal(http.StatusBadRequest, resp.StatusCode)
	s.Equal("invalid_request", s.decodeOAuthError(resp))
	s.Zero(s.store.count())
}

func (s *DeviceAuthorizationSuite) TestStoreFailureIsServerError() {
	s.store.saveErr = errors.New("disk full")
	resp := s.post(s.srv, validDeviceForm().Encode())
	defer resp.Body.Close()
	s.Equal(http.StatusInternalServerError, resp.StatusCode)
}

// TestUserCodeRegeneratesOnDuplicate proves the retry loop drives the
// user_code (and device_code, since regen is cheap) generators forward on a
// store-side UNIQUE collision. The first save returns a wrapped duplicate
// sentinel; the second succeeds, so the persisted row carries the *second*
// pair, not the first.
func (s *DeviceAuthorizationSuite) TestUserCodeRegeneratesOnDuplicate() {
	store := &memDeviceCodeStore{
		saveErrs: []error{
			// Wrap so the errors.Is path is exercised — the real store
			// returns its own typed sentinel that chains through this one.
			fmtErrorf("%w: wire collision", oidc.ErrDuplicateDeviceCode),
			nil,
		},
	}

	userCodes := []string{"AAAAAAAA", "BCDFGHJK"}
	deviceCodes := []string{"first-device-code", "second-device-code"}
	i := 0
	j := 0

	srv := s.serverFor(store, testIssuer,
		oidc.WithDeviceAuthorizationClock(func() time.Time { return devNow }),
		oidc.WithUserCodeGenerator(func() (string, error) {
			c := userCodes[i]
			i++
			return c, nil
		}),
		oidc.WithDeviceCodeGenerator(func() (string, error) {
			c := deviceCodes[j]
			j++
			return c, nil
		}),
	)
	defer srv.Close()

	resp := s.post(srv, validDeviceForm().Encode())
	defer resp.Body.Close()
	s.Require().Equal(http.StatusOK, resp.StatusCode)

	body := s.decode(resp)
	s.Equal("second-device-code", body.DeviceCode)
	s.Equal("BCDF-GHJK", body.UserCode)
	s.Require().Equal(1, store.count())
	s.Equal("BCDFGHJK", store.only().UserCode)
}

// TestUserCodeRetriesExhausted proves the retry loop has a hard cap: after
// userCodeMaxRetries collisions in a row, the handler gives up rather than
// looping forever, and the response is a server-side 5xx (the client did
// nothing wrong; the server failed to allocate a unique code).
func (s *DeviceAuthorizationSuite) TestUserCodeRetriesExhausted() {
	store := &memDeviceCodeStore{saveErr: fmtErrorf("%w: wire collision", oidc.ErrDuplicateDeviceCode)}

	srv := s.serverFor(store, testIssuer,
		oidc.WithDeviceAuthorizationClock(func() time.Time { return devNow }),
		oidc.WithDeviceCodeGenerator(func() (string, error) { return fixedDeviceCode, nil }),
		oidc.WithUserCodeGenerator(func() (string, error) { return fixedUserCode, nil }),
	)
	defer srv.Close()

	resp := s.post(srv, validDeviceForm().Encode())
	defer resp.Body.Close()
	s.Equal(http.StatusInternalServerError, resp.StatusCode)
	s.Zero(store.count())
}

// TestGeneratorFailureIsServerError covers the two crypto/rand-backed code
// paths: a failure inside either generator is a server_error, never a 4xx,
// since the client did nothing wrong.
func (s *DeviceAuthorizationSuite) TestGeneratorFailureIsServerError() {
	cases := []struct {
		name string
		opts []oidc.DeviceAuthorizationOption
	}{
		{
			"device_code generator fails",
			[]oidc.DeviceAuthorizationOption{
				oidc.WithDeviceAuthorizationClock(func() time.Time { return devNow }),
				oidc.WithDeviceCodeGenerator(func() (string, error) { return "", errors.New("rand fail") }),
				oidc.WithUserCodeGenerator(func() (string, error) { return fixedUserCode, nil }),
			},
		},
		{
			"user_code generator fails",
			[]oidc.DeviceAuthorizationOption{
				oidc.WithDeviceAuthorizationClock(func() time.Time { return devNow }),
				oidc.WithDeviceCodeGenerator(func() (string, error) { return fixedDeviceCode, nil }),
				oidc.WithUserCodeGenerator(func() (string, error) { return "", errors.New("rand fail") }),
			},
		},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			store := &memDeviceCodeStore{}
			srv := s.serverFor(store, testIssuer, tc.opts...)
			defer srv.Close()

			resp := s.post(srv, validDeviceForm().Encode())
			defer resp.Body.Close()
			s.Equal(http.StatusInternalServerError, resp.StatusCode)
			s.Zero(store.count())
		})
	}
}

// TestDefaultUserCodeGeneratorAlphabet exercises the production generator
// (no WithUserCodeGenerator override) and asserts every emitted character
// falls within the RFC 8628 §6.1-derived alphabet. Run enough times that a
// silent mis-pad of the rejection sampler (e.g. dropping the rejection step,
// allowing `%` modulo bias) shows up as an out-of-alphabet character with
// overwhelming probability.
func (s *DeviceAuthorizationSuite) TestDefaultUserCodeGeneratorAlphabet() {
	const alphabet = "BCDFGHJKLMNPQRSTVWXZ3479"
	allowed := make(map[byte]bool, len(alphabet))
	for i := 0; i < len(alphabet); i++ {
		allowed[alphabet[i]] = true
	}

	store := &memDeviceCodeStore{}
	srv := s.serverFor(store, testIssuer,
		oidc.WithDeviceAuthorizationClock(func() time.Time { return devNow }),
		oidc.WithDeviceCodeGenerator(func() (string, error) { return fixedDeviceCode, nil }),
	)
	defer srv.Close()

	const runs = 200
	seen := make(map[byte]int, len(alphabet))
	for i := 0; i < runs; i++ {
		store.mu.Lock()
		store.saved = nil
		store.mu.Unlock()

		resp := s.post(srv, validDeviceForm().Encode())
		body := s.decode(resp)
		resp.Body.Close()

		canonical := strings.ReplaceAll(body.UserCode, "-", "")
		s.Require().Lenf(canonical, 8, "user_code must be 8 characters (got %q)", body.UserCode)
		for j := 0; j < len(canonical); j++ {
			c := canonical[j]
			s.Truef(allowed[c], "user_code char %q not in alphabet (full code %q)", c, canonical)
			seen[c]++
		}
	}

	// Distribution sanity: 200 runs × 8 chars = 1,600 draws over 24
	// equiprobable buckets ⇒ expected ≈ 66 per bucket. A modulo-bias
	// regression (e.g., favouring the first few characters of the
	// alphabet) would leave at least one alphabet character with zero
	// draws or wildly skew the distribution. Assert every alphabet
	// character was emitted at least once — a weak but cheap canary.
	for i := 0; i < len(alphabet); i++ {
		c := alphabet[i]
		s.NotZerof(seen[c], "alphabet char %q never emitted across %d runs ⇒ likely rejection-sampling regression", c, runs)
	}
}

// TestDefaultDeviceCodeGeneratorEntropy exercises the production device_code
// generator (no WithDeviceCodeGenerator override) and asserts each emitted
// code decodes to exactly 32 bytes of entropy as base64url — the §3.2 32-byte
// shape promised by deviceCodeEntropyBytes.
func (s *DeviceAuthorizationSuite) TestDefaultDeviceCodeGeneratorEntropy() {
	store := &memDeviceCodeStore{}
	srv := s.serverFor(store, testIssuer,
		oidc.WithDeviceAuthorizationClock(func() time.Time { return devNow }),
		oidc.WithUserCodeGenerator(func() (string, error) { return fixedUserCode, nil }),
	)
	defer srv.Close()

	resp := s.post(srv, validDeviceForm().Encode())
	defer resp.Body.Close()
	s.Require().Equal(http.StatusOK, resp.StatusCode)
	body := s.decode(resp)

	raw, err := base64.RawURLEncoding.DecodeString(body.DeviceCode)
	s.Require().NoError(err)
	s.Len(raw, 32, "device_code must carry 32 bytes of entropy")
}

// fmtErrorf is a tiny indirection so the test stores can construct wrapped
// errors without importing fmt themselves — the wrapper exists only to
// exercise the handler's errors.Is path against the consumer-side sentinel.
func fmtErrorf(format string, args ...any) error {
	return fmt.Errorf(format, args...)
}
