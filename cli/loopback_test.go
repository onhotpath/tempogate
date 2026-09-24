package cli_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	"github.com/onhotpath/tempogate/cli"
)

var (
	fixedNow   = time.Unix(1700000000, 0).UTC()
	errBrowser = errors.New("simulated: no browser available")
	errGen     = errors.New("simulated: entropy source failed")
)

// mockIssuer stands in for a running tempogate: it answers /authorize and
// /token. Each handler is overridable so a single suite drives the happy path
// and every failure branch without forking the server. captured records what
// the CLI sent so the suite can assert PKCE, client_id, and the verifier.
type mockIssuer struct {
	srv *httptest.Server

	mu               sync.Mutex
	gotChallenge     string
	gotChallengeMeth string
	gotClientID      string
	gotVerifier      string
	gotRedirectURI   string
	gotGrantType     string

	authorize func(w http.ResponseWriter, r *http.Request, m *mockIssuer)
	token     func(w http.ResponseWriter, r *http.Request, m *mockIssuer)
}

func newMockIssuer() *mockIssuer {
	m := &mockIssuer{authorize: happyAuthorize, token: happyToken}
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		m.mu.Lock()
		m.gotChallenge = q.Get("code_challenge")
		m.gotChallengeMeth = q.Get("code_challenge_method")
		m.gotClientID = q.Get("client_id")
		m.gotRedirectURI = q.Get("redirect_uri")
		m.mu.Unlock()
		m.authorize(w, r, m)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		m.mu.Lock()
		m.gotVerifier = r.Form.Get("code_verifier")
		m.gotGrantType = r.Form.Get("grant_type")
		m.mu.Unlock()
		m.token(w, r, m)
	})
	m.srv = httptest.NewServer(mux)
	return m
}

func (m *mockIssuer) close() { m.srv.Close() }

// redirectBack 302s the headless browser to the CLI's loopback callback with
// the given query — the role tempogate's /callback/google plays for real.
func redirectBack(w http.ResponseWriter, r *http.Request, q url.Values) {
	redirectURI := r.URL.Query().Get("redirect_uri")
	http.Redirect(w, r, redirectURI+"?"+q.Encode(), http.StatusFound)
}

func happyAuthorize(w http.ResponseWriter, r *http.Request, _ *mockIssuer) {
	redirectBack(w, r, url.Values{
		"code":  {"auth-code-xyz"},
		"state": {r.URL.Query().Get("state")},
	})
}

func happyToken(w http.ResponseWriter, _ *http.Request, _ *mockIssuer) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":  "the.jwt.token",
		"refresh_token": "refresh-abc",
		"token_type":    "Bearer",
		"expires_in":    14400,
		"id_token":      "the.jwt.token",
	})
}

type LoopbackSuite struct {
	suite.Suite

	issuer *mockIssuer
}

func TestLoopbackSuite(t *testing.T) {
	suite.Run(t, new(LoopbackSuite))
}

func (s *LoopbackSuite) SetupTest() {
	s.issuer = newMockIssuer()
}

func (s *LoopbackSuite) TearDownTest() {
	s.issuer.close()
}

// headlessBrowser fetches the authorize URL on a redirect-following client,
// so the mock issuer's 302 lands on the loopback callback — the unit-test
// stand-in for a real browser, no Chrome required.
func headlessBrowser() func(string) error {
	client := &http.Client{Timeout: 5 * time.Second}
	return func(rawURL string) error {
		go func() {
			resp, err := client.Get(rawURL)
			if err == nil {
				_ = resp.Body.Close()
			}
		}()
		return nil
	}
}

func (s *LoopbackSuite) newFlow(opts ...cli.Option) *cli.Flow {
	base := []cli.Option{
		cli.WithIssuer(s.issuer.srv.URL),
		cli.WithOpenBrowser(headlessBrowser()),
		cli.WithClock(func() time.Time { return fixedNow }),
		cli.WithCallbackTimeout(5 * time.Second),
	}
	return cli.New(append(base, opts...)...)
}

func (s *LoopbackSuite) TestHappyPathReturnsTokenAndExpiry() {
	tok, err := s.newFlow().Run(context.Background())

	s.Require().NoError(err)
	s.Equal("the.jwt.token", tok.AccessToken)
	s.Equal("refresh-abc", tok.RefreshToken)
	s.Equal(fixedNow.Add(4*time.Hour), tok.ExpiresAt)

	s.Equal("authorization_code", s.issuer.gotGrantType)
	s.Equal("tempogate-cli", s.issuer.gotClientID, "default client_id")
}

func (s *LoopbackSuite) TestPKCEVerifierIsSpecCompliant() {
	_, err := s.newFlow().Run(context.Background())
	s.Require().NoError(err)

	v := s.issuer.gotVerifier
	s.GreaterOrEqual(len(v), 43, "RFC 7636 §4.1 minimum verifier length")
	s.LessOrEqual(len(v), 128, "RFC 7636 §4.1 maximum verifier length")

	s.Equal("S256", s.issuer.gotChallengeMeth)
	sum := sha256.Sum256([]byte(v))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	s.Equal(want, s.issuer.gotChallenge, "challenge must be BASE64URL(SHA256(verifier))")
}

func (s *LoopbackSuite) TestCustomClientIDIsSent() {
	_, err := s.newFlow(cli.WithClientID("my-cli")).Run(context.Background())
	s.Require().NoError(err)
	s.Equal("my-cli", s.issuer.gotClientID)
}

func (s *LoopbackSuite) TestStateMismatchAborts() {
	s.issuer.authorize = func(w http.ResponseWriter, r *http.Request, _ *mockIssuer) {
		redirectBack(w, r, url.Values{
			"code":  {"auth-code-xyz"},
			"state": {"forged-state"},
		})
	}

	_, err := s.newFlow().Run(context.Background())
	s.Require().Error(err)
	s.Contains(err.Error(), "state did not match")
}

func (s *LoopbackSuite) TestUpstreamErrorIsSurfaced() {
	s.issuer.authorize = func(w http.ResponseWriter, r *http.Request, _ *mockIssuer) {
		redirectBack(w, r, url.Values{
			"error":             {"access_denied"},
			"error_description": {"user declined consent"},
			"state":             {r.URL.Query().Get("state")},
		})
	}

	_, err := s.newFlow().Run(context.Background())
	s.Require().Error(err)
	s.Contains(err.Error(), "access_denied")
	s.Contains(err.Error(), "user declined consent")
}

func (s *LoopbackSuite) TestTokenEndpointErrorIsSurfaced() {
	s.issuer.token = func(w http.ResponseWriter, _ *http.Request, _ *mockIssuer) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_grant",
			"error_description": "PKCE verification failed",
		})
	}

	_, err := s.newFlow().Run(context.Background())
	s.Require().Error(err)
	s.Contains(err.Error(), "invalid_grant")
	s.Contains(err.Error(), "PKCE verification failed")
}

func (s *LoopbackSuite) TestCallbackTimeoutExits() {
	noop := func(string) error { return nil } // browser never returns a code

	_, err := s.newFlow(
		cli.WithOpenBrowser(noop),
		cli.WithCallbackTimeout(50*time.Millisecond),
	).Run(context.Background())

	s.Require().Error(err)
	s.Contains(err.Error(), "no authorization code received within")
}

func (s *LoopbackSuite) TestContextCancellationExits() {
	noop := func(string) error { return nil }
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()

	_, err := s.newFlow(
		cli.WithOpenBrowser(noop),
		cli.WithCallbackTimeout(5*time.Second),
	).Run(ctx)

	s.Require().Error(err)
	s.Contains(err.Error(), "login cancelled")
}

func (s *LoopbackSuite) TestMissingIssuerIsRejected() {
	_, err := cli.New().Run(context.Background())
	s.Require().Error(err)
	s.Contains(err.Error(), "issuer is required")
}

func (s *LoopbackSuite) TestOutputAndHTTPClientOptionsArePlumbed() {
	var out strings.Builder
	hb := headlessBrowser()

	tok, err := cli.New(
		cli.WithIssuer(s.issuer.srv.URL),
		cli.WithOpenBrowser(hb),
		cli.WithClock(func() time.Time { return fixedNow }),
		cli.WithCallbackTimeout(5*time.Second),
		cli.WithPort(0),
		cli.WithOutput(&out),
		cli.WithHTTPClient(s.issuer.srv.Client()),
	).Run(context.Background())

	s.Require().NoError(err)
	s.Equal("the.jwt.token", tok.AccessToken)
	s.Contains(out.String(), "Opening your browser")
}

func (s *LoopbackSuite) TestBrowserOpenErrorIsToleratedNotFatal() {
	var out strings.Builder
	hb := headlessBrowser()
	failingOpener := func(rawURL string) error {
		_ = hb(rawURL) // still drive the callback, as a manual open would
		return errBrowser
	}

	tok, err := s.newFlow(
		cli.WithOpenBrowser(failingOpener),
		cli.WithOutput(&out),
	).Run(context.Background())

	s.Require().NoError(err, "a failed browser launch must not abort the flow")
	s.Equal("the.jwt.token", tok.AccessToken)
	s.Contains(out.String(), "Could not open a browser automatically")
}

func (s *LoopbackSuite) TestInvalidPortFailsToBind() {
	_, err := s.newFlow(cli.WithPort(-1)).Run(context.Background())
	s.Require().Error(err)
	s.Contains(err.Error(), "bind loopback listener")
}

func (s *LoopbackSuite) TestCallbackWithoutCodeAborts() {
	s.issuer.authorize = func(w http.ResponseWriter, r *http.Request, _ *mockIssuer) {
		redirectBack(w, r, url.Values{"state": {r.URL.Query().Get("state")}})
	}

	_, err := s.newFlow().Run(context.Background())
	s.Require().Error(err)
	s.Contains(err.Error(), "no authorization code")
}

func (s *LoopbackSuite) TestTokenResponseWithoutAccessTokenIsRejected() {
	s.issuer.token = func(w http.ResponseWriter, _ *http.Request, _ *mockIssuer) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token_type":"Bearer","expires_in":14400}`))
	}

	_, err := s.newFlow().Run(context.Background())
	s.Require().Error(err)
	s.Contains(err.Error(), "no access_token")
}

func (s *LoopbackSuite) TestNonOAuthTokenErrorReportsStatus() {
	s.issuer.token = func(w http.ResponseWriter, _ *http.Request, _ *mockIssuer) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("upstream is down"))
	}

	_, err := s.newFlow().Run(context.Background())
	s.Require().Error(err)
	s.Contains(err.Error(), "HTTP 502")
}

func (s *LoopbackSuite) TestDefaultClockIsUsedWhenUnset() {
	// No WithClock: the production now() must run and yield an expiry ~4h out
	// (happyToken returns expires_in=14400).
	before := time.Now()
	tok, err := cli.New(
		cli.WithIssuer(s.issuer.srv.URL),
		cli.WithOpenBrowser(headlessBrowser()),
		cli.WithCallbackTimeout(5*time.Second),
	).Run(context.Background())
	after := time.Now()

	s.Require().NoError(err)
	s.WithinRange(tok.ExpiresAt,
		before.Add(4*time.Hour-2*time.Second),
		after.Add(4*time.Hour+2*time.Second))
}

func (s *LoopbackSuite) TestVerifierGenerationErrorAborts() {
	_, err := s.newFlow(
		cli.WithVerifierGenerator(func() (string, error) { return "", errGen }),
	).Run(context.Background())

	s.Require().Error(err)
	s.Contains(err.Error(), "generate PKCE verifier")
}

func (s *LoopbackSuite) TestStateGenerationErrorAborts() {
	_, err := s.newFlow(
		cli.WithStateGenerator(func() (string, error) { return "", errGen }),
	).Run(context.Background())

	s.Require().Error(err)
	s.Contains(err.Error(), "generate state")
}

func (s *LoopbackSuite) TestTokenEndpointConnectionErrorIsSurfaced() {
	s.issuer.token = func(w http.ResponseWriter, _ *http.Request, _ *mockIssuer) {
		hj, ok := w.(http.Hijacker)
		s.Require().True(ok)
		conn, _, hErr := hj.Hijack()
		s.Require().NoError(hErr)
		_ = conn.Close() // drop the POST mid-flight: Do returns an error
	}

	_, err := s.newFlow().Run(context.Background())
	s.Require().Error(err)
	s.Contains(err.Error(), "token request")
}

func (s *LoopbackSuite) TestMalformedTokenJSONIsRejected() {
	s.issuer.token = func(w http.ResponseWriter, _ *http.Request, _ *mockIssuer) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("<<< not json >>>"))
	}

	_, err := s.newFlow().Run(context.Background())
	s.Require().Error(err)
	s.Contains(err.Error(), "decode token response")
}

func (s *LoopbackSuite) TestLoopbackRedirectURIShape() {
	// The ephemeral default must still produce a 127.0.0.1 loopback callback
	// URI built from the actually-bound port, never a wildcard or hostname —
	// that is what tempogate's client-registry prefix is validated against.
	_, err := s.newFlow().Run(context.Background())
	s.Require().NoError(err)
	s.Regexp(`^http://127\.0\.0\.1:\d+/callback$`, s.issuer.gotRedirectURI)
}
