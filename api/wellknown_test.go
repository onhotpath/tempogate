package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/suite"

	"github.com/onhotpath/tempogate/api"
	"github.com/onhotpath/tempogate/keys"
)

// memKeyStore satisfies keys.KeyStore structurally — the consumer-side
// interface convention means api_test owns its own stub.
type memKeyStore struct {
	mu  sync.Mutex
	kps []keys.Keypair
}

func (m *memKeyStore) SaveKeypair(_ context.Context, kp keys.Keypair) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.kps = append(m.kps, kp)
	return nil
}

func (m *memKeyStore) LoadKeypairs(_ context.Context) ([]keys.Keypair, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]keys.Keypair, len(m.kps))
	copy(out, m.kps)
	return out, nil
}

type WellKnownSuite struct {
	suite.Suite

	ctx    context.Context
	keys   *keys.Keys
	srv    *httptest.Server
	issuer string
}

func TestWellKnownSuite(t *testing.T) {
	suite.Run(t, new(WellKnownSuite))
}

func (s *WellKnownSuite) SetupTest() {
	s.ctx = context.Background()
	s.keys = keys.New(
		keys.WithStore(&memKeyStore{}),
		keys.WithGenerateOptions(keys.WithRSABits(2048)),
	)
	s.Require().NoError(s.keys.Init(s.ctx))

	// Bind the listener before constructing the API so the discovery doc's
	// issuer matches the URL go-oidc later fetches it from.
	srv := httptest.NewUnstartedServer(nil)
	s.issuer = "http://" + srv.Listener.Addr().String()
	res := api.New(api.NewReadiness(), api.WithWellKnown(s.keys, s.issuer))
	srv.Config.Handler = res.Public.Handler
	srv.Start()
	s.srv = srv
}

func (s *WellKnownSuite) TearDownTest() {
	s.srv.Close()
}

func (s *WellKnownSuite) activeKid() string {
	kp, err := s.keys.Latest()
	s.Require().NoError(err)
	return kp.Kid
}

func (s *WellKnownSuite) TestJWKSDocumentShape() {
	resp, err := http.Get(s.srv.URL + "/.well-known/jwks.json")
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Equal(http.StatusOK, resp.StatusCode)
	s.Contains(resp.Header.Get("Content-Type"), "application/json")
	s.Equal("public, max-age=300", resp.Header.Get("Cache-Control"))

	var doc struct {
		Keys []map[string]string `json:"keys"`
	}
	s.Require().NoError(json.NewDecoder(resp.Body).Decode(&doc))
	s.Require().Len(doc.Keys, 1)

	k := doc.Keys[0]
	s.Equal(s.activeKid(), k["kid"])
	s.Equal("RSA", k["kty"])
	s.Equal("sig", k["use"])
	s.Equal("RS256", k["alg"])
	s.NotEmpty(k["n"])
	s.NotEmpty(k["e"])
}

func (s *WellKnownSuite) TestOpenIDConfigurationIsFullyPopulated() {
	resp, err := http.Get(s.srv.URL + "/.well-known/openid-configuration")
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Equal(http.StatusOK, resp.StatusCode)
	s.Equal("public, max-age=300", resp.Header.Get("Cache-Control"))

	var doc struct {
		Issuer                           string   `json:"issuer"`
		AuthorizationEndpoint            string   `json:"authorization_endpoint"`
		TokenEndpoint                    string   `json:"token_endpoint"`
		UserinfoEndpoint                 string   `json:"userinfo_endpoint"`
		DeviceAuthorizationEndpoint      string   `json:"device_authorization_endpoint"`
		JwksURI                          string   `json:"jwks_uri"`
		ResponseTypesSupported           []string `json:"response_types_supported"`
		GrantTypesSupported              []string `json:"grant_types_supported"`
		CodeChallengeMethodsSupported    []string `json:"code_challenge_methods_supported"`
		ScopesSupported                  []string `json:"scopes_supported"`
		SubjectTypesSupported            []string `json:"subject_types_supported"`
		IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	}
	s.Require().NoError(json.NewDecoder(resp.Body).Decode(&doc))

	s.Equal(s.issuer, doc.Issuer)
	s.Equal(s.issuer+"/authorize", doc.AuthorizationEndpoint)
	s.Equal(s.issuer+"/token", doc.TokenEndpoint)
	s.Equal(s.issuer+"/userinfo", doc.UserinfoEndpoint)
	// RFC 8628 §4 — discovery metadata for the device authorization
	// endpoint, advertised here so CLI / SDK callers can discover it
	// without a hard-coded path.
	s.Equal(s.issuer+"/device_authorization", doc.DeviceAuthorizationEndpoint)
	s.Equal(s.issuer+"/.well-known/jwks.json", doc.JwksURI)
	s.Equal([]string{"code"}, doc.ResponseTypesSupported)
	// device_code grant is intentionally absent from grant_types_supported
	// until /token grows the device_code branch — advertising before then
	// would lie to RFC-conformant clients.
	s.Equal([]string{"authorization_code", "refresh_token"}, doc.GrantTypesSupported)
	s.Equal([]string{"S256"}, doc.CodeChallengeMethodsSupported)
	s.Equal([]string{"openid", "profile", "email"}, doc.ScopesSupported)
	s.Equal([]string{"public"}, doc.SubjectTypesSupported)
	s.Equal([]string{"RS256"}, doc.IDTokenSigningAlgValuesSupported)
}

// TestGoOIDCRemoteKeySetVerifiesMintedJWT is the acceptance criterion: a
// standard OIDC client library loads our JWKS by URL and verifies a JWT
// signed with the active private key; a tampered token is rejected.
func (s *WellKnownSuite) TestGoOIDCRemoteKeySetVerifiesMintedJWT() {
	signed := s.mintJWT(time.Now())

	keySet := oidc.NewRemoteKeySet(s.ctx, s.srv.URL+"/.well-known/jwks.json")
	payload, err := keySet.VerifySignature(s.ctx, signed)
	s.Require().NoError(err)
	s.NotEmpty(payload)

	_, err = keySet.VerifySignature(s.ctx, signed+"tampered")
	s.Require().Error(err)
}

// TestGoOIDCProviderDiscoveryAndVerify exercises the full client path:
// discover via /.well-known/openid-configuration, fetch JWKS via the
// advertised jwks_uri, and verify an ID-token-shaped JWT end to end.
func (s *WellKnownSuite) TestGoOIDCProviderDiscoveryAndVerify() {
	provider, err := oidc.NewProvider(s.ctx, s.issuer)
	s.Require().NoError(err)

	verifier := provider.Verifier(&oidc.Config{ClientID: "temporal"})
	idToken, err := verifier.Verify(s.ctx, s.mintJWT(time.Now()))
	s.Require().NoError(err)
	s.Equal("operator", idToken.Subject)
}

// mintJWT stands in for the not-yet-built signing helper: it signs an
// ID-token-shaped JWT with the active private key, stamping the kid header
// so relying parties can select the right JWKS entry.
func (s *WellKnownSuite) mintJWT(now time.Time) string {
	kp, err := s.keys.Latest()
	s.Require().NoError(err)

	privKey, err := jwk.ParseKey(kp.PrivatePEM, jwk.WithX509(true))
	s.Require().NoError(err)
	s.Require().NoError(privKey.Set(jwk.KeyIDKey, kp.Kid))

	tok, err := jwt.NewBuilder().
		Issuer(s.issuer).
		Subject("operator").
		Audience([]string{"temporal"}).
		IssuedAt(now).
		Expiration(now.Add(time.Hour)).
		Build()
	s.Require().NoError(err)

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), privKey))
	s.Require().NoError(err)
	return string(signed)
}
