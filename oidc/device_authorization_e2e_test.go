package oidc_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	"github.com/onhotpath/tempogate/api"
	"github.com/onhotpath/tempogate/keys"
	"github.com/onhotpath/tempogate/oidc"
	"github.com/onhotpath/tempogate/state/sqlite"
)

// DeviceAuthorizationE2ESuite exercises POST /device_authorization against
// the real HTTP surface, a real sqlite store, and the discovery document the
// server actually publishes. No fakes for the store or the response shape.
type DeviceAuthorizationE2ESuite struct {
	suite.Suite

	store  *sqlite.Store
	keys   *keys.Keys
	srv    *httptest.Server
	client *http.Client
	issuer string
}

func TestDeviceAuthorizationE2ESuite(t *testing.T) {
	suite.Run(t, new(DeviceAuthorizationE2ESuite))
}

func (s *DeviceAuthorizationE2ESuite) SetupTest() {
	ctx := context.Background()

	store, err := sqlite.New(sqlite.WithPath(filepath.Join(s.T().TempDir(), "device-e2e.db")))
	s.Require().NoError(err)
	s.Require().NoError(store.Migrate(ctx))
	s.T().Cleanup(func() { _ = store.Close() })
	s.store = store

	s.keys = keys.New(keys.WithStore(store), keys.WithGenerateOptions(keys.WithRSABits(2048)))
	s.Require().NoError(s.keys.Init(ctx))

	reg, err := oidc.ParseClientRegistry("tempogate-device:cli")
	s.Require().NoError(err)

	s.issuer = testIssuer
	device := oidc.NewDeviceAuthorization(store, reg, s.issuer)

	result := api.New(api.NewReadiness(),
		api.WithWellKnown(s.keys, s.issuer),
		api.WithRegistrar(device.Register),
	)
	s.srv = httptest.NewServer(result.Public.Handler)
	s.T().Cleanup(s.srv.Close)
	s.client = &http.Client{}
}

func (s *DeviceAuthorizationE2ESuite) post(body url.Values) *http.Response {
	resp, err := s.client.Post(s.srv.URL+"/device_authorization",
		"application/x-www-form-urlencoded",
		strings.NewReader(body.Encode()))
	s.Require().NoError(err)
	return resp
}

// TestRoundTripAgainstRealStoreAndDiscovery proves that a fresh POST
// persists a row the underlying sqlite store can look up by either index,
// and that the verification_uri matches what the discovery document points
// callers at — the two cannot drift because they both pull from oidc.DevicePath.
func (s *DeviceAuthorizationE2ESuite) TestRoundTripAgainstRealStoreAndDiscovery() {
	resp := s.post(url.Values{
		"client_id": {"tempogate-device"},
		"scope":     {"openid email"},
	})
	defer resp.Body.Close()

	s.Require().Equal(http.StatusOK, resp.StatusCode)
	s.Equal("no-store", resp.Header.Get("Cache-Control"))

	var body struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int    `json:"expires_in"`
		Interval                int    `json:"interval"`
	}
	s.Require().NoError(json.NewDecoder(resp.Body).Decode(&body))
	s.NotEmpty(body.DeviceCode)
	s.Regexp(`^[BCDFGHJKLMNPQRSTVWXZ3479]{4}-[BCDFGHJKLMNPQRSTVWXZ3479]{4}$`, body.UserCode)
	s.Equal(s.issuer+"/device", body.VerificationURI)
	s.Equal(900, body.ExpiresIn)
	s.Equal(5, body.Interval)

	// Underlying row is reachable by device_code (the poll path E9.4 will
	// take) and by canonical user_code (the verification page path E9.5
	// will take). Both lookups have to resolve to the same row, otherwise
	// the §3.4 poll and the §3.3 verification page cannot share state.
	canonical := strings.ReplaceAll(body.UserCode, "-", "")

	byDevice, err := s.store.LookupDeviceCodeByDeviceCode(context.Background(), body.DeviceCode)
	s.Require().NoError(err)
	s.Equal("tempogate-device", byDevice.ClientID)
	s.Equal("openid email", byDevice.Scope)
	s.Equal(canonical, byDevice.UserCode)

	byUser, err := s.store.LookupDeviceCodeByUserCode(context.Background(), canonical)
	s.Require().NoError(err)
	s.Equal(body.DeviceCode, byUser.Code)

	// Discovery doc must point at the very path the response advertises.
	discResp, err := s.client.Get(s.srv.URL + "/.well-known/openid-configuration")
	s.Require().NoError(err)
	defer discResp.Body.Close()
	var disc struct {
		DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
	}
	s.Require().NoError(json.NewDecoder(discResp.Body).Decode(&disc))
	s.Equal(s.issuer+"/device_authorization", disc.DeviceAuthorizationEndpoint)
}

// TestPathPrefixedIssuerRoundTrip is the sub-path-hosting contract under a
// real server: an issuer with a /idp path component must yield a
// /idp/device verification URL and the discovery document must agree.
func (s *DeviceAuthorizationE2ESuite) TestPathPrefixedIssuerRoundTrip() {
	prefixedIssuer := s.issuer + "/idp"

	store, err := sqlite.New(sqlite.WithPath(filepath.Join(s.T().TempDir(), "device-prefix.db")))
	s.Require().NoError(err)
	s.Require().NoError(store.Migrate(context.Background()))
	defer store.Close()

	k := keys.New(keys.WithStore(store), keys.WithGenerateOptions(keys.WithRSABits(2048)))
	s.Require().NoError(k.Init(context.Background()))

	reg, err := oidc.ParseClientRegistry("tempogate-device:cli")
	s.Require().NoError(err)

	device := oidc.NewDeviceAuthorization(store, reg, prefixedIssuer)
	result := api.New(api.NewReadiness(),
		api.WithBasePath("/idp"),
		api.WithWellKnown(k, prefixedIssuer),
		api.WithRegistrar(device.Register),
	)
	srv := httptest.NewServer(result.Public.Handler)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/idp/device_authorization",
		"application/x-www-form-urlencoded",
		strings.NewReader("client_id=tempogate-device"))
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusOK, resp.StatusCode)

	var body struct {
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
	}
	s.Require().NoError(json.NewDecoder(resp.Body).Decode(&body))
	s.Equal(prefixedIssuer+"/device", body.VerificationURI)
	s.True(strings.HasPrefix(body.VerificationURIComplete, prefixedIssuer+"/device?user_code="),
		"verification_uri_complete must carry the same prefix as verification_uri (got %q)", body.VerificationURIComplete)

	discResp, err := http.Get(srv.URL + "/idp/.well-known/openid-configuration")
	s.Require().NoError(err)
	defer discResp.Body.Close()
	var disc struct {
		DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
	}
	s.Require().NoError(json.NewDecoder(discResp.Body).Decode(&disc))
	s.Equal(prefixedIssuer+"/device_authorization", disc.DeviceAuthorizationEndpoint)
}

// TestExpiresInMatchesAdvertisedTTL guards against a regression where
// expires_in and the row's expires_at drift: a relying party that respects
// expires_in would treat a row as live for the advertised window, so the
// row must outlive that window on disk.
func (s *DeviceAuthorizationE2ESuite) TestExpiresInMatchesAdvertisedTTL() {
	start := time.Now().UTC()
	resp := s.post(url.Values{"client_id": {"tempogate-device"}})
	defer resp.Body.Close()
	s.Require().Equal(http.StatusOK, resp.StatusCode)

	var body struct {
		DeviceCode string `json:"device_code"`
		ExpiresIn  int    `json:"expires_in"`
	}
	s.Require().NoError(json.NewDecoder(resp.Body).Decode(&body))

	row, err := s.store.LookupDeviceCodeByDeviceCode(context.Background(), body.DeviceCode)
	s.Require().NoError(err)
	advertised := start.Add(time.Duration(body.ExpiresIn) * time.Second)
	s.WithinDuration(advertised, row.ExpiresAt, time.Second,
		"row expiry must match the expires_in window the client was promised")
}
