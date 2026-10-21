package cli_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/onhotpath/tempogate/cli"
	"github.com/onhotpath/tempogate/oidc"
)

// redirectRig is an https issuer at https://issuer.internal whose endpoint at
// path answers with a 307 to target; every other path answers with a token
// (and device-code) response. Every name resolves to one of two
// local servers: issuer.internal:443 and other.internal:443 to the TLS
// issuer, issuer.internal:80 to a plain-http sink that counts what reaches it.
// A 307 makes Go's client re-send the POST body (refresh token, code,
// verifier) to the target, so the sink must see nothing.
type redirectRig struct {
	client    *http.Client
	issuer    string
	sinkHits  atomic.Int32
	otherHits atomic.Int32
}

const rigIssuer = "https://issuer.internal"

func newRedirectRig(t *testing.T, path, target string) *redirectRig {
	t.Helper()
	rig := &redirectRig{issuer: rigIssuer}

	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		rig.sinkHits.Add(1)
		writeRigToken(w)
	}))
	t.Cleanup(sink.Close)

	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "other.internal" {
			rig.otherHits.Add(1)
			writeRigToken(w)
			return
		}
		if r.URL.Path != path {
			writeRigToken(w)
			return
		}
		http.Redirect(w, r, target, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(tlsSrv.Close)

	tr := tlsSrv.Client().Transport.(*http.Transport).Clone()
	// The httptest certificate is issued for example.com; verify against it
	// whatever name the request used.
	tr.TLSClientConfig = &tls.Config{RootCAs: tr.TLSClientConfig.RootCAs, ServerName: "example.com", MinVersion: tls.VersionTLS12}
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dst := tlsSrv.Listener.Addr().String()
		if addr == "issuer.internal:80" {
			dst = sink.Listener.Addr().String()
		}
		return (&net.Dialer{}).DialContext(ctx, network, dst)
	}
	rig.client = &http.Client{Transport: tr, Timeout: 5 * time.Second}
	return rig
}

func writeRigToken(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": "leaked.access", "refresh_token": "r-new", "expires_in": 3600,
		"device_code": "dc", "user_code": "ABCD-EFGH", "verification_uri": "https://issuer.internal/device",
		"interval": 1,
	})
}

func (rig *redirectRig) refresh(t *testing.T, opts ...cli.RefreshOption) error {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token.json")
	require.NoError(t, cli.Save(path, cli.Token{
		AccessToken: "about.to.expire", RefreshToken: "r-old",
		ExpiresAt: time.Now().Add(-time.Minute), ClientID: "tempogate-cli",
	}))
	_, err := cli.EnsureFresh(context.Background(), path, rig.issuer,
		append([]cli.RefreshOption{cli.WithRefreshHTTPClient(rig.client)}, opts...)...)
	return err
}

// callbackBrowser plays the browser: it skips the issuer and lands straight on
// the loopback callback with a code, so the flow goes on to POST /token.
func callbackBrowser() func(string) error {
	return func(raw string) error {
		u, err := url.Parse(raw)
		if err != nil {
			return err
		}
		q := u.Query()
		cb := q.Get("redirect_uri") + "?" + url.Values{"code": {"c"}, "state": {q.Get("state")}}.Encode()
		go func() {
			resp, err := (&http.Client{Timeout: 5 * time.Second}).Get(cb)
			if err == nil {
				_ = resp.Body.Close()
			}
		}()
		return nil
	}
}

func TestRefreshRefusesRedirectToPlainHTTP(t *testing.T) {
	rig := newRedirectRig(t, oidc.TokenPath, "http://issuer.internal"+oidc.TokenPath)

	err := rig.refresh(t)
	require.ErrorIs(t, err, cli.ErrUnsafeRedirect)
	require.ErrorContains(t, err, "http://issuer.internal")
	require.Zero(t, rig.sinkHits.Load(), "the refresh token must not follow a redirect to plain http")
}

func TestRefreshInsecureAllowsRedirectToPlainHTTP(t *testing.T) {
	rig := newRedirectRig(t, oidc.TokenPath, "http://issuer.internal"+oidc.TokenPath)

	require.NoError(t, rig.refresh(t, cli.WithRefreshInsecure(true)))
	require.Equal(t, int32(1), rig.sinkHits.Load(), "--insecure covers the redirect the same as the issuer")
}

func TestRefreshRefusesRedirectToOtherHost(t *testing.T) {
	rig := newRedirectRig(t, oidc.TokenPath, "https://other.internal"+oidc.TokenPath)

	err := rig.refresh(t, cli.WithRefreshInsecure(true))
	require.ErrorIs(t, err, cli.ErrUnsafeRedirect)
	require.Zero(t, rig.otherHits.Load(), "the refresh token must not be re-sent to a host the user did not name")
}

func TestRefreshFollowsSameHostHTTPSRedirect(t *testing.T) {
	rig := newRedirectRig(t, oidc.TokenPath, "https://issuer.internal/landed")

	require.NoError(t, rig.refresh(t))
}

func TestLoginRefusesRedirectToPlainHTTP(t *testing.T) {
	rig := newRedirectRig(t, oidc.TokenPath, "http://issuer.internal"+oidc.TokenPath)

	_, err := cli.New(
		cli.WithIssuer(rig.issuer),
		cli.WithHTTPClient(rig.client),
		cli.WithOpenBrowser(callbackBrowser()),
		cli.WithCallbackTimeout(5*time.Second),
	).Run(context.Background())

	require.ErrorIs(t, err, cli.ErrUnsafeRedirect)
	require.Zero(t, rig.sinkHits.Load(), "the code and verifier must not follow a redirect to plain http")
}

func TestDeviceLoginRefusesRedirectToPlainHTTP(t *testing.T) {
	rig := newRedirectRig(t, oidc.DeviceAuthorizationPath, "http://issuer.internal"+oidc.DeviceAuthorizationPath)

	_, err := cli.NewDeviceFlow(
		cli.WithDeviceIssuer(rig.issuer),
		cli.WithDeviceHTTPClient(rig.client),
	).Run(context.Background())

	require.ErrorIs(t, err, cli.ErrUnsafeRedirect)
	require.Zero(t, rig.sinkHits.Load())
}

// A refused redirect while polling /token is terminal, not a transient
// network error to retry until the device code expires.
func TestDevicePollRefusesRedirectToPlainHTTP(t *testing.T) {
	rig := newRedirectRig(t, oidc.TokenPath, "http://issuer.internal"+oidc.TokenPath)

	_, err := cli.NewDeviceFlow(
		cli.WithDeviceIssuer(rig.issuer),
		cli.WithDeviceHTTPClient(rig.client),
		cli.WithDeviceSleep(func(context.Context, time.Duration) error { return nil }),
	).Run(context.Background())

	require.ErrorIs(t, err, cli.ErrUnsafeRedirect)
	require.Zero(t, rig.sinkHits.Load())
}

// The guard replaces net/http's default policy, so it keeps its loop limit.
func TestRefreshStopsSameHostRedirectLoop(t *testing.T) {
	rig := newRedirectRig(t, oidc.TokenPath, "https://issuer.internal"+oidc.TokenPath)

	require.ErrorContains(t, rig.refresh(t), "stopped after 10 redirects")
}

// A caller's own CheckRedirect still runs once the guard has passed the hop.
func TestRefreshKeepsCallerCheckRedirect(t *testing.T) {
	rig := newRedirectRig(t, oidc.TokenPath, "https://issuer.internal/landed")
	rig.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	require.ErrorContains(t, rig.refresh(t), "HTTP 307")
}
