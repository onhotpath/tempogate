//go:build e2e

// Acceptance proof of the device-flow hardening against the real container:
// a cross-site Referer cannot stand in for Origin on the approve POST,
// parallel /token polls are answered with slow_down, and user_code guessing
// is throttled per session and per client IP behind one uniform message.
// The subtests share one stack and run in order: the throttling ones go
// last because they spend the client IP's budget.
package e2e

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/onhotpath/tempogate/oidc"
)

const (
	deviceGrantType   = "urn:ietf:params:oauth:grant-type:device_code"
	rateLimitedMarker = "Too many attempts"
	crossSiteMarker   = "did not come from the expected page"
)

func TestDeviceFlowHardening(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e: skipped in -short")
	}
	ctx := context.Background()
	issuer, browser := setupDeviceStack(ctx, t, "")

	authorize := func(t *testing.T) (string, string) {
		t.Helper()
		resp, err := browser.PostForm(issuer+oidc.DeviceAuthorizationPath,
			url.Values{"client_id": {deviceClientID}, "scope": {"openid email"}})
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var da struct {
			DeviceCode string `json:"device_code"`
			UserCode   string `json:"user_code"`
		}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&da))
		return da.DeviceCode, da.UserCode
	}
	poll := func(t *testing.T, deviceCode string) (int, string) {
		t.Helper()
		resp, err := browser.PostForm(issuer+oidc.TokenPath, url.Values{
			"grant_type":  {deviceGrantType},
			"device_code": {deviceCode},
			"client_id":   {deviceClientID},
		})
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		var body struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		return resp.StatusCode, body.Error
	}
	submitCode := func(t *testing.T, c *http.Client, userCode string) (int, string) {
		t.Helper()
		resp, err := c.PostForm(issuer+oidc.DevicePath, url.Values{"user_code": {userCode}})
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		return resp.StatusCode, string(body)
	}

	t.Run("cross-site Referer without Origin is rejected on approve", func(t *testing.T) {
		deviceCode, userCode := authorize(t)
		csrf := openConfirmPage(t, browser, issuer, userCode)

		for _, referer := range []string{
			"http://tempogate:8000.evil.example/device/confirm",
			"http://tempogate:8000@evil.example/device/confirm",
		} {
			req := decisionRequest(ctx, t, issuer, userCode, "approve", csrf)
			req.Header.Set("Referer", referer)
			resp, err := browser.Do(req)
			require.NoError(t, err)
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			require.Containsf(t, string(body), crossSiteMarker, "Referer %s must not pass the same-origin check", referer)
		}
		status, oauthErr := poll(t, deviceCode)
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "authorization_pending", oauthErr, "a rejected cross-site POST must not approve the code")

		// The same-origin Referer a real browser sends still works.
		req := decisionRequest(ctx, t, issuer, userCode, "approve", csrf)
		req.Header.Set("Referer", issuer+oidc.DeviceConfirmPath+"?user_code="+url.QueryEscape(userCode))
		resp, err := browser.Do(req)
		require.NoError(t, err)
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		require.Containsf(t, string(body), "Device approved", "same-origin Referer must be accepted: %s", body)

		time.Sleep(6 * time.Second) // respect the 5 s poll interval
		status, oauthErr = poll(t, deviceCode)
		require.Equalf(t, http.StatusOK, status, "token after approve: %s", oauthErr)
	})

	t.Run("parallel polls get slow_down", func(t *testing.T) {
		deviceCode, _ := authorize(t)
		const polls = 16
		var (
			wg     sync.WaitGroup
			mu     sync.Mutex
			counts = map[string]int{}
			start  = make(chan struct{})
		)
		for range polls {
			wg.Go(func() {
				<-start
				_, oauthErr := poll(t, deviceCode)
				mu.Lock()
				counts[oauthErr]++
				mu.Unlock()
			})
		}
		close(start)
		wg.Wait()
		require.Equalf(t, polls, counts["slow_down"]+counts["authorization_pending"], "unexpected answers: %v", counts)
		require.LessOrEqualf(t, counts["authorization_pending"], 1,
			"at most one of %d parallel polls may be answered without slow_down: %v", polls, counts)
	})

	t.Run("user_code guessing is throttled per session with a uniform message", func(t *testing.T) {
		// A code the signed-in user denied is as unusable as one that never
		// existed; the page must not tell the two apart.
		_, denied := authorize(t)
		driveVerificationUI(ctx, t, browser, issuer, denied, "deny")

		status, deniedPage := submitCode(t, browser, denied)
		require.Equal(t, http.StatusOK, status)
		status, unknownPage := submitCode(t, browser, "BCDF-GHJK")
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, unknownPage, deniedPage, "a denied code and an unknown code must render the same page")

		failures := 2
		for ; failures < 10; failures++ {
			status, body := submitCode(t, browser, "BCDF-GHJK")
			if status == http.StatusTooManyRequests {
				require.Contains(t, body, rateLimitedMarker)
				break
			}
			require.Equal(t, http.StatusOK, status)
		}
		require.Equal(t, 5, failures, "the 6th failed guess from one session must be throttled")
	})

	t.Run("user_code guessing is throttled per client IP", func(t *testing.T) {
		_, pending := authorize(t)
		// A fresh browser has no session, so only the per-IP budget applies;
		// the previous subtest already spent part of it.
		stranger := *browser
		jar, err := cookiejar.New(nil)
		require.NoError(t, err)
		stranger.Jar = jar
		attempts := 0
		for ; attempts < 30; attempts++ {
			status, body := submitCode(t, &stranger, "BCDF-GHJK")
			if status == http.StatusTooManyRequests {
				require.Contains(t, body, rateLimitedMarker)
				break
			}
			require.Equal(t, http.StatusOK, status)
		}
		require.Less(t, attempts, 20, "per-IP throttle never engaged")

		// Once throttled, a live code gets the same 429 page: no oracle.
		status, body := submitCode(t, &stranger, pending)
		require.Equal(t, http.StatusTooManyRequests, status)
		require.Contains(t, body, rateLimitedMarker)
	})
}
