package oidc_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/onhotpath/tempogate/oidc"
)

// TestDeviceCodeConcurrentPollsGetSlowDown: RFC 8628 §3.5 slow_down must
// hold against a client that fires its polls in parallel. Against the real
// sqlite store, N simultaneous polls inside one interval may produce at
// most one non-slow_down answer; the rest must be told to slow down.
func (s *TokenE2ESuite) TestDeviceCodeConcurrentPollsGetSlowDown() {
	now := time.Now().UTC()
	s.Require().NoError(s.store.SaveDeviceCode(s.T().Context(), oidc.DeviceCode{
		Code:            "race-device-code",
		UserCode:        "RRRRSSSS",
		ClientID:        "tempogate-device",
		Scope:           "openid email",
		IntervalSeconds: 5,
		CreatedAt:       now,
		ExpiresAt:       now.Add(10 * time.Minute),
	}))

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
			resp, err := http.PostForm(s.srv.URL+"/token", url.Values{
				"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
				"device_code": {"race-device-code"},
				"client_id":   {"tempogate-device"},
			})
			if err != nil {
				s.T().Error(err)
				return
			}
			defer resp.Body.Close()
			var body struct {
				Error string `json:"error"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&body)
			mu.Lock()
			counts[body.Error]++
			mu.Unlock()
		})
	}
	close(start)
	wg.Wait()

	s.Equal(polls, counts["slow_down"]+counts["authorization_pending"], "unexpected answers: %v", counts)
	s.LessOrEqualf(counts["authorization_pending"], 1,
		"at most one of %d parallel polls may be answered without slow_down: %v", polls, counts)
}
