package api_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/onhotpath/tempogate/api"
)

func newTestServer(t *testing.T, r *api.Readiness) (*httptest.Server, func()) {
	t.Helper()
	res := api.New(r)
	srv := httptest.NewServer(res.Public.Handler)
	return srv, srv.Close
}

func get(t *testing.T, url string) (int, []byte) {
	t.Helper()
	resp, err := http.Get(url)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, body
}

func TestHealthz_OK(t *testing.T) {
	t.Parallel()
	srv, cleanup := newTestServer(t, api.NewReadiness())
	defer cleanup()

	code, body := get(t, srv.URL+"/healthz")
	assert.Equal(t, http.StatusOK, code)

	var got struct {
		Status  string `json:"status"`
		Version string `json:"version"`
	}
	require.NoError(t, json.Unmarshal(body, &got))
	assert.Equal(t, "ok", got.Status)
	assert.NotEmpty(t, got.Version)
}

func TestReadyz_503BeforeMark_200After(t *testing.T) {
	t.Parallel()
	r := api.NewReadiness()
	srv, cleanup := newTestServer(t, r)
	defer cleanup()

	code, _ := get(t, srv.URL+"/readyz")
	assert.Equal(t, http.StatusServiceUnavailable, code, "should be 503 before Mark()")

	r.Mark()

	code, body := get(t, srv.URL+"/readyz")
	assert.Equal(t, http.StatusOK, code, "should be 200 after Mark()")

	var got struct {
		Status string `json:"status"`
	}
	require.NoError(t, json.Unmarshal(body, &got))
	assert.Equal(t, "ready", got.Status)
}
