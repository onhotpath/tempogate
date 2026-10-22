package requestid_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/onhotpath/tempogate/api/requestid"
)

func TestMiddlewareStoresAndEchoesID(t *testing.T) {
	var seen string
	h := requestid.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = requestid.FromContext(r.Context())
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set(requestid.Header, "client-chosen")
	h.ServeHTTP(rec, req)

	require.NotEmpty(t, seen)
	assert.Equal(t, seen, rec.Header().Get(requestid.Header))
	assert.NotEqual(t, "client-chosen", seen, "a client-supplied id must not be trusted")
}

func TestFromContextOutsideMiddleware(t *testing.T) {
	assert.Empty(t, requestid.FromContext(context.Background()))
}
