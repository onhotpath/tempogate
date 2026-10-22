// Package requestid tags every HTTP request with a server-generated id so a
// generic error shown to a client can be matched to the detailed log line an
// operator reads.
package requestid

import (
	"context"
	"crypto/rand"
	"net/http"
)

// Header carries the request id on every response.
const Header = "X-Request-Id"

type ctxKey struct{}

// Middleware assigns a fresh id to each request, stores it in the request
// context, and echoes it in the response Header. Any id the client sends is
// ignored: accepting it would let callers forge log correlation and smuggle
// arbitrary text into log lines.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := rand.Text()
		w.Header().Set(Header, id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, id)))
	})
}

// FromContext returns the request id Middleware stored, or "" outside it.
func FromContext(ctx context.Context) string {
	id, _ := ctx.Value(ctxKey{}).(string)
	return id
}
