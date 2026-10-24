package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"go.uber.org/zap"

	"github.com/onhotpath/tempogate/api/requestid"
	"github.com/onhotpath/tempogate/buildinfo"
)

// ClientSafeError is implemented by error types whose body may be written for
// the client, such as the RFC 6749 error shape with a fixed description. A
// 5xx whose ClientSafe reports true keeps its body (the request id is still
// in the X-Request-Id header) and is logged like any other.
type ClientSafeError interface {
	error
	ClientSafe() bool
}

// sanitizeServerErrors rewrites every 5xx error body to a generic message
// naming the request id, and logs the original detail under that id.
//
// Huma's default error model copies err.Error() of whatever a handler
// returned into the response, which for a storage failure means SQLite text
// and file paths sent to anonymous clients. A transformer is used instead of
// replacing huma.NewError because it is per-API (no package-global state
// shared across surfaces and tests) and it sees the request context, which
// carries the request id. 4xx bodies, including the OAuth error shape, pass
// through untouched: they are written for the caller.
func sanitizeServerErrors(logger *zap.Logger) huma.Transformer {
	return func(ctx huma.Context, _ string, v any) (any, error) {
		se, ok := v.(huma.StatusError)
		if !ok || se.GetStatus() < http.StatusInternalServerError {
			return v, nil
		}
		status := se.GetStatus()
		id := requestid.FromContext(ctx.Context())

		// The URL path only: the query string can carry codes and tokens.
		detail := errorDetail(se)
		logger.Error("request failed",
			zap.String("request_id", id),
			zap.Int("status", status),
			zap.String("method", ctx.Method()),
			zap.String("path", ctx.URL().Path),
			zap.String("error", detail),
		)
		recordServerError(ctx.Context(), detail)

		if cs, ok := v.(ClientSafeError); ok && cs.ClientSafe() {
			return v, nil
		}
		return &huma.ErrorModel{
			Status: status,
			Title:  http.StatusText(status),
			Detail: fmt.Sprintf("%s (request id %s)", strings.ToLower(http.StatusText(status)), id),
		}, nil
	}
}

// errorDetail flattens a Huma error model's detail and per-error messages,
// which is where Huma puts the wrapped handler error.
func errorDetail(se huma.StatusError) string {
	em, ok := se.(*huma.ErrorModel)
	if !ok {
		return se.Error()
	}
	parts := []string{em.Detail}
	for _, d := range em.Errors {
		if d != nil {
			parts = append(parts, d.Message)
		}
	}
	return strings.Join(parts, ": ")
}

// newHumaConfig builds a Huma config with the 5xx sanitizer installed ahead of
// Huma's own transformers, so the generic body still gets the usual $schema
// link.
func newHumaConfig(title string, logger *zap.Logger) huma.Config {
	c := huma.DefaultConfig(title, buildinfo.Version())
	c.Transformers = append([]huma.Transformer{sanitizeServerErrors(logger)}, c.Transformers...)
	return c
}
