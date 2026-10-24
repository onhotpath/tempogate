package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/onhotpath/tempogate/api/requestid"
	"github.com/onhotpath/tempogate/observe"
)

// Surface names, the tempogate.listener attribute of a server span.
const (
	surfacePublic = "public"
	surfaceAdmin  = "admin"
)

// untracedPaths are hit every few seconds per pod by kubelet probes and
// Prometheus scrapes; tracing them would drown the real traffic.
var untracedPaths = map[string]bool{
	"/healthz":       true,
	"/readyz":        true,
	"/admin/healthz": true,
	"/metrics":       true,
}

// traceRequests makes every request a trace: a server span, the root, that
// everything the handler does is a child of. It must wrap the mux itself:
// the mux records the matched pattern on the request it is handed, so this
// is the only layer that sees the pattern without re-deriving it from the
// raw path, which is request input and never recorded. Every request starts
// a new trace: the public listener faces the internet, and a caller-chosen
// traceparent would let it pick trace IDs and force sampling. Without a
// tracer it is not installed at all (see apiConfig.wrap).
func traceRequests(t observe.Tracer, surface string, mux http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if untracedPaths[r.URL.Path] {
			mux.ServeHTTP(w, r)
			return
		}
		method, name := knownMethod(r.Method)
		ctx, span := t.Start(r.Context(), name,
			observe.AsRoot(),
			observe.WithSpanKind(observe.SpanKindServer),
			observe.WithAttributes(
				observe.String("http.request.method", method),
				observe.String("tempogate.listener", surface),
				observe.String("tempogate.request_id", requestid.FromContext(r.Context())),
			))
		failure := &requestFailure{}
		ctx = context.WithValue(ctx, requestFailureKey{}, failure)
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		r = r.WithContext(ctx)
		defer func() {
			status := rec.status
			p := recover()
			if p != nil {
				// About to become a dropped connection or a 500 further
				// out; end the request as the failure it is.
				status = http.StatusInternalServerError
			}
			if path := routePath(r.Pattern); path != "" {
				span.SetName(name + " " + path)
				span.SetAttributes(observe.String("http.route", path))
			}
			span.SetAttributes(observe.Int("http.response.status_code", status))
			if status >= http.StatusInternalServerError {
				span.Fail(strconv.Itoa(status), failure.err)
			}
			span.End()
			if p != nil {
				panic(p)
			}
		}()
		mux.ServeHTTP(rec, r)
	})
}

// requestFailure carries the detail of a 5xx from the error sanitizer, which
// hides it from the client, to the request's span.
type requestFailure struct{ err error }

type requestFailureKey struct{}

// recordServerError hands detail to the request's span, if it is traced.
func recordServerError(ctx context.Context, detail string) {
	if f, ok := ctx.Value(requestFailureKey{}).(*requestFailure); ok {
		f.err = errors.New(detail)
	}
}

// knownMethods are the methods the semantic conventions name; any other is
// raw request input and is recorded as _OTHER.
var knownMethods = map[string]bool{
	"CONNECT": true, "DELETE": true, "GET": true, "HEAD": true, "OPTIONS": true,
	"PATCH": true, "POST": true, "PUT": true, "TRACE": true,
}

// knownMethod returns the http.request.method value and the span name
// prefix for method.
func knownMethod(method string) (attr, name string) {
	if knownMethods[method] {
		return method, method
	}
	return "_OTHER", "HTTP"
}

// routePath strips the method from a ServeMux pattern ("POST /token"); the
// rest is a route template from tempogate's code, never the raw path.
func routePath(pattern string) string {
	if _, path, ok := strings.Cut(pattern, " "); ok {
		return path
	}
	return pattern
}

type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusRecorder) WriteHeader(code int) {
	// 1xx responses are interim; the final status comes later.
	if !s.wroteHeader && code >= http.StatusOK {
		s.status, s.wroteHeader = code, true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	s.wroteHeader = true
	return s.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the underlying writer (Flush,
// deadlines) through the recorder.
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }
