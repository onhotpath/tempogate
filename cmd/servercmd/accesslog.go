package servercmd

import (
	"net/http"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// requestIDHeader is read from the response after the handler ran, so a
// request-id middleware further in can set it without this one depending on
// it.
const requestIDHeader = "X-Request-Id"

// quietPaths are hit every few seconds per pod by kubelet probes and
// Prometheus scrapes; at info they would drown the real traffic.
var quietPaths = map[string]bool{
	"/healthz":       true,
	"/readyz":        true,
	"/admin/healthz": true,
	"/metrics":       true,
}

// accessLog emits one structured line per request. It must stay the
// outermost handler so it sees the final status and every header set further
// in. Fields are an allowlist: the query string (OAuth codes, states, PKCE
// verifiers), request headers (Authorization, cookies) and bodies (refresh
// tokens, client secrets) are never logged.
func accessLog(logger *zap.Logger, listener string, next http.Handler) http.Handler {
	logger = logger.Named("http")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		level := zapcore.InfoLevel
		if quietPaths[r.URL.Path] {
			level = zapcore.DebugLevel
		}
		ce := logger.Check(level, "http request")
		if ce == nil {
			return
		}
		fields := []zap.Field{
			zap.String("listener", listener),
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.Int("status", rec.status),
			zap.Duration("duration", time.Since(start)),
			zap.Int64("bytes", rec.bytes),
			zap.String("remote_addr", r.RemoteAddr),
			zap.String("user_agent", r.UserAgent()),
		}
		if id := rec.Header().Get(requestIDHeader); id != "" {
			fields = append(fields, zap.String("request_id", id))
		}
		ce.Write(fields...)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status      int
	bytes       int64
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
	n, err := s.ResponseWriter.Write(b)
	s.bytes += int64(n)
	return n, err
}

// Unwrap lets http.ResponseController reach Flush and deadline control on
// the underlying writer.
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }
