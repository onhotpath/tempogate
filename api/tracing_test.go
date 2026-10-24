package api_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/onhotpath/tempogate/api"
	"github.com/onhotpath/tempogate/api/requestid"
	"github.com/onhotpath/tempogate/observe"
	"github.com/onhotpath/tempogate/observe/observetest"
	"github.com/onhotpath/tempogate/redact"
)

func tracedServers(tr *observetest.Tracer) *api.Servers {
	return api.New(api.NewReadiness(),
		api.WithTracer(tr),
		api.WithRegistrar(func(a huma.API) {
			huma.Register(a, huma.Operation{Method: http.MethodGet, Path: "/things/{id}"},
				func(ctx context.Context, _ *struct {
					ID string `path:"id"`
				}) (*struct{}, error) {
					_, child := tr.Start(ctx, "child")
					child.End()
					return nil, nil
				})
			huma.Register(a, huma.Operation{Method: http.MethodPost, Path: "/boom"},
				func(context.Context, *struct{}) (*struct{}, error) {
					return nil, huma.Error500InternalServerError("store exploded")
				})
		}),
		api.WithAdminRegistrar(func(a huma.API) {
			huma.Get(a, "/admin/keys", func(context.Context, *struct{}) (*struct{}, error) { return nil, nil })
		}),
		api.WithAdminHandler("GET /metrics", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})),
	)
}

func serve(h http.Handler, method, target string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, target, http.NoBody))
	return rec
}

func serverSpans(tr *observetest.Tracer) []observetest.Span {
	var out []observetest.Span
	for _, sp := range tr.Spans() {
		if sp.Kind == observe.SpanKindServer {
			out = append(out, sp)
		}
	}
	return out
}

// A request is one trace, its server span the root, named by the route
// template the mux matched, never the raw path; the handler runs under it.
func TestRequestIsATraceNamedByItsRoute(t *testing.T) {
	tr := observetest.NewTracer()
	s := tracedServers(tr)

	rec := serve(s.Public.Handler, http.MethodGet, "/things/alice@example.com?client_id=tempogate-cli")
	require.Equal(t, http.StatusNoContent, rec.Code)

	server, ok := tr.Span("GET /things/{id}")
	require.True(t, ok, "spans: %v", tr.Spans())
	assert.Nil(t, server.Parent)
	assert.Equal(t, map[string]any{
		"http.request.method":       http.MethodGet,
		"http.route":                "/things/{id}",
		"http.response.status_code": http.StatusNoContent,
		"tempogate.listener":        "public",
		"tempogate.request_id":      rec.Header().Get(requestid.Header),
	}, server.Attrs)
	assert.NotEmpty(t, server.Attrs["tempogate.request_id"])
	assert.True(t, server.Ended)
	assert.Empty(t, server.ErrorType)

	child, ok := tr.Span("child")
	require.True(t, ok)
	assert.Equal(t, "GET /things/{id}", child.Parent.Name, "the handler runs under the request's span")
}

// A 5xx marks the span failed with the detail the client never sees.
func TestServerErrorCarriesItsDetail(t *testing.T) {
	tr := observetest.NewTracer()
	s := tracedServers(tr)

	rec := serve(s.Public.Handler, http.MethodPost, "/boom")
	require.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.NotContains(t, rec.Body.String(), "store exploded")

	sp, ok := tr.Span("POST /boom")
	require.True(t, ok)
	assert.Equal(t, "500", sp.ErrorType)
	require.Error(t, sp.Err)
	assert.Contains(t, sp.Err.Error(), "store exploded")
}

func TestUnmatchedRouteAndAdminSurface(t *testing.T) {
	tr := observetest.NewTracer()
	s := tracedServers(tr)

	serve(s.Public.Handler, http.MethodGet, "/no/such/path")
	serve(s.Admin.Handler, http.MethodGet, "/admin/keys")

	spans := serverSpans(tr)
	require.Len(t, spans, 2)
	assert.Equal(t, "GET", spans[0].Name, "no route matched: the method alone, never the raw path")
	assert.NotContains(t, spans[0].Attrs, "http.route")
	assert.Equal(t, http.StatusNotFound, spans[0].Attrs["http.response.status_code"])
	assert.Empty(t, spans[0].ErrorType, "a 4xx is the client's outcome, not a server error")
	assert.Equal(t, "GET /admin/keys", spans[1].Name)
	assert.Equal(t, "admin", spans[1].Attrs["tempogate.listener"])
}

func TestUnknownMethodIsOther(t *testing.T) {
	tr := observetest.NewTracer()
	s := tracedServers(tr)

	serve(s.Public.Handler, "PROPFIND", "/things/x")

	spans := serverSpans(tr)
	require.Len(t, spans, 1)
	assert.Equal(t, "_OTHER", spans[0].Attrs["http.request.method"])
	assert.Equal(t, "HTTP", spans[0].Name)
}

// Probes and scrapes arrive every few seconds; they are not traced.
func TestProbesAndScrapesAreNotTraced(t *testing.T) {
	tr := observetest.NewTracer()
	s := tracedServers(tr)

	serve(s.Public.Handler, http.MethodGet, "/healthz")
	serve(s.Public.Handler, http.MethodGet, "/readyz")
	serve(s.Admin.Handler, http.MethodGet, "/admin/healthz")
	serve(s.Admin.Handler, http.MethodGet, "/metrics")

	assert.Empty(t, tr.Spans())
}

// A handler that panics still ends its span, as the 500 it becomes.
func TestPanickingRequestEndsItsSpan(t *testing.T) {
	tr := observetest.NewTracer()
	s := api.New(api.NewReadiness(),
		api.WithTracer(tr),
		api.WithAdminHandler("GET /panic", http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") })),
	)

	assert.Panics(t, func() { serve(s.Admin.Handler, http.MethodGet, "/panic") })
	sp, ok := tr.Span("GET /panic")
	require.True(t, ok)
	assert.Equal(t, "500", sp.ErrorType)
	assert.True(t, sp.Ended)
}

// A traced request carries its own redact.Set, a child of the process's, for
// its handlers to declare into; without a tracer nothing is installed.
func TestTracedRequestCarriesARedactionSet(t *testing.T) {
	process := redact.NewSet()
	process.Declare(redact.Secret, "gocspx-secret")
	var sets []*redact.Set
	handler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		sets = append(sets, redact.FromContext(r.Context()))
		redact.Declare(r.Context(), redact.PII, "bob@example.com")
	})

	traced := api.New(api.NewReadiness(), api.WithTracer(observetest.NewTracer()), api.WithRedaction(process),
		api.WithAdminHandler("GET /x", handler))
	serve(traced.Admin.Handler, http.MethodGet, "/x")
	serve(traced.Admin.Handler, http.MethodGet, "/x")
	require.Len(t, sets, 2)
	require.NotNil(t, sets[0])
	assert.NotSame(t, sets[0], sets[1], "each request has its own")
	assert.Equal(t, "[REDACTED] b***@example.com", sets[0].Scrub("gocspx-secret bob@example.com"))
	assert.Equal(t, "bob@example.com", process.Scrub("bob@example.com"), "a request's values stay in the request")

	sets = nil
	untraced := api.New(api.NewReadiness(), api.WithRedaction(process), api.WithAdminHandler("GET /x", handler))
	serve(untraced.Admin.Handler, http.MethodGet, "/x")
	assert.Equal(t, []*redact.Set{nil}, sets)
}

// The span's status recorder must not hide the connection: a handler that
// flushes reaches the real writer through http.ResponseController.
func TestTracedHandlerCanFlush(t *testing.T) {
	tr := observetest.NewTracer()
	s := api.New(api.NewReadiness(),
		api.WithTracer(tr),
		api.WithAdminHandler("GET /stream", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("partial"))
			if err := http.NewResponseController(w).Flush(); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		})),
	)

	rec := serve(s.Admin.Handler, http.MethodGet, "/stream")
	assert.True(t, rec.Flushed)
	assert.Equal(t, "partial", rec.Body.String())
	sp, ok := tr.Span("GET /stream")
	require.True(t, ok)
	assert.Equal(t, http.StatusOK, sp.Attrs["http.response.status_code"])
}
