//go:build e2e

// Acceptance proof for OpenTelemetry tracing against the real image and a
// real OpenTelemetry collector: with OTEL_TRACES_EXPORTER=otlp, every request
// the access log shows on either listener is exactly one trace, rooted at its
// server span and carrying the log's request id; the Google calls and the
// state-store operations it made are child spans; and nothing exported
// carries the email, a client ID or a token value of those requests.
package e2e

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

var collectorImage = imageOr("E2E_OTEL_COLLECTOR_IMAGE", "otel/opentelemetry-collector-contrib:0.163.2@sha256:7f22d2a6748110ffb6a59bc0df448bccbf501cdb667d610ede4c61d3863d5849")

const (
	collectorAlias = "otelcol"
	// collectorSpansFile is where the collector writes every batch it
	// receives, one OTLP/JSON document per line.
	collectorSpansFile = "/spans.jsonl"
	collectorConfig    = `receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318
exporters:
  file:
    path: ` + collectorSpansFile + `
    flush_interval: 100ms
service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [file]
`
)

// startCollector runs an OpenTelemetry collector that accepts OTLP/HTTP on
// network under collectorAlias and appends what it receives to
// collectorSpansFile. The image is distroless with no writable directory for
// its own user, hence root.
func startCollector(ctx context.Context, t *testing.T, network string) testcontainers.Container {
	t.Helper()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image: collectorImage,
			User:  "0:0",
			Files: []testcontainers.ContainerFile{{
				Reader:            strings.NewReader(collectorConfig),
				ContainerFilePath: "/etc/otelcol-contrib/config.yaml",
				FileMode:          0o644,
			}},
			Networks:       []string{network},
			NetworkAliases: map[string][]string{network: {collectorAlias}},
			WaitingFor:     wait.ForLog("Everything is ready").WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	})
	track(ctx, t, "otelcol", c)
	require.NoError(t, err, "otel collector")
	return c
}

type otlpSpan struct {
	TraceID      string `json:"traceId"`
	SpanID       string `json:"spanId"`
	ParentSpanID string `json:"parentSpanId"`
	Name         string `json:"name"`
	Kind         int    `json:"kind"`
	Attributes   []struct {
		Key   string `json:"key"`
		Value struct {
			StringValue string `json:"stringValue"`
		} `json:"value"`
	} `json:"attributes"`
	Status struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"status"`
}

const otlpStatusCodeError = 2

const otlpSpanKindServer = 2

func (s otlpSpan) attr(key string) string {
	for _, kv := range s.Attributes {
		if kv.Key == key {
			return kv.Value.StringValue
		}
	}
	return ""
}

// exportedSpans returns the collector's file as received and every span in it.
func (s *observabilityStack) exportedSpans(ctx context.Context, t *testing.T) (string, []otlpSpan) {
	t.Helper()
	rc, err := s.collector.CopyFileFromContainer(ctx, collectorSpansFile)
	if err != nil {
		return "", nil // nothing exported yet
	}
	defer func() { _ = rc.Close() }()
	raw, err := io.ReadAll(rc)
	require.NoError(t, err)

	var spans []otlpSpan
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
	for sc.Scan() {
		var doc struct {
			ResourceSpans []struct {
				ScopeSpans []struct {
					Spans []otlpSpan `json:"spans"`
				} `json:"scopeSpans"`
			} `json:"resourceSpans"`
		}
		require.NoError(t, json.Unmarshal(sc.Bytes(), &doc))
		for _, rs := range doc.ResourceSpans {
			for _, ss := range rs.ScopeSpans {
				spans = append(spans, ss.Spans...)
			}
		}
	}
	require.NoError(t, sc.Err())
	return string(raw), spans
}

type accessLine struct {
	Listener  string `json:"listener"`
	Path      string `json:"path"`
	RequestID string `json:"request_id"`
}

// tracedRequests parses the access log, skipping the probes and scrapes that
// are deliberately not traced.
func (s *observabilityStack) tracedRequests(ctx context.Context, t *testing.T) []accessLine {
	t.Helper()
	var out []accessLine
	for _, line := range strings.Split(s.logs(ctx, t), "\n") {
		_, fields, ok := strings.Cut(line, "\thttp request\t")
		if !ok {
			continue
		}
		var l accessLine
		require.NoError(t, json.Unmarshal([]byte(fields), &l), line)
		switch l.Path {
		case "/healthz", "/readyz", "/admin/healthz", "/metrics":
			continue
		}
		require.NotEmpty(t, l.RequestID, line)
		out = append(out, l)
	}
	return out
}

func TestTracing(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e: skipped in -short")
	}
	t.Parallel()
	ctx := context.Background()
	st := setupObservabilityStack(ctx, t, observabilityOptions{tracing: true})

	// --- a real CLI login and refresh on the public listener, and an admin
	// request on the admin one (refused or not, it is a request).
	login, refreshed := st.loginAndRefresh(ctx, t)
	httpGet(t, st.adminURL+"/admin/keys")

	// --- a failed sign-in: Google returns an ID token for another client,
	// and go-oidc's refusal quotes the upstream client ID tempogate
	// expected, a declared value.
	setMockFaults(t, st.mockBaseURL, url.Values{"wrong_audience": {"true"}})
	br := upstreamBrowsers{tgBase: st.publicURL, mockBase: st.mockBaseURL}.newBrowser(t)
	require.Equal(t, http.StatusBadGateway, br.get(t, br.consent(t)).status)
	setMockFaults(t, st.mockBaseURL, url.Values{})

	// --- every logged request shows up as exactly one trace.
	requests := st.tracedRequests(ctx, t)
	require.NotEmpty(t, requests)
	var (
		raw   string
		spans []otlpSpan
	)
	byRequestID := map[string]otlpSpan{}
	require.Eventually(t, func() bool {
		raw, spans = st.exportedSpans(ctx, t)
		clear(byRequestID)
		for _, sp := range spans {
			if sp.Kind == otlpSpanKindServer {
				byRequestID[sp.attr("tempogate.request_id")] = sp
			}
		}
		for _, r := range requests {
			if _, ok := byRequestID[r.RequestID]; !ok {
				return false
			}
		}
		return true
	}, 30*time.Second, 200*time.Millisecond, "a logged request has no server span")

	servers := map[string]otlpSpan{} // by trace id
	for _, sp := range spans {
		if sp.Kind != otlpSpanKindServer {
			continue
		}
		require.Emptyf(t, sp.ParentSpanID, "server span %q must be its trace's root", sp.Name)
		_, dup := servers[sp.TraceID]
		require.Falsef(t, dup, "two requests share trace %s", sp.TraceID)
		servers[sp.TraceID] = sp
	}
	for _, r := range requests {
		require.Equal(t, r.Listener, byRequestID[r.RequestID].attr("tempogate.listener"), r.Path)
	}
	for _, sp := range spans {
		_, ok := servers[sp.TraceID]
		require.Truef(t, ok, "span %q is in no request's trace", sp.Name)
	}

	// --- each request's own work is in its trace: Google calls on the
	// callback, store operations on the callback and on /token.
	children := map[string][]string{} // server span name -> child span names
	for _, sp := range spans {
		if sp.Kind != otlpSpanKindServer {
			name := servers[sp.TraceID].Name
			children[name] = append(children[name], sp.Name)
		}
	}
	t.Logf("%d traced requests, %d spans; children by request: %v", len(requests), len(spans), children)
	require.Subset(t, children["GET /callback/{connector}"], []string{
		"upstream discovery", "upstream code_exchange", "upstream verify_id_token",
		"store consume_auth_request", "store save_auth_code",
	})
	require.Subset(t, children["POST /token"], []string{
		"store consume_auth_code", "store consume_refresh", "store save_refresh",
	})

	// --- the failed sign-in's error is exported, with the declared client
	// ID masked rather than dropped.
	var refused []string
	for _, sp := range spans {
		if sp.Name == "upstream verify_id_token" && sp.Status.Code == otlpStatusCodeError {
			refused = append(refused, sp.Status.Message)
		}
	}
	require.Len(t, refused, 1, "the refused ID token is one failed span")
	require.Contains(t, refused[0], `expected audience "tempog***"`)

	// --- no identity, client ID or token value is exported anywhere: span
	// names, attributes, error messages or resource.
	for name, secret := range map[string]string{
		"email":                  allowedEmail,
		"client ID":              cliClientID,
		"upstream client ID":     "tempogate-upstream",
		"upstream client secret": "tempogate-upstream-secret",
		"access token":           login.AccessToken,
		"refresh token":          login.RefreshToken,
		"refreshed access token": refreshed.AccessToken,
		"rotated refresh token":  refreshed.RefreshToken,
	} {
		require.NotEmpty(t, secret, name)
		require.NotContainsf(t, raw, secret, "the exported spans carry the %s", name)
	}
}
