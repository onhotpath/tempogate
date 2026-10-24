package oidc_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/onhotpath/tempogate/api"
	"github.com/onhotpath/tempogate/keys"
	"github.com/onhotpath/tempogate/oidc"
	"github.com/onhotpath/tempogate/redact"
	"github.com/onhotpath/tempogate/state/sqlite"
	"github.com/onhotpath/tempogate/telemetry"
)

// echoingStore fails every refresh consume with an error that quotes the
// token and client it was given, as a database error can quote the value it
// refused.
type echoingStore struct{ *sqlite.Store }

func (echoingStore) ConsumeRefresh(_ context.Context, token, clientID string, _ time.Time) (oidc.Refresh, error) {
	return oidc.Refresh{}, fmt.Errorf("db refused token %q for client %q", token, clientID)
}

// keptSpans keeps what it exported past Shutdown, which the provider calls
// to flush and InMemoryExporter answers by forgetting.
type keptSpans struct{ *tracetest.InMemoryExporter }

func (keptSpans) Shutdown(context.Context) error { return nil }

// A /token request's credentials, declared by the handler, are masked in the
// exported error of the 5xx they caused, through the real api middleware
// and OpenTelemetry tracer.
func TestTokenCredentialsAreMaskedInExportedErrors(t *testing.T) {
	ctx := context.Background()
	store, err := sqlite.New(sqlite.WithPath(filepath.Join(t.TempDir(), "state.db")))
	require.NoError(t, err)
	require.NoError(t, store.Migrate(ctx))
	t.Cleanup(func() { _ = store.Close() })
	k := keys.New(keys.WithStore(store), keys.WithGenerateOptions(keys.WithRSABits(2048)))
	require.NoError(t, k.Init(ctx))
	signer := keys.NewSigner(keys.WithKeys(k), keys.WithIssuer(testIssuer))

	const (
		clientID     = "confidential-webui"
		clientSecret = "webui-shared-secret"
		refreshToken = "refresh-token-presented-by-the-client"
	)
	reg, err := oidc.ParseClientRegistry(clientID + ":" + testRedirectURI)
	require.NoError(t, err)
	require.NoError(t, reg.WithSecrets(clientID+":"+clientSecret))

	spans := tracetest.NewInMemoryExporter()
	prov, err := telemetry.NewProvider(telemetry.WithSpanExporter(keptSpans{spans}))
	require.NoError(t, err)
	servers := api.New(api.NewReadiness(),
		api.WithTracer(prov.Tracer()),
		api.WithRedaction(redact.NewSet()),
		api.WithRegistrar(oidc.NewToken(echoingStore{store}, signer, reg, oidc.WithPermissionResolver(permitAll)).Register),
	)
	srv := httptest.NewServer(servers.Public.Handler)
	t.Cleanup(srv.Close)

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/token", strings.NewReader(url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	require.NoError(t, prov.Shutdown(ctx)) // flushes the batch

	var server tracetest.SpanStub
	for _, sp := range spans.GetSpans() {
		if sp.Name == "POST /token" {
			server = sp
		}
	}
	require.Equal(t, "POST /token", server.Name, "spans: %v", spans.GetSpans())
	msg := server.Status.Description
	assert.Contains(t, msg, `db refused token "[REDACTED]" for client "confid***"`)
	for _, v := range []string{refreshToken, clientID, clientSecret, req.Header.Get("Authorization")} {
		assert.NotContains(t, msg, v)
	}
}
