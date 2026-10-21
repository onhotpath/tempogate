// Command mockgoogle is a minimal but real upstream OIDC IdP used only by the
// end-to-end test (test/e2e). It stands in for Google: OIDC discovery, a JWKS,
// a consent screen a headless browser can click through, and a token endpoint
// that returns a properly RS256-signed id_token. The asserted identity (email,
// email_verified, Google Workspace `hd` and the stable `sub`) is controllable
// at runtime via /_control/identity so one running instance can drive the
// allowed, disallowed-domain and hosted-domain scenarios without a container
// restart.
//
// It is deliberately standalone (its own main, its own container image) so the
// test exercises tempogate's real golang.org/x/oauth2 + coreos/go-oidc code
// path against a separate process over the Docker network, exactly as it would
// against Google.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"
)

const kid = "mock-google-key-1"

// identity is what the next id_token asserts. Sub mirrors Google's opaque,
// never-reused account id; HD is the Workspace hosted domain, empty for a
// consumer account (Google omits the claim then, and so does the mock).
type identity struct {
	Sub      string
	Email    string
	Verified bool
	HD       string
}

// subject returns the configured sub, or a stable per-email default so tests
// that do not care about sub still get a non-email subject.
func (id identity) subject() string {
	if id.Sub != "" {
		return id.Sub
	}
	return "mock-google-sub-" + id.Email
}

type server struct {
	issuer string
	priv   *rsa.PrivateKey

	mu      sync.Mutex
	current identity
	codes   map[string]identity
}

func main() {
	issuer := envOr("MOCK_ISSUER", "http://mockgoogle:8080")
	addr := envOr("MOCK_LISTEN", ":8080")

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("mockgoogle: rsa key: %v", err)
	}

	s := &server{
		issuer: issuer,
		priv:   priv,
		current: identity{
			Sub:      os.Getenv("MOCK_SUB"),
			Email:    envOr("MOCK_EMAIL", "alice@example.com"),
			Verified: os.Getenv("MOCK_EMAIL_VERIFIED") != "false",
			HD:       os.Getenv("MOCK_HD"),
		},
		codes: map[string]identity{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", s.discovery)
	mux.HandleFunc("/jwks", s.jwks)
	mux.HandleFunc("/auth", s.auth)
	mux.HandleFunc("/auth/approve", s.approve)
	mux.HandleFunc("/token", s.token)
	mux.HandleFunc("/_control/identity", s.setIdentity)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	log.Printf("mockgoogle: issuer=%s listening on %s", issuer, addr)
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(srv.ListenAndServe())
}

func (s *server) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"issuer":                                s.issuer,
		"authorization_endpoint":                s.issuer + "/auth",
		"token_endpoint":                        s.issuer + "/token",
		"jwks_uri":                              s.issuer + "/jwks",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"subject_types_supported":               []string{"public"},
		"scopes_supported":                      []string{"openid", "email", "profile"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (s *server) jwks(w http.ResponseWriter, _ *http.Request) {
	pub, err := jwk.Import[jwk.Key](s.priv.Public())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = pub.Set(jwk.KeyIDKey, kid)
	_ = pub.Set(jwk.AlgorithmKey, jwa.RS256())
	_ = pub.Set(jwk.KeyUsageKey, "sig")
	set := jwk.NewSet()
	_ = set.AddKey(pub)
	writeJSON(w, set)
}

var consentTmpl = template.Must(template.New("consent").Parse(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Mock Google — Sign in</title></head>
<body>
<h1>Mock Google</h1>
<p id="who">Continue as <strong>{{.Email}}</strong>?</p>
<a id="approve" href="/auth/approve?redirect_uri={{.RedirectURI}}&state={{.State}}">Approve</a>
</body></html>`))

// auth is the consent screen. tempogate's /authorize redirects the browser
// here; the browser clicks "Approve", which is the human consent step.
func (s *server) auth(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	s.mu.Lock()
	email := s.current.Email
	s.mu.Unlock()

	// Pass the raw (already query-decoded) values: html/template URL-escapes
	// them exactly once in the href query context. Pre-escaping here would
	// double-encode, so /auth/approve would receive a still-encoded
	// redirect_uri, fail to parse it as absolute, and the browser would 404
	// on a relative redirect.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = consentTmpl.Execute(w, struct{ Email, RedirectURI, State string }{
		Email:       email,
		RedirectURI: q.Get("redirect_uri"),
		State:       q.Get("state"),
	})
}

// approve mints an authorization code bound to a snapshot of the current
// identity and redirects back to tempogate's callback.
func (s *server) approve(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirectURI := q.Get("redirect_uri")
	if redirectURI == "" {
		http.Error(w, "missing redirect_uri", http.StatusBadRequest)
		return
	}
	code := randToken()

	s.mu.Lock()
	s.codes[code] = s.current
	s.mu.Unlock()

	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	rq := u.Query()
	rq.Set("code", code)
	rq.Set("state", q.Get("state"))
	u.RawQuery = rq.Encode()
	// #nosec G710 -- redirecting to the OAuth client's supplied redirect_uri
	// IS an authorization endpoint's defined behaviour; this is a test-only
	// mock IdP (its own container image) that is never deployed.
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// token exchanges the code for a signed id_token. The audience is the
// client_id tempogate sends (its upstream Google client), which coreos/go-oidc
// inside tempogate verifies the id_token against.
func (s *server) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	code := r.Form.Get("code")
	clientID := r.Form.Get("client_id")

	s.mu.Lock()
	id, ok := s.codes[code]
	delete(s.codes, code)
	s.mu.Unlock()
	if !ok {
		http.Error(w, "invalid code", http.StatusBadRequest)
		return
	}

	priv, err := jwk.Import[jwk.Key](s.priv)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = priv.Set(jwk.KeyIDKey, kid)
	_ = priv.Set(jwk.AlgorithmKey, jwa.RS256())

	now := time.Now()
	b := jwt.NewBuilder().
		Issuer(s.issuer).
		Audience([]string{clientID}).
		Subject(id.subject()).
		IssuedAt(now).
		Expiration(now.Add(time.Hour)).
		Claim("email", id.Email).
		Claim("email_verified", id.Verified).
		Claim("name", id.Email)
	if id.HD != "" {
		b = b.Claim("hd", id.HD)
	}
	tok, err := b.Build()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), priv))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{
		"access_token": "mock-access-token",
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     string(signed),
	})
}

// setIdentity lets the test choose the asserted identity before driving the
// browser, so the allowed- and disallowed-domain scenarios share one instance.
// Form fields: email (required), verified ("false" to clear), sub and hd
// (both optional; an empty hd models a consumer account).
func (s *server) setIdentity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	email := r.Form.Get("email")
	if email == "" {
		http.Error(w, "email required", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.current = identity{
		Sub:      r.Form.Get("sub"),
		Email:    email,
		Verified: r.Form.Get("verified") != "false",
		HD:       r.Form.Get("hd"),
	}
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("mockgoogle: encode: %v", err)
	}
}

func randToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(errors.New("mockgoogle: rand failed"))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
