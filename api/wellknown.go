package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/onhotpath/tempogate/keys"
	"github.com/onhotpath/tempogate/oidc"
)

const (
	jwksPath      = "/.well-known/jwks.json"
	discoveryPath = "/.well-known/openid-configuration"

	// wellKnownCacheControl lets relying parties (Temporal frontend's JWKS
	// fetcher, OIDC clients) cache the documents for 5 minutes. Short enough
	// that a --force key rotation propagates promptly; long enough that a
	// busy frontend isn't refetching on every verification.
	wellKnownCacheControl = "public, max-age=300"
)

// jwkRSA is one RFC 7517 RSA public key. kty/use/alg form the envelope;
// n/e are the Base64urlUInt modulus/exponent supplied by keys.
type jwkRSA struct {
	Kty string `json:"kty" example:"RSA" doc:"Key type"`
	Use string `json:"use" example:"sig" doc:"Public key use"`
	Alg string `json:"alg" example:"RS256" doc:"Signature algorithm"`
	Kid string `json:"kid" doc:"Key ID; matches the JWT header kid"`
	N   string `json:"n" doc:"RSA modulus (base64url)"`
	E   string `json:"e" doc:"RSA public exponent (base64url)"`
}

type jwksDoc struct {
	Keys []jwkRSA `json:"keys"`
}

type jwksOutput struct {
	CacheControl string `header:"Cache-Control"`
	Body         jwksDoc
}

// openIDConfig is the OIDC discovery document. Endpoint URLs are derived
// from the issuer plus the paths the oidc handlers register at, so the
// document and the live routes cannot drift. The supported-* lists describe
// exactly the flow tempogate implements: authorization-code + PKCE (S256
// only), refresh-token renewal, RS256-signed tokens.
type openIDConfig struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	UserinfoEndpoint                 string   `json:"userinfo_endpoint"`
	DeviceAuthorizationEndpoint      string   `json:"device_authorization_endpoint"`
	JwksURI                          string   `json:"jwks_uri"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	GrantTypesSupported              []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported    []string `json:"code_challenge_methods_supported"`
	ScopesSupported                  []string `json:"scopes_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
}

type openIDOutput struct {
	CacheControl string `header:"Cache-Control"`
	Body         openIDConfig
}

// JWKSSource is api's consumer-side view of the keypair aggregate: the only
// behaviour the JWKS endpoint needs. *keys.Keys satisfies it structurally, so
// api couples to this narrow contract rather than the concrete aggregate
// (same consumer-defines-the-interface convention as oidc.AuthRequestStore /
// keys.KeyStore). It stays exported so the fx graph can bind the concrete
// type to it.
type JWKSSource interface {
	PublicJWKS() ([]keys.JWK, error)
}

// WithWellKnown registers the JWKS and OIDC discovery endpoints. issuer is
// the externally reachable base URL relying parties use to reach tempogate;
// jwks_uri in the discovery document is derived from it.
func WithWellKnown(k JWKSSource, issuer string) Option {
	return func(c *apiConfig) {
		c.registrars = append(c.registrars, func(a huma.API) {
			registerWellKnown(a, k, strings.TrimRight(issuer, "/"))
		})
	}
}

func registerWellKnown(a huma.API, k JWKSSource, issuer string) {
	huma.Register(a, huma.Operation{
		OperationID: "jwks",
		Method:      http.MethodGet,
		Path:        jwksPath,
		Summary:     "JWKS for verifying tempogate-signed JWTs",
		Tags:        []string{"well-known"},
	}, func(_ context.Context, _ *struct{}) (*jwksOutput, error) {
		set, err := k.PublicJWKS()
		if err != nil {
			return nil, huma.Error500InternalServerError("jwks unavailable", err)
		}
		doc := jwksDoc{Keys: make([]jwkRSA, 0, len(set))}
		for _, j := range set {
			doc.Keys = append(doc.Keys, jwkRSA{
				Kty: "RSA",
				Use: "sig",
				Alg: j.Alg,
				Kid: j.Kid,
				N:   j.N,
				E:   j.E,
			})
		}
		return &jwksOutput{CacheControl: wellKnownCacheControl, Body: doc}, nil
	})

	huma.Register(a, huma.Operation{
		OperationID: "openid-configuration",
		Method:      http.MethodGet,
		Path:        discoveryPath,
		Summary:     "OIDC discovery document",
		Tags:        []string{"well-known"},
	}, func(_ context.Context, _ *struct{}) (*openIDOutput, error) {
		return &openIDOutput{
			CacheControl: wellKnownCacheControl,
			Body: openIDConfig{
				Issuer:                           issuer,
				AuthorizationEndpoint:            issuer + oidc.AuthorizePath,
				TokenEndpoint:                    issuer + oidc.TokenPath,
				UserinfoEndpoint:                 issuer + oidc.UserInfoPath,
				DeviceAuthorizationEndpoint:      issuer + oidc.DeviceAuthorizationPath,
				JwksURI:                          issuer + jwksPath,
				ResponseTypesSupported:           []string{"code"},
				GrantTypesSupported:              []string{"authorization_code", "refresh_token"},
				CodeChallengeMethodsSupported:    []string{"S256"},
				ScopesSupported:                  []string{"openid", "profile", "email"},
				SubjectTypesSupported:            []string{"public"},
				IDTokenSigningAlgValuesSupported: []string{keys.AlgRS256},
			},
		}, nil
	})
}
