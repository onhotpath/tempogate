package config

// TestIssuerBasePath pins the single-source-of-truth rule: the base path tempogate
// mounts its OIDC surface under is exactly the path component of OIDC_ISSUER,
// normalised to a leading slash with no trailing slash (empty ⇒ root, the
// historical behaviour). Trailing-slash handling mirrors the existing
// strings.TrimRight(issuer, "/") in api/wellknown.go and oidc.New.
func (s *ConfigSuite) TestIssuerBasePath() {
	cases := []struct {
		name   string
		issuer string
		want   string
	}{
		{name: "no path", issuer: "https://tempogate.example.com", want: ""},
		{name: "default loopback issuer", issuer: "http://127.0.0.1:8000", want: ""},
		{name: "root slash only", issuer: "https://tempogate.example.com/", want: ""},
		{name: "single segment", issuer: "https://tempogate.example.com/idp", want: "/idp"},
		{name: "trailing slash trimmed", issuer: "https://tempogate.example.com/idp/", want: "/idp"},
		{name: "multi segment", issuer: "https://shared.example.com/auth/idp", want: "/auth/idp"},
		{name: "loopback with path", issuer: "http://127.0.0.1:8000/idp", want: "/idp"},
		{name: "empty issuer", issuer: "", want: ""},
		{name: "unparseable issuer", issuer: "://nonsense", want: ""},
	}

	for _, tc := range cases {
		s.Run(tc.name, func() {
			s.Equal(tc.want, issuerBasePath(tc.issuer))
		})
	}
}
