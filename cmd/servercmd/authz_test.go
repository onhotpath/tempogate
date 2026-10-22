package servercmd

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/onhotpath/tempogate/authz"
)

func runExplain(t *testing.T, rules []string, dflt, allowed string, args ...string) (string, error) {
	t.Helper()
	pol, err := authz.Parse(rules, dflt)
	require.NoError(t, err)
	cmd := newAuthzCmd(supply(authzParams{Policy: pol, AllowedDomains: allowed}))
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(new(testWriter))
	cmd.SetArgs(append([]string{"explain"}, args...))
	err = cmd.ExecuteContext(context.Background())
	return out.String(), err
}

func TestAuthzExplainListsMatchedRulesAndPermissions(t *testing.T) {
	out, err := runExplain(t, []string{
		"email:alice@example.com=ns-a:read",
		"email:bob@example.com=temporal-system:admin",
		"domain:example.com=ns-b:read",
	}, "", "example.com", "--email", "Alice@Example.com")
	require.NoError(t, err)
	require.Contains(t, out, "alice@example.com")
	require.Regexp(t, `matched:\s+rule 0\s+email:alice@example.com=ns-a:read`, out)
	require.Regexp(t, `\s+rule 2\s+domain:example.com=ns-b:read`, out)
	require.NotContains(t, out, "rule 1")
	require.Regexp(t, `permissions:\s+ns-a:read,ns-b:read`, out)
	require.NotContains(t, out, "admission:")
}

func TestAuthzExplainDefaultAndDenial(t *testing.T) {
	out, err := runExplain(t, []string{"email:alice@example.com=ns-a:read"}, "orders:read", "example.com",
		"--email", "carol@example.com")
	require.NoError(t, err)
	require.Contains(t, out, "no rule; OIDC_AUTHZ_DEFAULT_PERMISSIONS applies")
	require.Regexp(t, `permissions:\s+orders:read`, out)

	out, err = runExplain(t, []string{"email:alice@example.com=ns-a:read"}, "", "example.com",
		"--email", "carol@example.com")
	require.NoError(t, err)
	require.Contains(t, out, "none: sign-in is denied (access_denied), no token is issued")
}

func TestAuthzExplainFlagsAnEmailThatCannotSignIn(t *testing.T) {
	out, err := runExplain(t, []string{"email:dave@other.test=ns-a:read"}, "", "example.com",
		"--email", "dave@other.test")
	require.NoError(t, err)
	require.Contains(t, out, "not in OIDC_ALLOWED_DOMAINS")
	require.Regexp(t, `permissions:\s+ns-a:read`, out)

	out, err = runExplain(t, nil, "", "example.com", "--email", "no-at-sign")
	require.NoError(t, err)
	require.Contains(t, out, "not in OIDC_ALLOWED_DOMAINS")
}

func TestAuthzExplainRequiresAnEmail(t *testing.T) {
	_, err := runExplain(t, nil, "", "example.com")
	require.ErrorContains(t, err, `required flag(s) "email" not set`)

	_, err = runExplain(t, nil, "", "example.com", "--email", " ")
	require.ErrorContains(t, err, "--email must be non-empty")
}

func TestRequireAuthz(t *testing.T) {
	require.ErrorIs(t, requireAuthz(&authz.Policy{}), authz.ErrNoPolicy)
	require.NoError(t, requireAuthz(testPolicy))
}
