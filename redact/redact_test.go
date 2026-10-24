package redact_test

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/onhotpath/tempogate/redact"
)

func TestRules(t *testing.T) {
	cases := []struct {
		name string
		rule redact.Rule
		in   string
		want string
	}{
		{"secret", redact.Secret, "gocspx-very-secret", "[REDACTED]"},
		{"email", redact.PII, "alice@example.com", "a***@example.com"},
		{"multibyte email", redact.PII, "éloïse@example.com", "é***@example.com"},
		{"other personal value", redact.PII, "google:1234567890", "***"},
		{"identifier", redact.Identifier, "tempogate-cli", "temp***"},
		{"long identifier keeps its prefix", redact.Identifier, "123456789012-abc.apps.googleusercontent.com", "123456***"},
		{"short identifier shows a third at most", redact.Identifier, "abcdefgh", "ab***"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, c.rule.Mask(c.in))
		})
	}
}

func TestScrubMasksEveryDeclaredValue(t *testing.T) {
	s := redact.NewSet()
	s.Declare(redact.Identifier, "tempogate-cli")
	s.Declare(redact.PII, "alice@example.com")

	got := s.Scrub(`oidc: expected audience "tempogate-cli" got ["other"] for alice@example.com, again tempogate-cli`)
	assert.Equal(t, `oidc: expected audience "temp***" got ["other"] for a***@example.com, again temp***`, got)
}

// Where values overlap the longest wins, and a mask is not scanned again.
func TestScrubPrefersTheLongestValue(t *testing.T) {
	s := redact.NewSet()
	s.Declare(redact.Secret, "token-abc")
	s.Declare(redact.Identifier, "token-abc-refresh")
	s.Declare(redact.PII, "[REDACTED] and")

	assert.Equal(t, "tokeN: token*** and [REDACTED] and [REDACTED]",
		s.Scrub("tokeN: token-abc-refresh and token-abc and token-abc"))
}

// A value declared under several rules shows by the strongest, in whichever
// order and Set they were declared.
func TestStrongestRuleWins(t *testing.T) {
	s := redact.NewSet()
	s.Declare(redact.Identifier, "alice@example.com")
	s.Declare(redact.Secret, "alice@example.com")
	s.Declare(redact.PII, "alice@example.com")
	assert.Equal(t, "[REDACTED]", s.Scrub("alice@example.com"))

	process := redact.NewSet()
	process.Declare(redact.Secret, "the-client-secret")
	req := process.Child()
	req.Declare(redact.Identifier, "the-client-secret")
	assert.Equal(t, "[REDACTED]", req.Scrub("the-client-secret"), "a request cannot weaken a process secret")
}

func TestShortAndEmptyValuesAreIgnored(t *testing.T) {
	s := redact.NewSet()
	s.Declare(redact.Secret, "", "ui", "abc")
	s.Declare(redact.Identifier, "admin", "web-ui")
	assert.Equal(t, "build ui abc admin: web-ui", s.Scrub("build ui abc admin: web-ui"))
}

// A request's Set masks the process's values too, and sees those declared
// after it was made.
func TestChildMasksItsParents(t *testing.T) {
	process := redact.NewSet()
	process.Declare(redact.Secret, "gocspx-secret")
	req := process.Child()
	req.Declare(redact.PII, "bob@example.com")

	assert.Equal(t, "[REDACTED] b***@example.com", req.Scrub("gocspx-secret bob@example.com"))
	assert.Equal(t, "[REDACTED] bob@example.com", process.Scrub("gocspx-secret bob@example.com"), "a request's values stay in the request")

	process.Declare(redact.Secret, "late-secret")
	assert.Equal(t, "[REDACTED]", req.Scrub("late-secret"))
}

// A request that declared nothing masks what the process declared,
// including values the process declares later.
func TestChildWithoutValuesMasksTheProcess(t *testing.T) {
	process := redact.NewSet()
	process.Declare(redact.Secret, "gocspx-secret")
	req := process.Child()
	assert.Equal(t, "bad [REDACTED]", req.Scrub("bad gocspx-secret"))

	process.Declare(redact.PII, "bob@example.com")
	assert.Equal(t, "b***@example.com", req.Scrub("bob@example.com"))
	assert.Equal(t, "nothing declared", redact.NewSet().Child().Scrub("nothing declared"))
}

func TestNilSetAndContextWithoutASet(t *testing.T) {
	var s *redact.Set
	s.Declare(redact.Secret, "gocspx-secret")
	assert.Equal(t, "gocspx-secret", s.Scrub("gocspx-secret"))

	redact.Declare(context.Background(), redact.Secret, "gocspx-secret")
	assert.Nil(t, redact.FromContext(context.Background()))
}

func TestDeclareThroughContext(t *testing.T) {
	s := redact.NewSet()
	ctx := redact.NewContext(context.Background(), s)
	redact.Declare(ctx, redact.Secret, "refresh-token-value")
	assert.Same(t, s, redact.FromContext(ctx))
	assert.Equal(t, "got [REDACTED]", s.Scrub("got refresh-token-value"))
}

func TestConcurrentDeclareAndScrub(t *testing.T) {
	process := redact.NewSet()
	req := process.Child()
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			for j := range 100 {
				req.Declare(redact.Secret, "value-"+string(rune('a'+i))+string(rune('a'+j%26)))
				process.Declare(redact.Secret, "process-secret")
				_ = req.Scrub("value-aa process-secret")
			}
		})
	}
	wg.Wait()
	assert.Equal(t, "[REDACTED] [REDACTED]", req.Scrub("value-aa process-secret"))
}
