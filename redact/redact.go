// Package redact keeps declared secrets and personal data out of what
// tempogate exports. Code that handles a sensitive value declares it, with
// the Rule that says how it may be shown; whatever exports free text (today
// the error messages on failed spans, later the logs) passes it through
// Scrub, which masks every declared value it finds.
//
// Matching text, not types, is the point: an error from a library quotes
// values tempogate never formatted itself (go-oidc quotes the audience it
// refused, a database the value it rejected), and only a scan of the final
// text can catch those. It catches only what was declared, as declared: a
// value quoted in another encoding (URL-escaped, base64) or case is missed
// unless that form is declared too.
package redact

import (
	"cmp"
	"context"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"
)

// Rule says how a declared value is shown wherever it would appear. When a
// value is declared under several rules the strongest wins, wherever each
// was declared.
type Rule struct {
	mask     func(string) string
	strength int
	// minLen is the shortest value the rule masks: shorter ones are too
	// common to mask without mangling unrelated text ("ui" is in "build").
	minLen int
}

var (
	// Secret replaces a credential outright: client secrets, codes, tokens,
	// session ids, keys.
	Secret = Rule{mask: func(string) string { return "[REDACTED]" }, strength: 3, minLen: 4}
	// PII shows an email address as its first letter and its domain
	// ("a***@example.com"), and any other personal value as "***".
	PII = Rule{mask: maskPII, strength: 2, minLen: 4}
	// Identifier shows a value that is not secret but should not be
	// exported whole, such as a client ID, as a short prefix, never more
	// than a third of it ("tempog***"). Values shorter than 8 bytes are
	// left alone: operators name clients "admin" or "web", words that
	// appear in ordinary text.
	Identifier = Rule{mask: keepPrefix(6), strength: 1, minLen: 8}
)

// Mask returns how r shows v.
func (r Rule) Mask(v string) string { return r.mask(v) }

func keepPrefix(n int) func(string) string {
	return func(v string) string {
		keep := min(n, utf8.RuneCountInString(v)/3)
		i := 0
		for range keep {
			_, size := utf8.DecodeRuneInString(v[i:])
			i += size
		}
		return v[:i] + "***"
	}
}

func maskPII(v string) string {
	local, domain, ok := strings.Cut(v, "@")
	if !ok || local == "" || domain == "" {
		return "***"
	}
	_, size := utf8.DecodeRuneInString(local)
	return local[:size] + "***@" + domain
}

// Set holds declared values. A request's Set is a child of the process Set,
// so it masks the process's static secrets as well as its own. A Set is safe
// for concurrent use; a nil *Set declares nothing and scrubs nothing.
type Set struct {
	parent *Set

	mu      sync.Mutex
	values  map[string]Rule
	version uint64

	// The replacer is rebuilt only after a Declare here or in a parent.
	cached        *strings.Replacer
	cachedVersion uint64
}

func NewSet() *Set { return &Set{} }

// Child returns a new Set that also masks everything s masks.
func (s *Set) Child() *Set { return &Set{parent: s} }

// Declare marks values as sensitive, shown by r. Empty values and values
// shorter than r allows are ignored. A value declared again keeps the
// stronger rule; re-declaring one under the same rule (a DSN re-read for
// each connection) costs nothing.
func (s *Set) Declare(r Rule, values ...string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range values {
		if v == "" || len(v) < r.minLen {
			continue
		}
		if prev, ok := s.values[v]; ok && prev.strength >= r.strength {
			continue
		}
		if s.values == nil {
			s.values = map[string]Rule{}
		}
		s.values[v] = r
		s.version++
	}
}

// Scrub returns text with every declared value masked. Where declared values
// overlap, the longest wins, and masked text is never scanned again.
func (s *Set) Scrub(text string) string {
	if s == nil || text == "" {
		return text
	}
	r := s.replacer()
	if r == nil {
		return text
	}
	return r.Replace(text)
}

// replacer returns a replacer for every value declared here and in the
// parents, or nil when there are none.
func (s *Set) replacer() *strings.Replacer {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.values) == 0 && s.parent != nil {
		// A request that declared nothing masks what the process does;
		// the process's replacer is cached across requests.
		return s.parent.replacer()
	}
	v := s.versionLocked()
	if v == 0 || s.cachedVersion == v {
		return s.cached
	}
	// Values are never removed, so a non-zero version means some exist.
	merged := map[string]Rule{}
	s.collectLocked(merged)
	s.cachedVersion = v
	values := make([]string, 0, len(merged))
	for value := range merged {
		values = append(values, value)
	}
	// strings.Replacer tries its pairs in argument order at each position,
	// so the longest value is matched first.
	slices.SortFunc(values, func(a, b string) int {
		return cmp.Or(cmp.Compare(len(b), len(a)), strings.Compare(a, b))
	})
	pairs := make([]string, 0, 2*len(values))
	for _, value := range values {
		pairs = append(pairs, value, merged[value].Mask(value))
	}
	s.cached = strings.NewReplacer(pairs...)
	return s.cached
}

// versionLocked sums the versions of s and its parents: it changes whenever
// any of them declares something.
func (s *Set) versionLocked() uint64 {
	v := s.version
	for p := s.parent; p != nil; p = p.parent {
		p.mu.Lock()
		v += p.version
		p.mu.Unlock()
	}
	return v
}

// collectLocked merges the values of s and its parents, keeping the
// strongest rule for a value declared in more than one.
func (s *Set) collectLocked(into map[string]Rule) {
	add := func(values map[string]Rule) {
		for v, r := range values {
			if prev, ok := into[v]; !ok || r.strength > prev.strength {
				into[v] = r
			}
		}
	}
	for p := s.parent; p != nil; p = p.parent {
		p.mu.Lock()
		add(p.values)
		p.mu.Unlock()
	}
	add(s.values)
}

type setKey struct{}

// NewContext returns ctx carrying s, which Declare and FromContext find.
func NewContext(ctx context.Context, s *Set) context.Context {
	return context.WithValue(ctx, setKey{}, s)
}

// FromContext returns the Set ctx carries, or nil.
func FromContext(ctx context.Context) *Set {
	s, _ := ctx.Value(setKey{}).(*Set)
	return s
}

// Declare marks values as sensitive in the Set ctx carries. Without one (no
// exporter needs it) it does nothing, so declaring is free when nothing
// would export the value.
func Declare(ctx context.Context, r Rule, values ...string) {
	FromContext(ctx).Declare(r, values...)
}
