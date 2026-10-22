package keys

import (
	"context"
	"testing"
	"time"
)

// benchKeys is a production-shaped aggregate: a default 4096-bit keypair, so
// the benchmarks measure the key size tempogate actually signs with.
func benchKeys(b *testing.B) *Keys {
	b.Helper()
	k := New(WithStore(&fakeKeyStore{}))
	if err := k.Init(context.Background()); err != nil {
		b.Fatal(err)
	}
	return k
}

func BenchmarkSignerMint(b *testing.B) {
	ctx := context.Background()
	signer := NewSigner(WithKeys(benchKeys(b)), WithIssuer("https://tempogate.test"))
	req := MintRequest{Subject: "user:bench", Permissions: []string{"default:read"}, TTL: time.Hour}
	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := signer.Mint(ctx, req); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifierVerify(b *testing.B) {
	ctx := context.Background()
	k := benchKeys(b)
	signer := NewSigner(WithKeys(k), WithIssuer("https://tempogate.test"))
	verifier := NewVerifier(WithKeys(k), WithIssuer("https://tempogate.test"))
	signed, _, err := signer.Mint(ctx, MintRequest{Subject: "user:bench", TTL: time.Hour})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := verifier.Verify(ctx, signed); err != nil {
			b.Fatal(err)
		}
	}
}
