package semai

import (
	"strings"
	"testing"
)

func TestEncoderFingerprintAndUntruncatedCount(t *testing.T) {
	t.Setenv("DAI_NO_NIM", "1")
	raw := wordShareFixture(t)
	a, err := ParseEncoder(raw)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseEncoder(append([]byte(nil), raw...))
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Fingerprint()) != 64 || a.Fingerprint() != b.Fingerprint() {
		t.Fatal("unstable weight identity")
	}
	text := strings.Repeat("hello ", a.maxPos*2)
	if a.TokenCount(text) <= len(a.Tokenize(text, 1<<20)) {
		t.Fatal("token count silently capped at maxPos")
	}
	raw = append(raw, 'x') // Fingerprint covers the exact file, including trailing bytes.
	c, err := ParseEncoder(raw)
	if err != nil {
		t.Fatal(err)
	}
	if c.Fingerprint() == a.Fingerprint() {
		t.Fatal("different files share a fingerprint")
	}
}
