package deobfuscation

import (
	"math"
	"testing"
)

func TestShannonEntropy(t *testing.T) {
	if got := shannonEntropy(nil); got != 0 {
		t.Errorf("empty entropy = %v, want 0", got)
	}
	if got := shannonEntropy([]byte("AAAAAAAA")); got != 0 {
		t.Errorf("uniform entropy = %v, want 0", got)
	}
	// Two equally frequent symbols → exactly 1 bit/byte.
	if got := shannonEntropy([]byte("ABABABAB")); math.Abs(got-1.0) > 1e-9 {
		t.Errorf("two-symbol entropy = %v, want 1.0", got)
	}
	// 8 distinct bytes → 3 bits/byte.
	if got := shannonEntropy([]byte("ABCDEFGH")); math.Abs(got-3.0) > 1e-9 {
		t.Errorf("eight-symbol entropy = %v, want 3.0", got)
	}
}

func TestClassifyEncoding(t *testing.T) {
	cases := []struct {
		in   string
		want EncodingKind
	}{
		{"SGVsbG8gV29ybGQgVGVzdA==", EncodingBase64},
		{"deadbeefdeadbeef", EncodingHex},
		{"hello there friend", EncodingPlain},
		{"!@#$%^&*()_+{}|:<>?", EncodingHighEntropy},
		{"banana", EncodingPlain},
	}
	for _, c := range cases {
		if got := classifyEncoding(c.in); got != c.want {
			t.Errorf("classifyEncoding(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestEncodingKindString(t *testing.T) {
	cases := map[EncodingKind]string{
		EncodingPlain:       "plain",
		EncodingBase64:      "base64",
		EncodingHex:         "hex",
		EncodingHighEntropy: "high-entropy",
		EncodingUnknown:     "unknown",
		EncodingKind(200):   "unknown",
	}
	for k, want := range cases {
		if got := k.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", k, got, want)
		}
	}
}

func TestCharsetHelpers(t *testing.T) {
	if !isBase64Charset("ab+/=-_09") {
		t.Error("valid base64 charset rejected")
	}
	if isBase64Charset("hello world") {
		t.Error("string with space accepted as base64")
	}
	if isBase64Charset("") {
		t.Error("empty accepted as base64")
	}
	if !isHexCharset("00ffAB") {
		t.Error("valid hex rejected")
	}
	if isHexCharset("00fg") {
		t.Error("non-hex accepted")
	}
	if uniqueRuneRatio("") != 0 {
		t.Error("empty unique ratio should be 0")
	}
	if uniqueRuneRatio("aaaa") != 0.25 {
		t.Errorf("unique ratio of 'aaaa' = %v, want 0.25", uniqueRuneRatio("aaaa"))
	}
}
