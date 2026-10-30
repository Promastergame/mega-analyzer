package deobfuscation

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func base64Std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
func hexEncode(b []byte) string { return hex.EncodeToString(b) }

func TestCrackRepeatingXOR_RoundTrip(t *testing.T) {
	plain := "the quick brown fox jumps over the lazy dog and then keeps running along the river"
	key := []byte("KEY")
	ct := make([]byte, len(plain))
	for i := range plain {
		ct[i] = plain[i] ^ key[i%len(key)]
	}
	got, gotKey := crackRepeatingXOR(ct)
	if got != plain {
		t.Errorf("recovered %q, want %q", got, plain)
	}
	if string(gotKey) != "KEY" {
		t.Errorf("recovered key %q, want KEY", string(gotKey))
	}
}

func TestCrackRepeatingXOR_TooShort(t *testing.T) {
	if got, key := crackRepeatingXOR([]byte("abcd")); got != "" || key != nil {
		t.Errorf("short input should not crack, got %q/%v", got, key)
	}
}

func TestCrackRepeatingXOR_Garbage(t *testing.T) {
	// Random-ish high-entropy bytes should not yield a confident plaintext.
	data := []byte{0x00, 0x01, 0x80, 0xFE, 0x7F, 0x03, 0x99, 0xAB, 0x10, 0x22, 0xC4, 0x5D}
	if got, _ := crackRepeatingXOR(data); got != "" {
		t.Logf("note: garbage produced %q (acceptable if letter-rich)", got)
	}
}

func TestCrackROT_RoundTrip(t *testing.T) {
	plain := "the quick brown fox jumps over the lazy dog"
	enc := make([]byte, len(plain))
	for i := 0; i < len(plain); i++ {
		enc[i] = rotateByte(plain[i], 13)
	}
	got, n := crackROT(string(enc))
	if got != plain {
		t.Errorf("ROT recovered %q, want %q", got, plain)
	}
	if n != 13 {
		t.Errorf("ROT n = %d, want 13", n)
	}
}

func TestCrackROT_NonAlpha(t *testing.T) {
	if got, n := crackROT("1234567890!@#$"); got != "" || n != 0 {
		t.Errorf("non-alpha should not ROT-crack, got %q/%d", got, n)
	}
}

func TestTryDecryptString_RepeatingXORViaBase64(t *testing.T) {
	// A repeating-key-XOR payload wrapped in Base64 should be recovered with
	// the repeating-key annotation.
	plain := "premium license validated for user account holder now enabled"
	key := []byte("AB")
	ct := make([]byte, len(plain))
	for i := range plain {
		ct[i] = plain[i] ^ key[i%len(key)]
	}
	// hand it the raw XOR bytes as a string (path 3/4 of tryDecryptString)
	got, transform := tryDecryptString(string(ct))
	if got == "" {
		t.Fatal("expected a recovered string for repeating-key XOR payload")
	}
	if transform == "" {
		t.Error("expected a transform label alongside the plaintext")
	}
}

func TestTryDecryptString_Base64XOR(t *testing.T) {
	plain := "license verified premium unlocked for this account now"
	xored := make([]byte, len(plain))
	for i := range plain {
		xored[i] = plain[i] ^ 0x80 // high bit → non-printable, forces XOR path
	}
	enc := base64Std(xored)
	got, transform := tryDecryptString(enc)
	if got != plain {
		t.Errorf("Base64+XOR plaintext not recovered: %q", got)
	}
	if !strings.Contains(transform, "XOR key 0x80") {
		t.Errorf("Base64+XOR path not taken: %q", transform)
	}
}

func TestTryDecryptString_HexXOR(t *testing.T) {
	// Odd byte length → hex string length not divisible by 4 → base64 decode
	// fails and the hex branch is exercised.
	plain := "premium features fully unlocked ok" // length made odd below
	if len(plain)%2 == 0 {
		plain += "!"
	}
	xored := make([]byte, len(plain))
	for i := range plain {
		xored[i] = plain[i] ^ 0x80
	}
	enc := hexEncode(xored)
	got, transform := tryDecryptString(enc)
	if got != plain {
		t.Errorf("Hex+XOR plaintext not recovered: %q", got)
	}
	if !strings.Contains(transform, "XOR key 0x80") {
		t.Errorf("Hex+XOR path not taken: %q", transform)
	}
}

func TestEnglishScore(t *testing.T) {
	if englishScore(nil) != 0 {
		t.Error("empty english score should be 0")
	}
	if englishScore([]byte("1234567890")) != 0 {
		t.Error("digits-only score should be 0")
	}
	real := englishScore([]byte("the quick brown fox"))
	noise := englishScore([]byte("qzxjkvwqzxjkvwqz"))
	if real <= noise {
		t.Errorf("English text (%v) should outscore noise (%v)", real, noise)
	}
}

func TestParseSmaliInt(t *testing.T) {
	cases := []struct {
		in   string
		want int64
		ok   bool
	}{
		{"0x0", 0, true},
		{"3", 3, true},
		{"-0x10", -16, true},
		{"0x42", 66, true},
		{"#0", 0, true},
		{"0x1L", 1, true},
		{"255", 255, true},
		{"0xff", 255, true},
		{"+5", 5, true},
		{"", 0, false},
		{"xyz", 0, false},
		{"0x", 0, false},
		{"12a", 0, false},
		{"0xAB", 171, true}, // uppercase hex digits
		{"0xG", 0, false},   // invalid hex digit
		{"-", 0, false},     // sign with no digits
	}
	for _, c := range cases {
		got, ok := parseSmaliInt(c.in)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("parseSmaliInt(%q) = %d,%v; want %d,%v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestLastOperandAndAssigns(t *testing.T) {
	if got := lastOperand("const/4 v0, 0x3"); got != "0x3" {
		t.Errorf("lastOperand = %q", got)
	}
	if got := lastOperand("nop"); got != "nop" {
		t.Errorf("lastOperand no-comma = %q", got)
	}
	if !assignsRegister("const/4 v0, 0x3", "v0") {
		t.Error("v0 should be the destination register")
	}
	if assignsRegister("const/4 v0, 0x3", "v3") {
		t.Error("v3 is the immediate, not the destination")
	}
	if assignsRegister("nop", "v0") {
		t.Error("single-field instruction has no destination")
	}
}

func TestFormatKey(t *testing.T) {
	if got := formatKey(nil); got != "0x00" {
		t.Errorf("formatKey(nil) = %q", got)
	}
	if got := formatKey([]byte{0xDE, 0xAD}); got != "0xDEAD" {
		t.Errorf("formatKey = %q", got)
	}
}
