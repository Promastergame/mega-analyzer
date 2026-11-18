package deobfuscation

import (
	"encoding/base64"
	"strings"
	"testing"
)

func encodeSaltedNibbleFixture(value string, enc *base64.Encoding) string {
	salt := []byte{0x32, 0x61, 0x87, 0x13, 0xa9, 0x4f}
	data := []byte(value)
	for round := 0; round < int(salt[0]&7)+1; round++ {
		for i, b := range data {
			x := (b ^ salt[i%6]) + salt[(i+1)%6]
			data[i] = x<<4 | x>>4
		}
	}
	return enc.EncodeToString(append(salt, data...))
}

func TestSaltedNibbleRecoversEndpointsWithProvenance(t *testing.T) {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		for _, want := range []string{"https://controller.example.org/gate", "198.51.100.42", "telemetry.example.cfd"} {
			got, transform := tryDecryptStringUncached(encodeSaltedNibbleFixture(want, enc))
			if got != want || !strings.Contains(transform, "/salted-nibble") {
				t.Fatalf("recovery = %q / %q, want %q and transform", got, transform, want)
			}
		}
	}
}

func TestSaltedNibbleRejectsShortAndOversizedPayloads(t *testing.T) {
	if decodeSaltedNibble(make([]byte, 10)) != nil || decodeSaltedNibble(make([]byte, (256<<10)+1)) != nil {
		t.Fatal("unbounded or ambiguous short payload accepted")
	}
	if got, _ := tryDecryptStringUncached(base64.StdEncoding.EncodeToString([]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAA"))); got != "" {
		t.Fatalf("opaque repeated data recovered as %q", got)
	}
}

func TestEncodedBlobCannotBecomeRawRotOrXORRecovery(t *testing.T) {
	// This printable Base64 encoding turns into a password-shaped raw string
	// under a Caesar rotation; its decoded bytes carry no such evidence.
	encoded := strings.Repeat("QUJD", 300) + "sdvvzrug" + strings.Repeat("QUJD", 300)
	if _, err := base64.StdEncoding.DecodeString(encoded); err != nil {
		t.Fatal(err)
	}
	if got, transform := tryDecryptStringUncached(encoded); got != "" {
		t.Fatalf("encoded binary invented a recovery (%d bytes) via %s", len(got), transform)
	}
}
