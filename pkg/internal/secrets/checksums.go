package secrets

import (
	"hash/crc32"
	"strings"
)

// Offline token-checksum validation. GitHub classic tokens (ghp_, gho_, ghu_,
// ghs_, ghr_) and npm tokens (npm_) end with a 6-character base62 encoding of
// the CRC32 (IEEE) of the 30 random characters before it. Checking it is pure
// arithmetic: no network, no provider API, nothing leaves the process. A valid
// checksum proves the string was minted by the real generator; an invalid one
// proves it is a hand-typed or corrupted example.

const b62Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

var checksumPrefixes = []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "npm_"}

// ChecksumResult reports the outcome of ValidateTokenChecksum.
type ChecksumResult struct {
	Applicable bool   // token shape carries an embedded checksum
	Valid      bool   // checksum matched
	Detail     string // human-readable explanation
}

// ValidateTokenChecksum validates the embedded CRC32 checksum of supported
// token formats, fully offline.
func ValidateTokenChecksum(token string) ChecksumResult {
	for _, p := range checksumPrefixes {
		if !strings.HasPrefix(token, p) {
			continue
		}
		body := token[len(p):]
		if len(body) != 36 {
			return ChecksumResult{}
		}
		random, sum := body[:30], body[30:]
		want := b62Encode(crc32.ChecksumIEEE([]byte(random)), 6)
		if sum == want {
			return ChecksumResult{Applicable: true, Valid: true, Detail: "embedded CRC32 checksum valid: token has a genuine generator format"}
		}
		return ChecksumResult{Applicable: true, Valid: false, Detail: "embedded CRC32 checksum mismatch: fabricated or corrupted token"}
	}
	return ChecksumResult{}
}

// b62Encode renders n as fixed-width base62, zero-padded on the left.
func b62Encode(n uint32, width int) string {
	buf := make([]byte, width)
	for i := width - 1; i >= 0; i-- {
		buf[i] = b62Alphabet[n%62]
		n /= 62
	}
	return string(buf)
}
