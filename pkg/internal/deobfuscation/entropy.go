package deobfuscation

import "math"

// ═══════════════════════════════════════════════════════════════════════════════
// ENTROPY & ENCODING CLASSIFICATION
// ═══════════════════════════════════════════════════════════════════════════════
//
// Obfuscators hide payloads as Base64/hex blobs or high-entropy ciphertext. A
// cheap, allocation-free entropy estimate lets us rank candidate literals and
// classify how they are most likely encoded before we spend effort trying to
// decrypt them.

// EncodingKind classifies the most likely surface encoding of a literal.
type EncodingKind uint8

const (
	// EncodingPlain is human-readable text with low entropy.
	EncodingPlain EncodingKind = iota
	// EncodingBase64 matches the Base64 alphabet with a length divisible by 4.
	EncodingBase64
	// EncodingHex matches the hexadecimal alphabet with an even length.
	EncodingHex
	// EncodingHighEntropy is neither Base64 nor hex but has entropy typical of
	// packed or encrypted data.
	EncodingHighEntropy
	// EncodingUnknown is used when no classification is confident.
	EncodingUnknown
)

func (k EncodingKind) String() string {
	switch k {
	case EncodingPlain:
		return "plain"
	case EncodingBase64:
		return "base64"
	case EncodingHex:
		return "hex"
	case EncodingHighEntropy:
		return "high-entropy"
	default:
		return "unknown"
	}
}

// shannonEntropy returns the Shannon entropy of data in bits per byte (0..8).
// An empty slice has zero entropy. The computation is a single pass with a
// fixed-size histogram, so it never allocates on the heap.
func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var freq [256]int
	for _, b := range data {
		freq[b]++
	}
	n := float64(len(data))
	entropy := 0.0
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// isBase64Charset reports whether every rune in s is part of the standard or
// URL-safe Base64 alphabet (including padding).
func isBase64Charset(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch >= 'A' && ch <= 'Z',
			ch >= 'a' && ch <= 'z',
			ch >= '0' && ch <= '9',
			ch == '+', ch == '/', ch == '=', ch == '-', ch == '_':
		default:
			return false
		}
	}
	return true
}

// isHexCharset reports whether every rune in s is a hexadecimal digit.
func isHexCharset(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch >= '0' && ch <= '9',
			ch >= 'a' && ch <= 'f',
			ch >= 'A' && ch <= 'F':
		default:
			return false
		}
	}
	return true
}

// uniqueRuneRatio returns the fraction of distinct byte values in s.
func uniqueRuneRatio(s string) float64 {
	if s == "" {
		return 0
	}
	var seen [256]bool
	unique := 0
	for i := 0; i < len(s); i++ {
		if !seen[s[i]] {
			seen[s[i]] = true
			unique++
		}
	}
	return float64(unique) / float64(len(s))
}

// classifyEncoding inspects a string and reports its most likely surface
// encoding. Hex is preferred over Base64 when both match because the hex
// alphabet is a strict subset of Base64 and the even-length + all-hex shape is
// a stronger signal.
func classifyEncoding(s string) EncodingKind {
	if len(s) < minEncryptedLen {
		if uniqueRuneRatio(s) > highEntropyUniqueRatio {
			return EncodingHighEntropy
		}
		return EncodingPlain
	}
	if isHexCharset(s) && len(s)%2 == 0 {
		return EncodingHex
	}
	if isBase64Charset(s) && len(s)%4 == 0 {
		return EncodingBase64
	}
	if isBase64Charset(s) {
		return EncodingBase64
	}
	if uniqueRuneRatio(s) > highEntropyUniqueRatio {
		return EncodingHighEntropy
	}
	return EncodingPlain
}
