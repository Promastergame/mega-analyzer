// Package piracy — wordmatch.go
// Literal word-boundary matching without the regexp engine.
package piracy

import "bytes"

// isWordByteAt reports whether the byte at i is an ASCII word byte.
// Out-of-range positions count as non-word, mirroring the start/end of input
// behaviour of Go's \b assertion.
func isWordByteAt(b []byte, i int) bool {
	if i < 0 || i >= len(b) {
		return false
	}
	return isASCIIWordByte(b[i])
}

// wordIndex returns the offset of the first occurrence of pat in content that
// is delimited by ASCII word boundaries, or -1.
//
// It reproduces exactly what `regexp.MustCompile("(?i)\\b"+QuoteMeta(v)+"\\b")`
// used to do on already-lowercased input, without paying for the regexp engine.
// Go's \b is ASCII-only: a boundary exists where the wordness of the two
// adjacent bytes differs, and any byte >= 0x80 is non-word.
func wordIndex(content, pat []byte) int {
	if len(pat) == 0 || len(content) < len(pat) {
		return -1
	}

	firstIsWord := isASCIIWordByte(pat[0])
	lastIsWord := isASCIIWordByte(pat[len(pat)-1])

	for from := 0; from <= len(content)-len(pat); {
		rel := bytes.Index(content[from:], pat)
		if rel < 0 {
			return -1
		}
		abs := from + rel

		leftOK := isWordByteAt(content, abs-1) != firstIsWord
		rightOK := isWordByteAt(content, abs+len(pat)) != lastIsWord
		if leftOK && rightOK {
			return abs
		}
		from = abs + 1
	}
	return -1
}
