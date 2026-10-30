package ensemble

import "math"

// ═══════════════════════════════════════════════════════════════════════════════
// ENTROPY
// ═══════════════════════════════════════════════════════════════════════════════
//
// Shannon entropy is bounded by log2(alphabet). For ASCII bodies the upper
// bound is ~7.0; for raw bytes it is 8.0. We cap at 8.0 to keep values
// comparable.

// shannonEntropy computes Shannon entropy in bits per symbol.
//
// Returns 0 for empty input. The result is bounded to [0..8].
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	var h float64
	n := float64(len(s))
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	if h > 8 {
		return 8
	}
	if h < 0 {
		return 0
	}
	return h
}

// bigramEntropy computes Shannon entropy over byte bigrams. Useful to
// distinguish structured text (low) from compressed/encrypted blobs (high).
func bigramEntropy(s string) float64 {
	if len(s) < 2 {
		return 0
	}
	counts := make(map[uint16]int, 1024)
	for i := 0; i < len(s)-1; i++ {
		key := uint16(s[i])<<8 | uint16(s[i+1])
		counts[key]++
	}
	n := float64(len(s) - 1)
	var h float64
	for _, c := range counts {
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	if h > 16 {
		return 16
	}
	if h < 0 {
		return 0
	}
	return h
}
