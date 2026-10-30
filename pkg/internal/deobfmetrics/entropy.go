package deobfmetrics

import "math"

// ShannonEntropy computes the Shannon entropy of a string in bits per
// character. It runs in a single pass over the runes of s.
//
// The result is always in the range [0, log2(n)] where n is the number of
// distinct runes, and is 0 for the empty string.
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]int)
	var length int
	for _, r := range s {
		freq[r]++
		length++
	}
	if length == 0 {
		return 0
	}

	fLen := float64(length)
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / fLen
		entropy -= p * math.Log2(p)
	}

	// Guard against -0.0 and any FP noise.
	if entropy <= 0 {
		return 0
	}
	return entropy
}
