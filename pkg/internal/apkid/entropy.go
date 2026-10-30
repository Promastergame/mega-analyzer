package apkid

import "math"

// ShannonEntropy computes the Shannon entropy of data in bits per byte
// (range [0.0, 8.0]). Returns 0 for empty input.
//
// Formula: H = -Σ p(x) · log₂(p(x))  over all byte values x in [0,255].
func ShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var freq [256]int
	for _, b := range data {
		freq[b]++
	}
	n := float64(len(data))
	var h float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// isHighEntropy returns true when the first scanBytes bytes of data have
// Shannon entropy above the given threshold.
func isHighEntropy(data []byte, scanBytes int, threshold float64) bool {
	if len(data) == 0 {
		return false
	}
	sample := data
	if len(sample) > scanBytes {
		sample = sample[:scanBytes]
	}
	return ShannonEntropy(sample) >= threshold
}
