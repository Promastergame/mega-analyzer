package imageforensics

import "math"

// Shannon returns the Shannon entropy (in bits/byte) for the given data.
// Range is [0, 8]. Returns 0 for empty input.
func Shannon(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	total := float64(len(data))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / total
		h -= p * math.Log2(p)
	}
	if h < 0 {
		return 0
	}
	if h > 8 {
		return 8
	}
	return h
}
