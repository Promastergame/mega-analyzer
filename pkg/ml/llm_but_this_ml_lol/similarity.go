package llmkeys

import (
	"fmt"
	"strings"
)

// Similarity/fingerprinting answers a question the plain classifier cannot:
// "are these two candidate secrets the same *kind* of thing?" That matters for
// reports. A binary might surface twenty tokens that are really one rotated key
// plus its test double plus eighteen framework GUIDs; grouping them by shape
// tells the analyst there is one interesting cluster, not twenty findings.
//
// Everything here is structural and offline: we compare the *shape* and
// *character n-gram profile* of values, never their meaning.

// Fingerprint returns a stable, coarse signature for value that collapses
// cosmetic differences (the concrete random characters) while preserving the
// structural identity (family, skeleton, size band, entropy band). Two values
// that a human would call "the same kind of token" share a Fingerprint.
//
// Format: "<family>|<shape>|L<lenBucket>|H<entBucket>"
func Fingerprint(value string) string {
	f := Extract(value)
	fam := f.Family
	if fam == "" {
		fam = "?"
	}
	return fmt.Sprintf("%s|%s|L%d|H%d", fam, f.Shape, lengthBucket(f.RuneLength), entropyBucket(f.Entropy))
}

// FingerprintFeatures is Fingerprint for an already-extracted Features value,
// avoiding a re-classification.
func FingerprintFeatures(f Features) string {
	fam := f.Family
	if fam == "" {
		fam = "?"
	}
	return fmt.Sprintf("%s|%s|L%d|H%d", fam, f.Shape, lengthBucket(f.RuneLength), entropyBucket(f.Entropy))
}

// lengthBucket maps a length to a coarse band so 31 and 32-char tokens group
// together. Bands: 0:<8, 1:8-15, 2:16-23, 3:24-31, 4:32-47, 5:48-63, 6:64-95,
// 7:96-127, 8:>=128.
func lengthBucket(n int) int {
	switch {
	case n < 8:
		return 0
	case n < 16:
		return 1
	case n < 24:
		return 2
	case n < 32:
		return 3
	case n < 48:
		return 4
	case n < 64:
		return 5
	case n < 96:
		return 6
	case n < 128:
		return 7
	default:
		return 8
	}
}

// entropyBucket maps entropy (bits/rune) to an integer band (0..6+) by
// half-bit steps around the interesting 2.5-5.5 range.
func entropyBucket(h float64) int {
	b := int((h - 2.0) * 2.0)
	if b < 0 {
		b = 0
	}
	if b > 8 {
		b = 8
	}
	return b
}

// Similarity returns a structural similarity score in [0,1] between two values.
// 1.0 means structurally identical (same family, same shape, near-identical
// n-gram profile); 0.0 means nothing in common. It combines three signals:
//
//	0.50  character trigram Jaccard overlap (captures shared prefixes/bodies)
//	0.30  shape-skeleton similarity        (captures common layout)
//	0.20  same detected credential family  (captures semantic kinship)
func Similarity(a, b string) float64 {
	fa, fb := Extract(a), Extract(b)
	return similarityFeatures(a, b, fa, fb)
}

// SimilarityFeatures is Similarity for two already-extracted Features, given
// their original values (needed for the n-gram comparison).
func SimilarityFeatures(aVal, bVal string, fa, fb Features) float64 {
	return similarityFeatures(aVal, bVal, fa, fb)
}

func similarityFeatures(a, b string, fa, fb Features) float64 {
	if a == b {
		return 1.0
	}
	tri := trigramJaccard(a, b)
	shape := shapeSimilarity(fa.Shape, fb.Shape)
	fam := 0.0
	if fa.HasFamily && fb.HasFamily && fa.Family == fb.Family {
		fam = 1.0
	}
	return clamp(0.50*tri+0.30*shape+0.20*fam, 0.0, 1.0)
}

// trigramJaccard is the Jaccard index of the sets of character 3-grams of a
// and b. Short strings (<3 runes) fall back to a set of the whole string.
func trigramJaccard(a, b string) float64 {
	sa, sb := trigrams(a), trigrams(b)
	if len(sa) == 0 && len(sb) == 0 {
		return 1.0
	}
	if len(sa) == 0 || len(sb) == 0 {
		return 0.0
	}
	inter := 0
	small, large := sa, sb
	if len(large) < len(small) {
		small, large = large, small
	}
	for g := range small {
		if large[g] {
			inter++
		}
	}
	union := len(sa) + len(sb) - inter
	if union == 0 {
		return 0.0
	}
	return float64(inter) / float64(union)
}

func trigrams(s string) map[string]bool {
	runes := []rune(s)
	set := make(map[string]bool)
	if len(runes) < 3 {
		if len(runes) > 0 {
			set[s] = true
		}
		return set
	}
	for i := 0; i+3 <= len(runes); i++ {
		set[string(runes[i:i+3])] = true
	}
	return set
}

// shapeSimilarity compares two shape skeletons with a normalized Levenshtein
// similarity (1 - editDistance/maxLen).
func shapeSimilarity(a, b string) float64 {
	if a == b {
		return 1.0
	}
	maxLen := len(a)
	if len(b) > maxLen {
		maxLen = len(b)
	}
	if maxLen == 0 {
		return 1.0
	}
	d := levenshtein(a, b)
	return 1.0 - float64(d)/float64(maxLen)
}

// levenshtein returns the edit distance between two short ASCII strings
// (shape skeletons), using a single-row rolling buffer.
func levenshtein(a, b string) int {
	if a == b {
		return 0
	}
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur := make([]int, len(b)+1)
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min3(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(b)]
}

func min3(a, b, c int) int {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}

// commonPrefixLen counts shared leading runes (used by insights to spot
// key-rotation families like sk-live_… vs sk-test_…).
func commonPrefixLen(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	n := 0
	for n < len(ra) && n < len(rb) && ra[n] == rb[n] {
		n++
	}
	return n
}

// NormalizedValue lowercases and trims a value for grouping keys. Exposed so
// callers building their own maps use the same canonical form as the package.
func NormalizedValue(v string) string { return strings.ToLower(strings.TrimSpace(v)) }
