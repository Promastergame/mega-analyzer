package media

// SimilarityResult describes how similar two files are.
type SimilarityResult struct {
	Similarity float64 `json:"similarity"` // 0.0 = completely different, 1.0 = identical
	Method     string  `json:"method"`     // "byte_hash", "byte_diff_hash", "metadata_match"
	Evidence   string  `json:"evidence"`
}

// ByteDifferenceHash computes an 8-byte difference hash over the FIRST 64
// RAW BYTES of the input. Each bit records whether one byte is greater than
// the next.
//
// NOTE: despite the dHash-style structure, this operates on undecoded file
// bytes, NOT on decoded image pixels. It is therefore only a coarse
// byte-layout fingerprint and must not be mistaken for a true perceptual
// (visual) image hash. It was previously misnamed PerceptualHash, which
// overstated its capabilities.
func ByteDifferenceHash(data []byte) [8]byte {
	var hash [8]byte
	if len(data) < 64 {
		return hash
	}

	// Compare adjacent raw bytes in the first 8x8 window. Each bit represents
	// whether the left byte is greater than the right byte.
	for row := 0; row < 8; row++ {
		for col := 0; col < 7; col++ {
			idx := row*8 + col
			if idx+1 < len(data) && data[idx] > data[idx+1] {
				hash[row] |= 1 << uint(col)
			}
		}
	}
	return hash
}

// HammingDistance counts the number of differing bits between two hashes.
func HammingDistance(a, b [8]byte) int {
	dist := 0
	for i := 0; i < 8; i++ {
		xor := a[i] ^ b[i]
		for xor != 0 {
			dist++
			xor &= xor - 1
		}
	}
	return dist
}

// CompareBytes compares two byte slices for exact or near-exact similarity.
//
// It reports 1.0 for byte-identical inputs. Otherwise it estimates overlap by
// comparing bytes at the SAME positions (positionally aligned sampling, with
// stride sampling for large inputs). This is NOT a rolling hash and NOT a
// true longest-common-subsequence: it is position-sensitive, so inserting or
// deleting bytes (which shifts everything downstream) will report low
// similarity even for otherwise near-identical files.
func CompareBytes(a, b []byte) SimilarityResult {
	if len(a) == 0 && len(b) == 0 {
		return SimilarityResult{Similarity: 1.0, Method: "byte_hash", Evidence: "Both empty"}
	}
	if len(a) == 0 || len(b) == 0 {
		return SimilarityResult{Similarity: 0.0, Method: "byte_hash", Evidence: "One file empty"}
	}

	// Exact match
	if len(a) == len(b) {
		match := true
		for i := range a {
			if a[i] != b[i] {
				match = false
				break
			}
		}
		if match {
			return SimilarityResult{Similarity: 1.0, Method: "byte_hash", Evidence: "Byte-identical files"}
		}
	}

	// Positionally aligned similarity: count bytes that match at the same
	// offset, up to the shorter length (with stride sampling for speed on
	// large inputs). This is intentionally simple and position-sensitive.
	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}

	var matches int
	sampleStep := 1
	if minLen > 10000 {
		sampleStep = minLen / 10000 // sample for performance
	}

	for i := 0; i < minLen; i += sampleStep {
		if a[i] == b[i] {
			matches++
		}
	}
	sampled := (minLen + sampleStep - 1) / sampleStep
	ratio := float64(matches) / float64(sampled)

	similarity := Clamp(ratio)
	evidence := ""
	if similarity > 0.95 {
		evidence = "Near-identical content"
	} else if similarity > 0.7 {
		evidence = "Significant content overlap"
	} else if similarity > 0.3 {
		evidence = "Partial content similarity"
	} else {
		evidence = "Different content"
	}

	return SimilarityResult{Similarity: similarity, Method: "byte_hash", Evidence: evidence}
}

// CompareMetadata checks if two AnalysisResults share metadata indicators
// that suggest they came from the same device or were created by the same
// tool.
func CompareMetadata(a, b AnalysisResult) SimilarityResult {
	var matches []string
	total := 0

	getField := func(r AnalysisResult, key string) string {
		if r.Classification.RecoveredData != nil {
			return r.Classification.RecoveredData[key]
		}
		return ""
	}

	// Camera serial number match (strongest indicator)
	serialA := getField(a, "BodySerialNumber")
	serialB := getField(b, "BodySerialNumber")
	if serialA != "" && serialA == serialB {
		matches = append(matches, "identical camera serial number")
	}
	total++

	// Camera make/model match
	makeA := getField(a, "Camera_Make")
	makeB := getField(b, "Camera_Make")
	modelA := getField(a, "Camera_Model")
	modelB := getField(b, "Camera_Model")
	if makeA != "" && makeA == makeB && modelA != "" && modelA == modelB {
		matches = append(matches, "identical camera make/model")
	}
	total++

	// Software match
	swA := getField(a, "Software")
	swB := getField(b, "Software")
	if swA != "" && swA == swB {
		matches = append(matches, "identical software tag")
	}
	total++

	if total == 0 {
		return SimilarityResult{Similarity: 0.0, Method: "metadata_match", Evidence: "No comparable metadata"}
	}

	ratio := float64(len(matches)) / float64(total)
	return SimilarityResult{Similarity: ratio, Method: "metadata_match", Evidence: joinStrings(matches)}
}

func joinStrings(ss []string) string {
	if len(ss) == 0 {
		return ""
	}
	result := ss[0]
	for _, s := range ss[1:] {
		result += ", " + s
	}
	return result
}
