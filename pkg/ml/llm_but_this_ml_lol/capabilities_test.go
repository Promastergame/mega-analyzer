package llmkeys

import (
	"testing"
)

// ── Feature extraction ────────────────────────────────────────────────────────

func TestExtractFeaturesBasic(t *testing.T) {
	f := ExtractFeaturesOnly("Ab12-Cd34")
	if f.Length != 9 || f.RuneLength != 9 {
		t.Errorf("length = %d/%d, want 9/9", f.Length, f.RuneLength)
	}
	if f.Uppers != 2 || f.Lowers != 2 || f.Digits != 4 || f.Symbols != 1 {
		t.Errorf("class counts wrong: U=%d L=%d D=%d S=%d", f.Uppers, f.Lowers, f.Digits, f.Symbols)
	}
	if f.Segments != 2 {
		t.Errorf("segments = %d, want 2", f.Segments)
	}
	if f.Shape != "Aa0-Aa0" {
		t.Errorf("shape = %q, want %q", f.Shape, "Aa0-Aa0")
	}
	if f.UniqueRatio <= 0 || f.UniqueRatio > 1 {
		t.Errorf("unique ratio out of range: %f", f.UniqueRatio)
	}
}

func TestExtractFillsVerdict(t *testing.T) {
	f := Extract("AKIA1B2C3D4E5F6G7H8J")
	if !f.IsSecret || f.Family != "aws" {
		t.Errorf("Extract secret fields wrong: IsSecret=%v family=%q", f.IsSecret, f.Family)
	}
	if !f.HasFamily {
		t.Error("HasFamily should be true for a matched family")
	}
}

func TestExtractEmpty(t *testing.T) {
	f := ExtractFeaturesOnly("")
	if f.RuneLength != 0 || f.Shape != "" || f.Segments != 0 {
		t.Errorf("empty features not zero: %+v", f)
	}
}

func TestMaxRun(t *testing.T) {
	f := ExtractFeaturesOnly("aaabbccccd")
	if f.MaxRun != 4 {
		t.Errorf("MaxRun = %d, want 4", f.MaxRun)
	}
}

// ── Cache ─────────────────────────────────────────────────────────────────────

func TestClassifyCachedMatchesClassify(t *testing.T) {
	ResetCache()
	values := []string{
		"AKIA1B2C3D4E5F6G7H8J", "123456789", "sk-ant-Xy12Zw34Vu56Ts78Rq90PoNmLkJiHg",
		"your_key_here", "ghp_AbC1dEf2GhI3jKl4MnO5pQr6StU7vWx8",
	}
	for _, v := range values {
		want := Classify(v)
		got := ClassifyCached(v)
		if got.IsSecret != want.IsSecret || got.Family != want.Family || got.Confidence != want.Confidence {
			t.Errorf("ClassifyCached(%q) = %+v, want %+v", v, got, want)
		}
	}
}

func TestCacheHitsAccumulate(t *testing.T) {
	ResetCache()
	for i := 0; i < 5; i++ {
		ClassifyCached("AKIA1B2C3D4E5F6G7H8J")
	}
	hits, misses, size := CacheStats()
	if misses != 1 {
		t.Errorf("misses = %d, want 1", misses)
	}
	if hits != 4 {
		t.Errorf("hits = %d, want 4", hits)
	}
	if size != 1 {
		t.Errorf("size = %d, want 1", size)
	}
}

func TestCacheEviction(t *testing.T) {
	c := newVerdictCache(3)
	c.put("a", Verdict{Family: "a"})
	c.put("b", Verdict{Family: "b"})
	c.put("c", Verdict{Family: "c"})
	// touch "a" so it is most-recently-used, then insert "d": "b" should be evicted.
	c.get("a")
	c.put("d", Verdict{Family: "d"})
	if _, ok := c.get("b"); ok {
		t.Error("expected 'b' to be evicted as least-recently-used")
	}
	if _, ok := c.get("a"); !ok {
		t.Error("expected 'a' to survive (recently used)")
	}
}

func TestClassifyBatchDedup(t *testing.T) {
	in := []string{"AKIA1B2C3D4E5F6G7H8J", "AKIA1B2C3D4E5F6G7H8J", "123456789"}
	out := ClassifyBatch(in)
	if len(out) != 3 {
		t.Fatalf("len = %d, want 3", len(out))
	}
	if !out[0].IsSecret || !out[1].IsSecret || out[2].IsSecret {
		t.Errorf("batch verdicts wrong: %v", out)
	}
}

// ── Similarity & fingerprint ──────────────────────────────────────────────────

func TestSimilarityIdentical(t *testing.T) {
	if s := Similarity("AKIA1B2C3D4E5F6G7H8J", "AKIA1B2C3D4E5F6G7H8J"); s != 1.0 {
		t.Errorf("identical similarity = %f, want 1.0", s)
	}
}

func TestSimilaritySameFamilyHigher(t *testing.T) {
	// Two AWS keys should be more similar than an AWS key and a GitHub token.
	aws1 := "AKIA1B2C3D4E5F6G7H8J"
	aws2 := "AKIA9Z8Y7X6W5V4U3T2S"
	gh := "ghp_AbC1dEf2GhI3jKl4MnO5pQr6StU7vWx8"
	same := Similarity(aws1, aws2)
	diff := Similarity(aws1, gh)
	if same <= diff {
		t.Errorf("expected same-family similarity (%f) > cross-family (%f)", same, diff)
	}
	if same < 0.5 {
		t.Errorf("same-family similarity unexpectedly low: %f", same)
	}
}

func TestSimilarityRange(t *testing.T) {
	s := Similarity("abc", "xyz789!!!")
	if s < 0 || s > 1 {
		t.Errorf("similarity out of range: %f", s)
	}
}

func TestFingerprintGroupsSameKind(t *testing.T) {
	// Two structurally identical AWS-shaped keys share a fingerprint.
	fp1 := Fingerprint("AKIA1B2C3D4E5F6G7H8J")
	fp2 := Fingerprint("AKIA9Z8Y7X6W5V4U3T2S")
	if fp1 != fp2 {
		t.Errorf("expected shared fingerprint, got %q vs %q", fp1, fp2)
	}
	// A GitHub token has a different fingerprint.
	fp3 := Fingerprint("ghp_AbC1dEf2GhI3jKl4MnO5pQr6StU7vWx8")
	if fp1 == fp3 {
		t.Errorf("expected distinct fingerprints for aws vs github, both %q", fp1)
	}
}

func TestLevenshtein(t *testing.T) {
	if d := levenshtein("kitten", "sitting"); d != 3 {
		t.Errorf("levenshtein = %d, want 3", d)
	}
	if d := levenshtein("", "abc"); d != 3 {
		t.Errorf("levenshtein empty = %d, want 3", d)
	}
	if d := levenshtein("same", "same"); d != 0 {
		t.Errorf("levenshtein equal = %d, want 0", d)
	}
}

func TestCommonPrefixLen(t *testing.T) {
	if n := commonPrefixLen("sk-live_abc", "sk-test_xyz"); n != 3 {
		t.Errorf("commonPrefixLen = %d, want 3", n)
	}
}

// ── Clustering ────────────────────────────────────────────────────────────────

func TestClusterByFingerprint(t *testing.T) {
	values := []string{
		"AKIA1B2C3D4E5F6G7H8J",                 // aws
		"AKIA9Z8Y7X6W5V4U3T2S",                 // aws (same shape)
		"ghp_AbC1dEf2GhI3jKl4MnO5pQr6StU7vWx8", // github
		"AKIA1B2C3D4E5F6G7H8J",                 // duplicate of first
	}
	clusters := ClusterByFingerprint(values)
	if len(clusters) < 2 {
		t.Fatalf("expected at least 2 clusters, got %d", len(clusters))
	}
	// Largest cluster should be the two distinct AWS keys (dup collapsed).
	top := clusters[0]
	if top.Size != 2 || top.Family != "aws" {
		t.Errorf("top cluster size=%d family=%q, want size=2 family=aws", top.Size, top.Family)
	}
	if top.Representative == "" {
		t.Error("cluster representative should not be empty")
	}
}

func TestClusterSimilar(t *testing.T) {
	values := []string{
		"AKIA1B2C3D4E5F6G7H8J",
		"AKIA9Z8Y7X6W5V4U3T2S",
		"ghp_AbC1dEf2GhI3jKl4MnO5pQr6StU7vWx8",
	}
	clusters := ClusterSimilar(values, 0.6)
	if len(clusters) == 0 {
		t.Fatal("expected non-empty clustering")
	}
	total := 0
	for _, c := range clusters {
		total += c.Size
	}
	if total != len(values) {
		t.Errorf("cluster members total = %d, want %d", total, len(values))
	}
}

func TestClusterEmpty(t *testing.T) {
	if c := ClusterByFingerprint(nil); len(c) != 0 {
		t.Errorf("expected no clusters for nil input, got %d", len(c))
	}
}

// ── Anomaly detection ─────────────────────────────────────────────────────────

func TestAnomalyKnownFamilyNotAnomalous(t *testing.T) {
	a := AnomalyScore("AKIA1B2C3D4E5F6G7H8J")
	if a.Score > 0.1 {
		t.Errorf("known family should score low, got %f (%s)", a.Score, a.Reason)
	}
	if !a.IsKnownSecret {
		t.Error("expected IsKnownSecret true for AWS key")
	}
}

func TestAnomalyUnknownHighEntropy(t *testing.T) {
	// No known prefix, long, high entropy, mixed classes -> should look anomalous.
	a := AnomalyScore("Xy7Qw9Zr2Vt4Bn6Mk8Lp0Cd3Fg5Hj1Ab")
	if a.Score < anomalyThreshold {
		t.Errorf("expected anomalous score >= %f, got %f (%s)", anomalyThreshold, a.Score, a.Reason)
	}
	if a.Family != "" {
		t.Errorf("expected no family for anomaly, got %q", a.Family)
	}
}

func TestAnomalyStructuredNonSecret(t *testing.T) {
	// A UUID is structured, not anomalous.
	a := AnomalyScore("550e8400-e29b-41d4-a716-446655440000")
	if a.Score > 0.1 {
		t.Errorf("UUID should score low, got %f (%s)", a.Score, a.Reason)
	}
}

func TestAnomalyPlaceholder(t *testing.T) {
	a := AnomalyScore("your_api_key_here_placeholder")
	if a.Score > 0.1 {
		t.Errorf("placeholder should score low, got %f (%s)", a.Score, a.Reason)
	}
}

func TestAnomalyShort(t *testing.T) {
	a := AnomalyScore("abc")
	if a.Score != 0 {
		t.Errorf("short value should score 0, got %f", a.Score)
	}
}

func TestDetectAnomaliesSorted(t *testing.T) {
	values := []string{
		"AKIA1B2C3D4E5F6G7H8J",                // known family, not anomalous
		"Xy7Qw9Zr2Vt4Bn6Mk8Lp0Cd3Fg5Hj1Ab",    // anomalous
		"123456789",                           // trivial
		"Qz4Wm9Xr7Vt2Bn5Kp8Lc1Df3Gh6Jk0Ab9Yz", // anomalous
	}
	got := DetectAnomalies(values, 0)
	if len(got) < 2 {
		t.Fatalf("expected at least 2 anomalies, got %d", len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].Score < got[i].Score {
			t.Errorf("anomalies not sorted descending at %d: %f < %f", i, got[i-1].Score, got[i].Score)
		}
	}
}

func TestIsAnomalous(t *testing.T) {
	if !IsAnomalous("Xy7Qw9Zr2Vt4Bn6Mk8Lp0Cd3Fg5Hj1Ab") {
		t.Error("expected unknown high-entropy token to be anomalous")
	}
	if IsAnomalous("AKIA1B2C3D4E5F6G7H8J") {
		t.Error("expected recognized AWS family token to be non-anomalous")
	}
	if IsAnomalous("123456789") {
		t.Error("expected trivial value to be non-anomalous")
	}
}

func TestSimilarityFeaturesAPI(t *testing.T) {
	a, b := "AKIA1B2C3D4E5F6G7H8J", "AKIA9Z8Y7X6W5V4U3T2S"
	fa, fb := Extract(a), Extract(b)
	got := SimilarityFeatures(a, b, fa, fb)
	want := Similarity(a, b)
	if got != want {
		t.Errorf("SimilarityFeatures = %f, want %f (== Similarity)", got, want)
	}
}

func TestBucketsCoverRange(t *testing.T) {
	// lengthBucket should be monotonic non-decreasing across representative sizes.
	prev := -1
	for _, n := range []int{1, 10, 20, 28, 40, 56, 80, 112, 200} {
		b := lengthBucket(n)
		if b < prev {
			t.Errorf("lengthBucket(%d)=%d decreased below previous %d", n, b, prev)
		}
		prev = b
	}
	// entropyBucket clamps at both ends.
	if entropyBucket(0.0) != 0 {
		t.Errorf("entropyBucket(0) = %d, want 0", entropyBucket(0.0))
	}
	if entropyBucket(99.0) != 8 {
		t.Errorf("entropyBucket(99) = %d, want 8", entropyBucket(99.0))
	}
}

// ── Insights ──────────────────────────────────────────────────────────────────

func TestSummarize(t *testing.T) {
	values := []string{
		"AKIA1B2C3D4E5F6G7H8J",                 // aws secret
		"AKIA9Z8Y7X6W5V4U3T2S",                 // aws secret
		"ghp_AbC1dEf2GhI3jKl4MnO5pQr6StU7vWx8", // github secret
		"123456789",                            // junk
		"your_key_here",                        // junk
		"AKIA1B2C3D4E5F6G7H8J",                 // duplicate (deduped)
	}
	ins := Summarize(values)
	if ins.Total != 5 {
		t.Errorf("Total = %d, want 5 (deduped)", ins.Total)
	}
	if ins.Secrets != 3 {
		t.Errorf("Secrets = %d, want 3", ins.Secrets)
	}
	if ins.NonSecrets != 2 {
		t.Errorf("NonSecrets = %d, want 2", ins.NonSecrets)
	}
	if len(ins.ByFamily) == 0 || ins.ByFamily[0].Family != "aws" || ins.ByFamily[0].Count != 2 {
		t.Errorf("expected aws as top family with count 2, got %+v", ins.ByFamily)
	}
	if ins.MeanConfidence <= 0 || ins.MeanConfidence > 1 {
		t.Errorf("MeanConfidence out of range: %f", ins.MeanConfidence)
	}
	if ins.ClusterCount == 0 {
		t.Error("expected non-zero cluster count")
	}
}

func TestSummarizeEmpty(t *testing.T) {
	ins := Summarize(nil)
	if ins.Total != 0 || ins.Secrets != 0 || len(ins.ByFamily) != 0 {
		t.Errorf("empty summary not zero: %+v", ins)
	}
}
