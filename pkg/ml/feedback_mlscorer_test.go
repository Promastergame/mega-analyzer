package ml

import "testing"

// fakeScorer is a deterministic KeywordRelevanceScorer for tests: it returns a
// fixed probability per keyword.
type fakeScorer struct {
	loaded bool
	probs  map[string]float64
}

func (f *fakeScorer) IsLoaded() bool { return f.loaded }
func (f *fakeScorer) ScoreKeyword(kf *KeywordFeedback) float64 {
	if p, ok := f.probs[kf.Keyword]; ok {
		return p
	}
	return 0.5
}

func newEngineWith(keywords map[string]*AggregatedKeyword) *LearningEngine {
	le := NewLearningEngine(0.95, 100)
	le.Stats = &AggregatedStats{KeywordStats: keywords}
	// Start from a clean slate so preloaded known-noise doesn't mask assertions.
	le.WeightAdj = make(map[string]float64)
	return le
}

func TestRecalculateWeightsMLBranch(t *testing.T) {
	keywords := map[string]*AggregatedKeyword{
		"noisy":   {Keyword: "noisy", TotalTriggers: 10, TotalInLibrary: 9, SumImportance: 2},
		"good":    {Keyword: "good", TotalTriggers: 10, TotalInAppCode: 10, SumImportance: 80},
		"neutral": {Keyword: "neutral", TotalTriggers: 5, TotalInAppCode: 3, SumImportance: 15},
	}
	le := newEngineWith(keywords)
	le.SetMLScorer(&fakeScorer{
		loaded: true,
		probs:  map[string]float64{"noisy": 0.05, "good": 0.95, "neutral": 0.5},
	})

	le.recalculateWeights()

	if w := le.WeightAdj["noisy"]; w >= 0.2 {
		t.Errorf("noisy keyword should be suppressed, got weight %.3f", w)
	}
	if w := le.WeightAdj["good"]; w <= 1.0 {
		t.Errorf("relevant keyword should be boosted >1.0, got weight %.3f", w)
	}
	if _, ok := le.WeightAdj["neutral"]; ok {
		t.Errorf("uncertain keyword should fall back to default (no adjustment)")
	}
}

func TestRecalculateWeightsHeuristicFallback(t *testing.T) {
	keywords := map[string]*AggregatedKeyword{
		// avg = 0.2, seen in 3 APKs → heuristic strong-noise (0.05).
		"lownoise": {Keyword: "lownoise", TotalTriggers: 10, TotalInLibrary: 8, SumImportance: 2, APKsSeenIn: 3},
		// avg = 8, low library → heuristic strong-relevant (1.5).
		"strong": {Keyword: "strong", TotalTriggers: 10, TotalInAppCode: 10, SumImportance: 80},
	}
	le := newEngineWith(keywords)
	// No MLScorer set → heuristic path.
	le.recalculateWeights()

	if w := le.WeightAdj["lownoise"]; w != 0.05 {
		t.Errorf("expected heuristic noise weight 0.05, got %.3f", w)
	}
	if w := le.WeightAdj["strong"]; w != 1.5 {
		t.Errorf("expected heuristic relevant weight 1.5, got %.3f", w)
	}
}

func TestToFeatureVectorLength(t *testing.T) {
	kf := &KeywordFeedback{Triggered: 4, InAppCode: 3, InLibrary: 1, SumImportance: 12, APKsSeenIn: 2}
	v := kf.ToFeatureVector()
	if len(v) != len(KeywordRelevanceFeatureNames) {
		t.Fatalf("feature vector length %d != %d", len(v), len(KeywordRelevanceFeatureNames))
	}
}
