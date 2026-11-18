package fusion

import (
	"math"
	"math/rand"
	"strings"
	"testing"
)

// ---- test helpers ----------------------------------------------------------

type fixedProvider struct {
	name   string
	weight float64
	score  float64
}

func (p fixedProvider) Name() string              { return p.name }
func (p fixedProvider) Weight() float64           { return p.weight }
func (p fixedProvider) Score(_ []float64) float64 { return p.score }

// ---- FusionEngine ----------------------------------------------------------

func TestFusionConsensusHighConfidence(t *testing.T) {
	e := NewFusionEngine(DefaultFusionConfig())
	d := e.Fuse([]ModelSignal{
		{Name: "gbm", Score: 0.92, Weight: 1},
		{Name: "hdc", Score: 0.90, Weight: 1},
		{Name: "anomaly", Score: 0.94, Weight: 1},
	}, nil)
	if d.ThreatScore < 0.85 {
		t.Errorf("threat score too low: %g", d.ThreatScore)
	}
	if d.Disagreement {
		t.Error("agreeing models should not flag disagreement")
	}
	if d.ConfidenceBand != "High" {
		t.Errorf("expected High confidence, got %s (%.2f)", d.ConfidenceBand, d.Confidence)
	}
	if d.Recommendation != "report" {
		t.Errorf("expected report, got %s", d.Recommendation)
	}
}

func TestFusionDisagreementLowersConfidence(t *testing.T) {
	e := NewFusionEngine(DefaultFusionConfig())
	agree := e.Fuse([]ModelSignal{
		{Name: "a", Score: 0.8, Weight: 1},
		{Name: "b", Score: 0.82, Weight: 1},
		{Name: "c", Score: 0.78, Weight: 1},
	}, nil)
	conflict := e.Fuse([]ModelSignal{
		{Name: "a", Score: 0.95, Weight: 1},
		{Name: "b", Score: 0.05, Weight: 1},
		{Name: "c", Score: 0.55, Weight: 1},
	}, nil)
	if !conflict.Disagreement {
		t.Error("conflicting models should flag disagreement")
	}
	if conflict.Confidence >= agree.Confidence {
		t.Errorf("conflict confidence %g should be below consensus %g", conflict.Confidence, agree.Confidence)
	}
	if conflict.Recommendation != "deep_analysis" {
		t.Errorf("conflict should request deep analysis, got %s", conflict.Recommendation)
	}
}

func TestFusionExplanationFormat(t *testing.T) {
	e := NewFusionEngine(DefaultFusionConfig())
	d := e.Fuse([]ModelSignal{
		{Name: "gbm", Score: 0.9, Weight: 1},
		{Name: "anomaly", Score: 0.8, Weight: 1},
	}, []Evidence{{Factor: "CFG flattening detected", Contribution: 0}})
	if !strings.Contains(d.Explanation, "Threat score:") {
		t.Errorf("explanation missing header: %q", d.Explanation)
	}
	if !strings.Contains(d.Explanation, "Confidence:") {
		t.Error("explanation missing confidence line")
	}
	// Evidence contributions from signals should sum to the threat score.
	var sum float64
	for _, ev := range d.Evidence {
		sum += ev.Contribution
	}
	if math.Abs(sum-d.ThreatScore) > 1e-9 {
		t.Errorf("evidence contributions %g should sum to threat score %g", sum, d.ThreatScore)
	}
}

func TestFusionEmptySignals(t *testing.T) {
	e := NewFusionEngine(DefaultFusionConfig())
	d := e.Fuse(nil, nil)
	if d.Recommendation != "deep_analysis" {
		t.Error("no signals should trigger deep analysis")
	}
}

func TestFusionInsufficientSignalsRequireAnalysis(t *testing.T) {
	e := NewFusionEngine(FusionConfig{MinSignals: 2})
	d := e.Fuse([]ModelSignal{{Name: "scanner_heuristic", Score: 0.95, Weight: 1}}, nil)
	if d.Recommendation != "deep_analysis" || d.ConfidenceBand != "Low" {
		t.Fatalf("single heuristic was presented as sufficient evidence: %+v", d)
	}
	if !strings.Contains(d.Explanation, "Only one signal") || strings.Contains(d.Explanation, "independent systems agree") {
		t.Fatalf("single signal described as independent confirmation: %s", d.Explanation)
	}
	if strings.Contains(d.Explanation, "Threat probability:") {
		t.Fatal("uncalibrated score described as a probability")
	}
	full := e.Fuse([]ModelSignal{
		{Name: "a", Score: 0.95, Weight: 1},
		{Name: "b", Score: 0.95, Weight: 1},
	}, nil)
	if full.Confidence <= d.Confidence || full.Recommendation != "report" {
		t.Fatalf("signal coverage did not affect the decision: single=%+v full=%+v", d, full)
	}
}

// ---- OnlineLogistic --------------------------------------------------------

func TestOnlineLogisticLearnsSeparable(t *testing.T) {
	m := NewOnlineLogistic(2, 0.2, 1e-5)
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 4000; i++ {
		x0 := rng.NormFloat64()
		x1 := rng.NormFloat64()
		label := 0
		if x0+0.5*x1 > 0 { // linearly separable boundary
			label = 1
		}
		if _, err := m.Update([]float64{x0, x1}, label); err != nil {
			t.Fatal(err)
		}
	}
	if m.Samples() != 4000 {
		t.Errorf("sample count = %d", m.Samples())
	}
	pos := m.PredictProba([]float64{3, 3})
	neg := m.PredictProba([]float64{-3, -3})
	if pos < 0.7 {
		t.Errorf("expected high proba for positive region, got %g", pos)
	}
	if neg > 0.3 {
		t.Errorf("expected low proba for negative region, got %g", neg)
	}
}

func TestOnlineLogisticGuards(t *testing.T) {
	m := NewOnlineLogistic(2, 0.1, 0)
	if _, err := m.Update([]float64{1}, 1); err == nil {
		t.Error("expected width mismatch error")
	}
	if _, err := m.Update([]float64{1, 2}, 5); err == nil {
		t.Error("expected invalid label error")
	}
}

// ---- FeatureMonitor --------------------------------------------------------

func TestFeatureMonitorImportanceAndQuality(t *testing.T) {
	fm := NewFeatureMonitor([]string{"useful", "useless", "noise"}, 256)
	rng := rand.New(rand.NewSource(2))
	for i := 0; i < 500; i++ {
		label := i % 2
		useful := float64(label) + rng.NormFloat64()*0.05 // strongly correlated
		useless := 7.0                                    // constant
		noise := rng.NormFloat64()                        // uncorrelated
		if err := fm.Observe([]float64{useful, useless, noise}, label); err != nil {
			t.Fatal(err)
		}
	}
	scores := fm.Scores()
	if scores[0].Name != "useful" {
		t.Errorf("most important feature should be 'useful', got %q", scores[0].Name)
	}
	useless := false
	for _, s := range scores {
		if s.Name == "useless" && s.Useless {
			useless = true
		}
	}
	if !useless {
		t.Error("constant feature should be flagged useless")
	}
	if got := fm.UselessFeatures(); len(got) != 1 || got[0] != "useless" {
		t.Errorf("UselessFeatures = %v", got)
	}
	w := fm.AdaptiveWeights()
	if w[1] != 0 {
		t.Errorf("useless feature weight should be 0, got %g", w[1])
	}
	if w[0] <= w[2] {
		t.Errorf("useful weight %g should exceed noise weight %g", w[0], w[2])
	}
}

func TestFeatureMonitorCorrelationDetection(t *testing.T) {
	fm := NewFeatureMonitor([]string{"x", "twoX", "indep"}, 256)
	rng := rand.New(rand.NewSource(3))
	for i := 0; i < 300; i++ {
		x := rng.NormFloat64()
		if err := fm.Observe([]float64{x, 2 * x, rng.NormFloat64()}, i%2); err != nil {
			t.Fatal(err)
		}
	}
	pairs := fm.DetectCorrelated(0.95)
	if len(pairs) == 0 {
		t.Fatal("expected to detect the x / twoX correlation")
	}
	top := pairs[0]
	if !((top.A == "x" && top.B == "twoX") || (top.A == "twoX" && top.B == "x")) {
		t.Errorf("top correlated pair unexpected: %+v", top)
	}
}

func TestFeatureMonitorDriftDetection(t *testing.T) {
	fm := NewFeatureMonitor([]string{"f"}, 512)
	for i := 0; i < 200; i++ {
		_ = fm.Observe([]float64{0.0}, 0)
	}
	for i := 0; i < 200; i++ {
		_ = fm.Observe([]float64{50.0}, 1) // sustained shift
	}
	if len(fm.DriftedFeatures()) == 0 {
		t.Error("expected drift detection after a sustained distribution shift")
	}
}

// ---- KnowledgeMemory -------------------------------------------------------

func TestKnowledgeMemoryResembles(t *testing.T) {
	mem := NewKnowledgeMemory(DefaultMemoryConfig(4))
	_ = mem.Remember(Record{ID: "a1", Label: "FamilyA", Vec: []float64{1, 0, 0, 0}})
	_ = mem.Remember(Record{ID: "a2", Label: "FamilyA", Vec: []float64{0.95, 0.05, 0, 0}})
	_ = mem.Remember(Record{ID: "b1", Label: "FamilyB", Vec: []float64{0, 0, 1, 0}})
	matches, err := mem.Resembles([]float64{0.98, 0.02, 0, 0}, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 || matches[0].Label != "FamilyA" {
		t.Errorf("expected FamilyA as top resemblance, got %+v", matches)
	}
	if matches[0].Similarity < 0.9 {
		t.Errorf("expected high similarity, got %g", matches[0].Similarity)
	}
}

func TestKnowledgeMemoryClustering(t *testing.T) {
	mem := NewKnowledgeMemory(DefaultMemoryConfig(3))
	// Two well-separated groups should form two clusters.
	for i := 0; i < 10; i++ {
		_ = mem.Remember(Record{Label: "A", Vec: []float64{1, 0, 0}})
		_ = mem.Remember(Record{Label: "B", Vec: []float64{0, 0, 1}})
	}
	if len(mem.Clusters()) != 2 {
		t.Errorf("expected 2 clusters, got %d", len(mem.Clusters()))
	}
}

// ---- Intelligence end to end ----------------------------------------------

func TestIntelligenceEndToEnd(t *testing.T) {
	schema := []string{"f0", "f1", "f2", "f3"}
	cfg := IntelligenceConfig{Schema: schema, Fusion: DefaultFusionConfig()}
	eng := NewIntelligence(cfg,
		fixedProvider{name: "gbm", weight: 1.2, score: 0.9},
		fixedProvider{name: "hdc", weight: 1.0, score: 0.88},
	)

	// Seed continuous learning + memory.
	rng := rand.New(rand.NewSource(4))
	for i := 0; i < 200; i++ {
		label := i % 2
		f := []float64{float64(label) + rng.NormFloat64()*0.1, rng.NormFloat64(), 5, rng.NormFloat64()}
		lbl := "benign"
		if label == 1 {
			lbl = "FamilyA"
		}
		if err := eng.Learn(Sample{ID: "s" + itoa(i), Features: f}, label, lbl); err != nil {
			t.Fatal(err)
		}
	}

	rep, err := eng.Analyze(Sample{
		ID:       "unknown-1",
		Features: []float64{1.0, 0.2, 5, 0.1},
		Extra:    []Evidence{{Factor: "String entropy abnormal", Contribution: 0}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Decision.Signals) < 3 {
		t.Errorf("expected supervised + online + similarity signals, got %d", len(rep.Decision.Signals))
	}
	if rep.Decision.Explanation == "" {
		t.Error("expected an explanation")
	}
	if len(rep.TopFeatures) == 0 {
		t.Error("expected feature intelligence in the report")
	}
	if eng.OnlineSamples() != 200 {
		t.Errorf("online samples = %d", eng.OnlineSamples())
	}
}

// ---- benchmarks ------------------------------------------------------------

func BenchmarkFusionFuse(b *testing.B) {
	e := NewFusionEngine(DefaultFusionConfig())
	signals := []ModelSignal{
		{Name: "gbm", Score: 0.9, Weight: 1.2},
		{Name: "hdc", Score: 0.85, Weight: 1.0},
		{Name: "anomaly", Score: 0.92, Weight: 1.0},
		{Name: "similarity", Score: 0.8, Weight: 0.8},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = e.Fuse(signals, nil)
	}
}

func BenchmarkOnlineUpdate(b *testing.B) {
	m := NewOnlineLogistic(32, 0.1, 1e-5)
	x := make([]float64, 32)
	for i := range x {
		x[i] = float64(i) * 0.01
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = m.Update(x, i&1)
	}
}

func BenchmarkMemoryResembles(b *testing.B) {
	mem := NewKnowledgeMemory(DefaultMemoryConfig(32))
	rng := rand.New(rand.NewSource(9))
	for i := 0; i < 2000; i++ {
		v := make([]float64, 32)
		for j := range v {
			v[j] = rng.NormFloat64()
		}
		_ = mem.Remember(Record{ID: itoa(i), Label: "fam" + itoa(i%8), Vec: v})
	}
	q := make([]float64, 32)
	for j := range q {
		q[j] = rng.NormFloat64()
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = mem.Resembles(q, 5)
	}
}
