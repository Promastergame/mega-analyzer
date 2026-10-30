package anomaly

import (
	"math"
	"math/rand"
	"testing"
)

// makeCluster builds n points drawn from a tight Gaussian cluster around
// `center` using a fixed seed for reproducibility.
func makeCluster(n, dims int, center, spread float64, seed int64) [][]float64 {
	rng := rand.New(rand.NewSource(seed))
	out := make([][]float64, n)
	for i := range out {
		v := make([]float64, dims)
		for d := range v {
			v[d] = center + rng.NormFloat64()*spread
		}
		out[i] = v
	}
	return out
}

func TestWelfordMatchesNaive(t *testing.T) {
	vals := []float64{2, 4, 4, 4, 5, 5, 7, 9}
	var w Welford
	for _, v := range vals {
		w.Add(v)
	}
	if w.Count() != len(vals) {
		t.Fatalf("count = %d, want %d", w.Count(), len(vals))
	}
	if math.Abs(w.Mean()-5.0) > 1e-9 {
		t.Errorf("mean = %g, want 5", w.Mean())
	}
	// Sample variance of this classic set is 32/7.
	if math.Abs(w.Variance()-(32.0/7.0)) > 1e-9 {
		t.Errorf("variance = %g, want %g", w.Variance(), 32.0/7.0)
	}
}

func TestBaselineZeroVarianceIsStable(t *testing.T) {
	b := NewBaseline(2)
	for i := 0; i < 10; i++ {
		if err := b.Observe([]float64{3, 3}); err != nil {
			t.Fatal(err)
		}
	}
	z, err := b.ZScores([]float64{3, 100})
	if err != nil {
		t.Fatal(err)
	}
	if z[0] != 0 {
		t.Errorf("constant feature should give z=0, got %g", z[0])
	}
	if math.IsInf(z[1], 0) || math.IsNaN(z[1]) {
		t.Errorf("z-score must stay finite, got %g", z[1])
	}
}

func TestIsolationForestScoresAnomalyHigher(t *testing.T) {
	train := makeCluster(400, 6, 0, 1, 1)
	f := NewIsolationForest(DefaultIsolationForestConfig())
	if err := f.Fit(train); err != nil {
		t.Fatal(err)
	}
	normal := make([]float64, 6) // at the cluster centre
	outlier := []float64{40, -40, 40, -40, 40, -40}
	ns := f.Score(normal)
	os := f.Score(outlier)
	if os <= ns {
		t.Errorf("outlier score %g should exceed normal score %g", os, ns)
	}
	if os < 0 || os > 1 || ns < 0 || ns > 1 {
		t.Errorf("scores must be in [0,1]: normal=%g outlier=%g", ns, os)
	}
}

func TestIsolationForestDeterministic(t *testing.T) {
	train := makeCluster(200, 4, 1, 2, 7)
	x := []float64{9, 9, 9, 9}
	f1 := NewIsolationForest(IsolationForestConfig{NumTrees: 50, SampleSize: 128, Seed: 42})
	f2 := NewIsolationForest(IsolationForestConfig{NumTrees: 50, SampleSize: 128, Seed: 42})
	if err := f1.Fit(train); err != nil {
		t.Fatal(err)
	}
	if err := f2.Fit(train); err != nil {
		t.Fatal(err)
	}
	if f1.Score(x) != f2.Score(x) {
		t.Errorf("same seed must give identical scores: %g vs %g", f1.Score(x), f2.Score(x))
	}
}

func TestIsolationForestEdgeCases(t *testing.T) {
	f := NewIsolationForest(DefaultIsolationForestConfig())
	if err := f.Fit(nil); err == nil {
		t.Error("expected error on empty training data")
	}
	if err := f.Fit([][]float64{{1, 2}, {1}}); err == nil {
		t.Error("expected error on ragged training data")
	}
	// Untrained forest returns 0 rather than panicking.
	fresh := NewIsolationForest(DefaultIsolationForestConfig())
	if fresh.Score([]float64{1, 2, 3}) != 0 {
		t.Error("untrained forest should score 0")
	}
	// Constant data must not panic and yields a defined score.
	const_ := [][]float64{{1, 1}, {1, 1}, {1, 1}}
	if err := f.Fit(const_); err != nil {
		t.Fatal(err)
	}
	_ = f.Score([]float64{1, 1})
}

func TestLSHFindsNearestNeighbor(t *testing.T) {
	idx := NewLSHIndex(4, 32, 1)
	_ = idx.Add("a", []float64{1, 0, 0, 0})
	_ = idx.Add("b", []float64{0, 1, 0, 0})
	_ = idx.Add("c", []float64{0.9, 0.1, 0, 0})
	res, err := idx.Query([]float64{1, 0, 0, 0}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 2 {
		t.Fatalf("expected 2 neighbours, got %d", len(res))
	}
	if res[0].ID != "a" {
		t.Errorf("nearest should be 'a', got %q", res[0].ID)
	}
	if res[0].Cosine < res[1].Cosine {
		t.Errorf("results must be sorted by cosine desc: %v", res)
	}
}

func TestLSHOverwriteAndWidthGuard(t *testing.T) {
	idx := NewLSHIndex(3, 16, 2)
	_ = idx.Add("x", []float64{1, 1, 1})
	_ = idx.Add("x", []float64{2, 2, 2})
	if idx.Len() != 1 {
		t.Errorf("re-adding same id should overwrite, len=%d", idx.Len())
	}
	if err := idx.Add("y", []float64{1, 2}); err == nil {
		t.Error("expected width mismatch error")
	}
	if _, err := idx.Query([]float64{1, 2}, 1); err == nil {
		t.Error("expected width mismatch error on query")
	}
}

func TestDetectorEndToEnd(t *testing.T) {
	schema := []string{"f0", "f1", "f2", "f3", "f4"}
	train := makeCluster(300, 5, 0, 1, 3)
	ids := make([]string, len(train))
	for i := range ids {
		ids[i] = "target_" + itoa(i)
	}
	d := NewDetector(schema, DefaultConfig())
	if err := d.Fit(train, ids); err != nil {
		t.Fatal(err)
	}
	res, err := d.Analyze([]float64{25, -25, 25, -25, 25})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsAnomaly {
		t.Errorf("expected anomaly flag, score=%g threshold=%g", res.Score, res.Threshold)
	}
	if len(res.TopContributors) == 0 {
		t.Error("expected explanations")
	}
	if res.TopContributors[0].Feature == "" {
		t.Error("contribution should be named from schema")
	}
	if len(res.Neighbors) == 0 {
		t.Error("expected similarity neighbours with LSH enabled")
	}
	// Contributions must be sorted by |z| desc.
	for i := 1; i < len(res.TopContributors); i++ {
		if absf(res.TopContributors[i-1].ZScore) < absf(res.TopContributors[i].ZScore) {
			t.Error("contributions not sorted by |z-score|")
		}
	}
}

func TestDetectorUntrainedGuards(t *testing.T) {
	d := NewDetector([]string{"a"}, DefaultConfig())
	if _, err := d.Analyze([]float64{1}); err == nil {
		t.Error("expected error analysing before Fit")
	}
	if err := d.Fit(nil, nil); err == nil {
		t.Error("expected error fitting empty corpus")
	}
}

func TestItoa(t *testing.T) {
	cases := map[int]string{0: "0", 7: "7", 42: "42", -13: "-13", 1000: "1000"}
	for in, want := range cases {
		if got := itoa(in); got != want {
			t.Errorf("itoa(%d) = %q, want %q", in, got, want)
		}
	}
}

func BenchmarkIsolationForestScore(b *testing.B) {
	train := makeCluster(500, 16, 0, 1, 1)
	f := NewIsolationForest(DefaultIsolationForestConfig())
	if err := f.Fit(train); err != nil {
		b.Fatal(err)
	}
	x := make([]float64, 16)
	for i := range x {
		x[i] = 5
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = f.Score(x)
	}
}

func BenchmarkLSHQuery(b *testing.B) {
	idx := NewLSHIndex(32, 48, 1)
	corpus := makeCluster(2000, 32, 0, 1, 9)
	for i, v := range corpus {
		_ = idx.Add(itoa(i), v)
	}
	q := corpus[0]
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = idx.Query(q, 10)
	}
}
