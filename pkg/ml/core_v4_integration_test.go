package ml

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	"mega-analyzer/pkg/ml/ensemble"
)

type coreV4Model struct {
	calls  int
	cancel context.CancelFunc
}

func (m *coreV4Model) IsLoaded() bool { return true }
func (m *coreV4Model) Score(_ ensemble.Features) (float64, bool) {
	m.calls++
	if m.cancel != nil {
		m.cancel()
	}
	return 1, true
}
func coreV4Candidate() AnalysisCandidate {
	return AnalysisCandidate{FilePath: "app/test/Feature.smali", Content: []byte(coreV4Fixture), IsAppCode: true}
}

func TestCoreMLV4ModelRunsBeforePresentationCutoff(t *testing.T) {
	p := coreV4Predictor()
	p.scorer.config.MaxScore = 20 // Deliberately below the legacy fixed cutoff of 30.
	p.config.EnableEnsembleBoost = true
	p.config.EnsembleMix.LegacyWeight = 0.1
	p.config.EnsembleMix.EnsembleWeight = 0.9
	m := &coreV4Model{}
	p.SetTrainedRiskScorer(m)
	body := `.class public Lapp/test/Feature;
.super Ljava/lang/Object;
.method public feature()Z
 .locals 1
 const/4 v0, 0x0
 return v0
.end method
`
	candidate := AnalysisCandidate{FilePath: "app/test/Feature.smali", Content: []byte(body), IsAppCode: true}
	baseline := p.analyzer.BatchAnalyze([]AnalysisCandidate{candidate})
	if old := p.scorer.ScoreBatch(baseline); len(old) != 0 {
		t.Fatalf("fixture must be below legacy score cutoff, got %d", len(old))
	}
	result := p.PredictFromCandidates([]AnalysisCandidate{candidate})
	if m.calls != 1 {
		t.Fatalf("configured model never saw the low-base-score method: %d", m.calls)
	}
	if result.Stats.PatchPointsFound != 1 {
		t.Fatalf("late model contribution lost before final threshold: %+v", result.Stats)
	}
	if len(result.Stats.PipelineMetrics.Stages) != 8 {
		t.Fatalf("not the full live chain: %+v", result.Stats.PipelineMetrics)
	}
}

func TestCoreMLV4FeedbackBeforeFinalThreshold(t *testing.T) {
	p := coreV4Predictor()
	p.scorer.config.MaxScore = 50
	p.config.MinScore = 55
	p.history = &AnalysisHistory{maxItems: 10, records: []*AnalysisFeedback{{ID: "core-v4", UserOverrides: []UserOverride{{Path: "app/test", Action: FeedbackRelevant}}}}}
	result := p.PredictFromCandidates([]AnalysisCandidate{coreV4Candidate()})
	if result.Stats.PatchPointsFound == 0 {
		t.Fatalf("relevance adjustment was applied after discarding candidate: %+v", result.Stats)
	}
}

func TestCoreMLV4Cancellation(t *testing.T) {
	t.Run("before_parse", func(t *testing.T) {
		p := coreV4Predictor()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		r, err := p.PredictFromCandidatesContext(ctx, []AnalysisCandidate{coreV4Candidate()})
		if !errors.Is(err, context.Canceled) || !r.PartialResults || r.Stats.TotalFilesScanned != 0 {
			t.Fatalf("cancel ignored: err=%v stats=%+v", err, r.Stats)
		}
	})
	t.Run("during_model", func(t *testing.T) {
		p := coreV4Predictor()
		p.config.EnableEnsembleBoost = true
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		m := &coreV4Model{cancel: cancel}
		p.SetTrainedRiskScorer(m)
		r, err := p.PredictFromCandidatesContext(ctx, []AnalysisCandidate{coreV4Candidate()})
		if m.calls != 1 || !errors.Is(err, context.Canceled) || !r.PartialResults {
			t.Fatalf("mid-run cancellation not propagated: calls=%d err=%v partial=%v", m.calls, err, r.PartialResults)
		}
		if r.Stats.PatchPointsFound != 0 {
			t.Fatal("cancelled run produced automatic candidates")
		}
	})
}

func TestCoreMLV4InputBudgetIsObservable(t *testing.T) {
	p := coreV4Predictor()
	p.config.MaxSmaliFileSize = 10
	r := p.PredictFromCandidates([]AnalysisCandidate{coreV4Candidate()})
	if !r.PartialResults || r.Stats.FilesTooLarge != 1 || r.Stats.TotalFilesScanned != 0 || len(r.Stats.ScanErrors) == 0 {
		t.Fatalf("input budget was silent: %+v", r.Stats)
	}
}

func TestCoreMLV4ConcurrentRunsHaveIsolatedMetrics(t *testing.T) {
	p := coreV4Predictor()
	var wg sync.WaitGroup
	results := make([]*PatchPrediction, 4)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = p.PredictFromCandidates([]AnalysisCandidate{coreV4Candidate()})
		}(i)
	}
	wg.Wait()
	for _, r := range results {
		if r.PartialResults || r.Stats.PipelineMetrics.TotalMethods != 1 || len(r.Stats.PipelineMetrics.Stages) != 8 {
			t.Fatalf("invalid concurrent prediction: %+v", r.Stats)
		}
	}
	results[0].Stats.PipelineMetrics.Stages[0].Name = "changed"
	if results[1].Stats.PipelineMetrics.Stages[0].Name != "score" {
		t.Fatal("run metrics alias each other")
	}
}

func TestCoreMLV4AggregatedMetricsAreMeasured(t *testing.T) {
	p := coreV4Predictor()
	combined := p.emptyPrediction()
	// Windows monotonic clock granularity is ~0.5ms: a single-candidate batch
	// scores in microseconds and quantizes to a zero duration, so the merge
	// would legitimately sum to zero and trip the masquerade assertion. Feed
	// each batch enough work to exceed the clock resolution.
	heavy := make([]AnalysisCandidate, 0, 300)
	for i := 0; i < 300; i++ {
		heavy = append(heavy, coreV4Candidate())
	}
	for i := 0; i < 3; i++ {
		p.mergeDirectoryPrediction(combined, p.PredictFromCandidates(heavy))
	}
	p.enrichMLHealth(combined)
	m := combined.Stats.PipelineMetrics
	if m == nil || m.TotalMethods != 900 || m.Stages[0].InputCount != 900 || m.TotalDurationNs <= 0 || m.Throughput <= 0 {
		t.Fatalf("last-batch metrics masqueraded as aggregate: %+v", m)
	}
	if combined.Stats.MLHealth.ECE != 0 || combined.Stats.MLHealth.DriftVerdict != "unavailable" {
		t.Fatal("invented model quality")
	}
}

func TestCoreMLV4HeapMatchesFullSort(t *testing.T) {
	random := rand.New(rand.NewSource(9))
	for n := 1; n <= 100; n++ {
		points := make([]PatchPoint, n)
		for i := range points {
			points[i] = PatchPoint{FilePath: fmt.Sprintf("app/%03d.smali", i), MethodName: "f", MethodSignature: "f()Z", RiskScore: float64(random.Intn(11)), Confidence: float64(random.Intn(5)) / 5}
		}
		reference := append([]PatchPoint(nil), points...)
		sort.Slice(reference, func(i, j int) bool { return betterPatchPoint(&reference[i], &reference[j], patchValueOrFallback) })
		k := min(7, n)
		reference = reference[:k]
		random.Shuffle(n, func(i, j int) { points[i], points[j] = points[j], points[i] })
		got := retainTopPatchPoints(nil, points, k, patchValueOrFallback)
		for i := range got {
			if patchPointIdentity(&got[i]) != patchPointIdentity(&reference[i]) {
				t.Fatalf("n=%d rank=%d differs from exact full sort", n, i)
			}
		}
	}
}

func TestCoreMLV4EffectContractIsOpcodeAware(t *testing.T) {
	for _, tc := range []struct{ name, line, status string }{{"literal", "const-string v0, \"sput invoke-static monitor-enter\"", "compatible"}, {"field_write", "sput-boolean v0, Lapp/State;->flag:Z", "needs_review"}, {"call", "invoke-static {}, Lapp/State;->save()V", "needs_review"}} {
		t.Run(tc.name, func(t *testing.T) {
			m := coreV4Scored("inspect", 99, "Z")
			m.Method.RawBody = append(m.Method.RawBody[:2], append([]string{tc.line}, m.Method.RawBody[2:]...)...)
			a := assessRecommendation(&PatchPoint{SuggestedPatch: PatchReturnFalse}, &m.Method)
			if a.Status != tc.status {
				t.Fatalf("status=%s, want %s", a.Status, tc.status)
			}
		})
	}
}

func TestCoreMLV4StagesPreserveBorrowedScores(t *testing.T) {
	p := coreV4Predictor()
	m := coreV4Scored("inspect", 90, "Z")
	m.Score.Reasons = make([]string, 1, 10)
	m.Score.Reasons[0] = "original"
	original := append([]string(nil), m.Score.Reasons...)
	_, err := p.filterPredictorNoise(context.Background(), []ScoredMethod{m})
	if err != nil || !reflect.DeepEqual(m.Score.Reasons, original) {
		t.Fatal("borrowed score mutated")
	}
}

func BenchmarkCoreMLV4TopK10k(b *testing.B) {
	points := make([]PatchPoint, 10000)
	for i := range points {
		points[i] = PatchPoint{FilePath: fmt.Sprintf("app/%05d.smali", i), MethodName: "f", MethodSignature: "f()Z", RiskScore: float64((i*7919)%10000) / 100}
	}
	b.Run("bounded", func(b *testing.B) {
		b.ReportAllocs()
		for n := 0; n < b.N; n++ {
			got := retainTopPatchPoints(nil, points, 15, patchValueOrFallback)
			if len(got) != 15 {
				b.Fatal("bad result")
			}
		}
	})
	b.Run("full_sort_reference", func(b *testing.B) {
		b.ReportAllocs()
		for n := 0; n < b.N; n++ {
			copy := append([]PatchPoint(nil), points...)
			sort.Slice(copy, func(i, j int) bool { return betterPatchPoint(&copy[i], &copy[j], patchValueOrFallback) })
			if len(copy) < 15 {
				b.Fatal("bad result")
			}
		}
	})
}

type coreV4BlockingModel struct {
	started chan struct{}
	release chan struct{}
}

func (m *coreV4BlockingModel) IsLoaded() bool { return true }
func (m *coreV4BlockingModel) Score(_ ensemble.Features) (float64, bool) {
	close(m.started)
	<-m.release
	return 1, true
}
func TestCoreMLV4CancelledQueueWaitReturns(t *testing.T) {
	p := coreV4Predictor()
	p.config.EnableEnsembleBoost = true
	m := &coreV4BlockingModel{started: make(chan struct{}), release: make(chan struct{})}
	p.SetTrainedRiskScorer(m)
	finished := make(chan struct{})
	go func() { defer close(finished); p.PredictFromCandidates([]AnalysisCandidate{coreV4Candidate()}) }()
	defer func() { close(m.release); <-finished }()
	select {
	case <-m.started:
	case <-time.After(time.Second):
		t.Fatal("first model did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := p.PredictFromCandidatesContext(ctx, []AnalysisCandidate{coreV4Candidate()})
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("queue error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled call still waiting for another prediction")
	}
}
func TestCoreMLV4NoImplementationContract(t *testing.T) {
	for _, name := range []string{"native_tabs", "directives_only"} {
		t.Run(name, func(t *testing.T) {
			m := coreV4Scored("inspect", 99, "Z")
			if name == "native_tabs" {
				m.Method.MethodHeader = ".method public\tnative inspect()Z"
			} else {
				m.Method.RawBody = []string{".locals 1", "# no implementation", ".end method"}
			}
			a := assessRecommendation(&PatchPoint{SuggestedPatch: PatchReturnFalse}, &m.Method)
			if a.Status != "reject" {
				t.Fatalf("non-implementation accepted: %+v", a)
			}
		})
	}
}
