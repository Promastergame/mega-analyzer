package ml

import (
	"context"
	"fmt"
	"runtime"
	"sort"
	"sync"
	"time"
)

// Stage is a sequential pipeline step. Process must cooperate with context
// cancellation; Go cannot forcibly terminate an arbitrary callback safely.
// Inputs and their nested reference fields are borrowed read-only. A stage
// making changes must return its own slice and own any nested values it changes.
type Stage interface {
	Name() string
	Process(context.Context, []ScoredMethod) ([]ScoredMethod, error)
	Budget() time.Duration
}
type StageFunc struct {
	name   string
	budget time.Duration
	fn     func(context.Context, []ScoredMethod) ([]ScoredMethod, error)
}

func NewStage(name string, budget time.Duration, fn func(context.Context, []ScoredMethod) ([]ScoredMethod, error)) Stage {
	return &StageFunc{name: name, budget: budget, fn: fn}
}
func (s *StageFunc) Name() string          { return s.name }
func (s *StageFunc) Budget() time.Duration { return s.budget }
func (s *StageFunc) Process(ctx context.Context, in []ScoredMethod) ([]ScoredMethod, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s.budget > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.budget)
		defer cancel()
	}
	if err := ctx.Err(); err != nil {
		return in, err
	}
	if s.fn == nil {
		return in, fmt.Errorf("stage %q has no function", s.name)
	}
	out, err := s.fn(ctx, in)
	if err == nil {
		err = ctx.Err()
	}
	return out, err
}

type PipelineMetrics struct {
	Scope           string         `json:"scope,omitempty"`
	TotalDurationNs int64          `json:"total_duration_ns"`
	TotalMethods    int            `json:"total_methods"`
	Stages          []StageMetrics `json:"stages"`
	TotalDurationMs int64          `json:"total_duration_ms"`
	Throughput      float64        `json:"throughput_methods_per_sec"`
	SchemaHash      string         `json:"schema_hash"`
	SchemaVersion   int            `json:"schema_version"`
	Goroutines      int            `json:"goroutines"` // configured worker budget, not observed live count
	Errors          []string       `json:"errors,omitempty"`
}
type StageMetrics struct {
	Name        string  `json:"name"`
	InputCount  int     `json:"input_count"`
	OutputCount int     `json:"output_count"`
	DurationMs  int64   `json:"duration_ms"`
	Filtered    int     `json:"filtered"`
	Error       string  `json:"error,omitempty"`
	Throughput  float64 `json:"throughput,omitempty"`
}

// MLPipeline runs a linear sequence (not a DAG). Configuration and completed-run
// metrics are synchronized. Concurrent callers own their inputs; custom stages
// must also synchronize any shared state they capture. Metrics reports the last
// COMPLETED run and remains readable while another run is in progress.
type MLPipeline struct {
	stages  []Stage
	metrics PipelineMetrics
	mu      sync.Mutex
	workers int
}

func NewMLPipeline(workers int, stages ...Stage) *MLPipeline {
	if workers <= 0 {
		workers = max(1, runtime.GOMAXPROCS(0)*3/4)
	}
	return &MLPipeline{stages: append([]Stage(nil), stages...), workers: workers}
}
func (p *MLPipeline) AddStage(s Stage) *MLPipeline {
	p.mu.Lock()
	p.stages = append(p.stages, s)
	p.mu.Unlock()
	return p
}
func (p *MLPipeline) Run(ctx context.Context, input []ScoredMethod) ([]ScoredMethod, PipelineMetrics) {
	if ctx == nil {
		ctx = context.Background()
	}
	p.mu.Lock()
	stages := append([]Stage(nil), p.stages...)
	workers := p.workers
	p.mu.Unlock()
	start := time.Now()
	reg := GlobalFeatureRegistry()
	metrics := PipelineMetrics{TotalMethods: len(input), SchemaHash: reg.SchemaHash(), SchemaVersion: reg.Version(), Goroutines: workers, Stages: make([]StageMetrics, 0, len(stages))}
	cur := input
	for _, stage := range stages {
		if err := ctx.Err(); err != nil {
			metrics.Errors = append(metrics.Errors, "pipeline cancelled: "+err.Error())
			break
		}
		if stage == nil {
			metrics.Errors = append(metrics.Errors, "nil stage skipped")
			continue
		}
		began := time.Now()
		// Enforce Budget for every implementation, not only StageFunc adapters.
		stageCtx := ctx
		cancel := func() {}
		if stage.Budget() > 0 {
			stageCtx, cancel = context.WithTimeout(ctx, stage.Budget())
		}
		out, err := stage.Process(stageCtx, cur)
		if err == nil {
			err = stageCtx.Err()
		}
		cancel()
		elapsed := time.Since(began)
		sm := StageMetrics{Name: stage.Name(), InputCount: len(cur), OutputCount: len(cur), DurationMs: elapsed.Milliseconds(), Throughput: float64(len(cur)) / maxFloat(elapsed.Seconds(), .000001)}
		if err != nil {
			sm.Error = err.Error()
			metrics.Errors = append(metrics.Errors, fmt.Sprintf("stage %q: %v", stage.Name(), err))
			// Fail-open means retain the previous valid output, not successful filtering.
		} else {
			sm.OutputCount = len(out)
			sm.Filtered = max(0, len(cur)-len(out))
			cur = out
		}
		metrics.Stages = append(metrics.Stages, sm)
	}
	elapsed := time.Since(start)
	metrics.TotalDurationMs = elapsed.Milliseconds()
	metrics.TotalDurationNs = elapsed.Nanoseconds()
	metrics.Throughput = float64(len(input)) / maxFloat(elapsed.Seconds(), .000001)
	p.mu.Lock()
	p.metrics = copyPipelineMetrics(metrics)
	p.mu.Unlock()
	return cur, metrics
}
func copyPipelineMetrics(m PipelineMetrics) PipelineMetrics {
	m.Stages = append([]StageMetrics(nil), m.Stages...)
	m.Errors = append([]string(nil), m.Errors...)
	return m
}
func (p *MLPipeline) Metrics() PipelineMetrics {
	p.mu.Lock()
	defer p.mu.Unlock()
	return copyPipelineMetrics(p.metrics)
}

// ScoreStage scores the supplied methods without the candidate/score cutoff in
// ScoreClass. It is no longer a pass-through placeholder. The legacy analyzer
// argument remains supported for callers that do not supply a scorer.
func ScoreStage(scorer *PatchScorer, analyzer *PatchAnalyzer) Stage {
	if scorer == nil {
		if analyzer == nil {
			analyzer = NewPatchAnalyzer()
		}
		scorer = NewPatchScorer(analyzer)
	}
	return NewStage("score", 30*time.Second, func(ctx context.Context, in []ScoredMethod) ([]ScoredMethod, error) {
		out := append([]ScoredMethod(nil), in...)
		for i := range out {
			if err := ctx.Err(); err != nil {
				return in, err
			}
			if score := scorer.ScoreMethod(&out[i].Method); score != nil {
				out[i].Score = *score
			}
		}
		return out, nil
	})
}
func NoiseFilterStage(nf NoiseFilter, scorer InterestingScorer, entry EntryPointDetector) Stage {
	return NewStage("noise_filter", 15*time.Second, func(ctx context.Context, in []ScoredMethod) ([]ScoredMethod, error) {
		if nf == nil {
			return in, nil
		}
		out := make([]ScoredMethod, 0, len(in))
		for _, sm := range in {
			if err := ctx.Err(); err != nil {
				return in, err
			}
			var interesting *InterestingScore
			if scorer != nil {
				interesting = scorer.Calculate(&sm.Method, nil)
			}
			filtered, _ := nf.ShouldFilter(&sm.Method, interesting)
			// Diagnostic evidence must survive library/generic-method suppression.
			signals := sm.Score.VulnerabilitySignals
			if signals == nil && filtered {
				signals = AnalyzeVulnerabilitySignals(&sm.Method)
			}
			if !filtered || signals.HasAnyHighSeverity() {
				sm.Interesting = interesting
				out = append(out, sm)
			}
		}
		return out, nil
	})
}

// ParallelMapStage preserves the old callback API. New expensive callbacks
// should use ParallelMapStageContext and check their received context.
func ParallelMapStage(name string, workers int, fn func(*ScoredMethod) error) Stage {
	return ParallelMapStageContext(name, workers, func(_ context.Context, sm *ScoredMethod) error {
		if fn == nil {
			return fmt.Errorf("stage %q has no mapper", name)
		}
		return fn(sm)
	})
}
func ParallelMapStageContext(name string, workers int, fn func(context.Context, *ScoredMethod) error) Stage {
	if workers <= 0 {
		workers = max(1, runtime.GOMAXPROCS(0)*3/4)
	}
	return NewStage(name, 60*time.Second, func(ctx context.Context, in []ScoredMethod) ([]ScoredMethod, error) {
		if len(in) == 0 {
			return in, nil
		}
		if fn == nil {
			return in, fmt.Errorf("stage %q has no mapper", name)
		}
		out := append([]ScoredMethod(nil), in...)
		workCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		jobs := make(chan int)
		var wg sync.WaitGroup
		var once sync.Once
		var firstErr error
		fail := func(err error) { once.Do(func() { firstErr = err; cancel() }) }
		n := workers
		if n > len(in) {
			n = len(in)
		}
		if n > 1024 {
			n = 1024
		}
		for w := 0; w < n; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range jobs {
					if err := workCtx.Err(); err != nil {
						return
					}
					if err := fn(workCtx, &out[i]); err != nil {
						fail(err)
						return
					}
				}
			}()
		}
	send:
		for i := range out {
			select {
			case <-workCtx.Done():
				break send
			case jobs <- i:
			}
		}
		close(jobs)
		wg.Wait()
		if firstErr != nil {
			return in, firstErr
		}
		if err := ctx.Err(); err != nil {
			return in, err
		}
		return out, nil
	})
}
func FilterStage(name string, pred func(*ScoredMethod) bool) Stage {
	return NewStage(name, 10*time.Second, func(ctx context.Context, in []ScoredMethod) ([]ScoredMethod, error) {
		if pred == nil {
			return in, fmt.Errorf("stage %q has no predicate", name)
		}
		out := make([]ScoredMethod, 0, len(in))
		for _, sm := range in {
			if err := ctx.Err(); err != nil {
				return in, err
			}
			if pred(&sm) {
				out = append(out, sm)
			}
		}
		return out, nil
	})
}
func SortStage() Stage {
	return NewStage("sort_by_patch_value", 5*time.Second, func(_ context.Context, in []ScoredMethod) ([]ScoredMethod, error) {
		out := append([]ScoredMethod(nil), in...)
		sort.SliceStable(out, func(i, j int) bool { return out[i].Score.FinalScore > out[j].Score.FinalScore })
		return out, nil
	})
}
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
