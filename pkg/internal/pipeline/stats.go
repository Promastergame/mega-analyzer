// pkg/internal/pipeline/stats.go
package pipeline

import (
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PIPELINE STATS
// ═══════════════════════════════════════════════════════════════════════════════

type PipelineStats struct {
	FilesDiscovered atomic.Int64
	FilesEligible   atomic.Int64
	FilesTotal      atomic.Int64
	FilesProcessed  atomic.Int64
	// Work units drive the progress bar. A normal file costs one unit; a DEX
	// costs one unit per contained class, so progress cannot reach 99% while a
	// large classes.dex is still being analysed.
	WorkTotal       atomic.Int64
	WorkProcessed   atomic.Int64
	FilesParsed     atomic.Int64
	FilesSkipped    atomic.Int64
	FilesFailed     atomic.Int64
	ParseFailed     atomic.Int64
	SkippedBySize   atomic.Int64
	SkippedByLimit  atomic.Int64
	Unsupported     atomic.Int64
	ClassesAnalyzed atomic.Int64
	MethodsAnalyzed atomic.Int64
	AnalysisUnits   atomic.Int64
	FindingsBearing atomic.Int64
	LimitReached    atomic.Bool
	MatchesTotal    atomic.Int64
	HotspotsTotal   atomic.Int64
	CriticalCount   atomic.Int64
	BytesProcessed  atomic.Int64
	ErrorCount      atomic.Int64
	ResultsDropped  atomic.Int64
	DeobfTotal      atomic.Int64
	DeobfProcessed  atomic.Int64
	StartTime       time.Time

	// InternalTimings breaks down scan_and_analyze into individual sub-stages.
	// Workers call Record/Hit/Miss directly on the counters — no lock needed.
	InternalTimings *InternalTimings
}

func NewPipelineStats() *PipelineStats {
	return &PipelineStats{
		StartTime:       time.Now(),
		InternalTimings: &InternalTimings{},
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// TRACER
// ═══════════════════════════════════════════════════════════════════════════════

type StageMetrics struct {
	Name      string
	StartTime time.Time
	EndTime   time.Time
	Duration  time.Duration
	Memory    int64
}

type Tracer struct {
	enabled bool
	stages  []StageMetrics
	mu      sync.Mutex
}

func NewTracer(enabled bool) *Tracer {
	return &Tracer{
		enabled: enabled,
		stages:  make([]StageMetrics, 0, 8),
	}
}

func (t *Tracer) StartStage(name string) *StageMetrics {
	if !t.enabled {
		return nil
	}
	return &StageMetrics{Name: name, StartTime: time.Now()}
}

func (t *Tracer) EndStage(m *StageMetrics) {
	if !t.enabled || m == nil {
		return
	}
	m.EndTime = time.Now()
	m.Duration = m.EndTime.Sub(m.StartTime)

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	m.Memory = int64(memStats.Alloc)

	t.mu.Lock()
	t.stages = append(t.stages, *m)
	t.mu.Unlock()
}

func (t *Tracer) GetStages() []StageMetrics {
	t.mu.Lock()
	defer t.mu.Unlock()
	result := make([]StageMetrics, len(t.stages))
	copy(result, t.stages)
	return result
}
