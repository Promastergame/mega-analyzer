package vulnscan

import (
	"sync"
	"sync/atomic"
	"time"
)

// ScanTelemetry exposes real-time, poll-able scan progress and metrics,
// replacing the opaque log() callback as the only observability surface.
type ScanTelemetry struct {
	RequestsSent    atomic.Int64
	ResponsesOK     atomic.Int64
	ResponsesError  atomic.Int64
	FindingsEmitted atomic.Int64

	activePhase    atomic.Value // string
	currentSurface atomic.Value // string

	mu             sync.Mutex
	elapsedByPhase map[string]time.Duration
	phaseStarted   map[string]time.Time
}

// NewScanTelemetry returns an initialised telemetry sink.
func NewScanTelemetry() *ScanTelemetry {
	t := &ScanTelemetry{
		elapsedByPhase: make(map[string]time.Duration),
		phaseStarted:   make(map[string]time.Time),
	}
	t.activePhase.Store("")
	t.currentSurface.Store("")
	return t
}

// StartPhase marks a phase active and begins its timer.
func (t *ScanTelemetry) StartPhase(phase string) {
	if t == nil {
		return
	}
	t.activePhase.Store(phase)
	t.mu.Lock()
	t.phaseStarted[phase] = time.Now()
	t.mu.Unlock()
}

// EndPhase accumulates elapsed time for a phase.
func (t *ScanTelemetry) EndPhase(phase string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	if start, ok := t.phaseStarted[phase]; ok {
		t.elapsedByPhase[phase] += time.Since(start)
		delete(t.phaseStarted, phase)
	}
	t.mu.Unlock()
}

// SetSurface records the surface currently under test.
func (t *ScanTelemetry) SetSurface(id string) {
	if t == nil {
		return
	}
	t.currentSurface.Store(id)
}

// OnRequest / OnResponse update counters.
func (t *ScanTelemetry) OnRequest() {
	if t != nil {
		t.RequestsSent.Add(1)
	}
}

func (t *ScanTelemetry) OnResponse(ok bool) {
	if t == nil {
		return
	}
	if ok {
		t.ResponsesOK.Add(1)
	} else {
		t.ResponsesError.Add(1)
	}
}

func (t *ScanTelemetry) OnFinding() {
	if t != nil {
		t.FindingsEmitted.Add(1)
	}
}

// TelemetrySnapshot is a point-in-time, serialisable view of scan progress.
type TelemetrySnapshot struct {
	RequestsSent    int64                    `json:"requests_sent"`
	ResponsesOK     int64                    `json:"responses_ok"`
	ResponsesError  int64                    `json:"responses_error"`
	FindingsEmitted int64                    `json:"findings_emitted"`
	ActivePhase     string                   `json:"active_phase"`
	CurrentSurface  string                   `json:"current_surface"`
	ElapsedByPhase  map[string]time.Duration `json:"elapsed_by_phase"`
}

// Snapshot captures current telemetry safely.
func (t *ScanTelemetry) Snapshot() TelemetrySnapshot {
	if t == nil {
		return TelemetrySnapshot{}
	}
	t.mu.Lock()
	elapsed := make(map[string]time.Duration, len(t.elapsedByPhase))
	for k, v := range t.elapsedByPhase {
		elapsed[k] = v
	}
	t.mu.Unlock()

	phase, _ := t.activePhase.Load().(string)
	surface, _ := t.currentSurface.Load().(string)
	return TelemetrySnapshot{
		RequestsSent:    t.RequestsSent.Load(),
		ResponsesOK:     t.ResponsesOK.Load(),
		ResponsesError:  t.ResponsesError.Load(),
		FindingsEmitted: t.FindingsEmitted.Load(),
		ActivePhase:     phase,
		CurrentSurface:  surface,
		ElapsedByPhase:  elapsed,
	}
}
