// pkg/internal/pipeline/internal_timings.go
//
// Fine-grained, zero-overhead internal stage timing.
//
// Each sub-stage inside scan_and_analyze accumulates its own:
//   - total CPU-like time  (sum across all goroutines — not wall-clock)
//   - call count
//   - per-call max duration (best-effort, lock-free CAS)
//   - cache hits / misses
//
// Everything is atomic — safe for concurrent workers. The final summary is
// printed once at the end of Run() so developers can see exactly where time
// goes without attaching a heavy profiler.
package pipeline

import (
	"fmt"
	"sync/atomic"
	"time"

	"mega-analyzer/pkg/logger"
)

// ═══════════════════════════════════════════════════════════════════════════════
// STAGE COUNTER
// ═══════════════════════════════════════════════════════════════════════════════

// StageCounter accumulates CPU-like time for a named pipeline sub-stage.
// All fields are updated atomically; safe for any number of concurrent goroutines.
// The max field uses a lock-free CAS loop — the value may be slightly off in the
// rare case of a concurrent update, which is acceptable for diagnostics.
type StageCounter struct {
	totalNs   atomic.Int64
	calls     atomic.Int64
	maxNs     atomic.Int64
	cacheHits atomic.Int64
	cacheMiss atomic.Int64
}

// Record adds one observation of duration d.
func (s *StageCounter) Record(d time.Duration) {
	ns := d.Nanoseconds()
	if ns < 0 {
		ns = 0
	}
	s.totalNs.Add(ns)
	s.calls.Add(1)
	// Best-effort lock-free max.
	for {
		cur := s.maxNs.Load()
		if ns <= cur {
			break
		}
		if s.maxNs.CompareAndSwap(cur, ns) {
			break
		}
	}
}

// Hit records one cache hit (no duration — the point is we skipped the work).
func (s *StageCounter) Hit() { s.cacheHits.Add(1) }

// Miss records one cache miss.
func (s *StageCounter) Miss() { s.cacheMiss.Add(1) }

// snapshot returns a read-consistent copy of all fields.
func (s *StageCounter) snapshot() stageSnap {
	return stageSnap{
		totalNs:   s.totalNs.Load(),
		calls:     s.calls.Load(),
		maxNs:     s.maxNs.Load(),
		cacheHits: s.cacheHits.Load(),
		cacheMiss: s.cacheMiss.Load(),
	}
}

type stageSnap struct {
	totalNs   int64
	calls     int64
	maxNs     int64
	cacheHits int64
	cacheMiss int64
}

func (sn stageSnap) avgNs() int64 {
	if sn.calls == 0 {
		return 0
	}
	return sn.totalNs / sn.calls
}

func (sn stageSnap) hitRate() string {
	total := sn.cacheHits + sn.cacheMiss
	if total == 0 {
		return ""
	}
	rate := float64(sn.cacheHits) * 100.0 / float64(total)
	return fmt.Sprintf("  cache=%d/%d (%.0f%%)", sn.cacheHits, total, rate)
}

// fmtNs formats nanoseconds as a human-readable duration string.
func fmtNs(ns int64) string {
	d := time.Duration(ns)
	switch {
	case d >= time.Second:
		return fmt.Sprintf("%.2fs", d.Seconds())
	case d >= time.Millisecond:
		return fmt.Sprintf("%.1fms", float64(d)/float64(time.Millisecond))
	case d >= time.Microsecond:
		return fmt.Sprintf("%.1fµs", float64(d)/float64(time.Microsecond))
	default:
		return fmt.Sprintf("%dns", ns)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// INTERNAL TIMINGS — collection of all sub-stage counters
// ═══════════════════════════════════════════════════════════════════════════════

// InternalTimings holds one StageCounter per named sub-stage.
// Add new counters here when new hot paths are instrumented.
type InternalTimings struct {
	// SmaliParse: time spent in smaliParser.Parse() — one call per class.
	SmaliParse StageCounter

	// MethodFeatures: time spent in methodAnalyzer.Analyze() — one call per
	// method that was a cache miss.
	MethodFeatures StageCounter

	// CFGBuild: time spent in buildMethodCFG() — one call per method.
	// Cache hit/miss track contentcache CFG summary lookups.
	CFGBuild StageCounter

	// Deobfuscation: time spent in engine.Analyze(graph) — one call per
	// method processed by the smali deobfuscation engine.
	// Cache hit/miss track contentcache deobf lookups.
	Deobfuscation StageCounter

	// PatternMatch: time spent in matcher.MatchContentWithFilterLower() —
	// one call per file that passes the content-scan check.
	PatternMatch StageCounter

	// Detectors: aggregate time spent in the detector chain (runDetectors).
	// This is wall-clock per file because detectors run sequentially per file.
	Detectors StageCounter

	// CollectResult: time spent in collectResult() — one call per non-nil
	// analysis unit forwarded from a worker.
	CollectResult StageCounter
}

// ═══════════════════════════════════════════════════════════════════════════════
// LOGGING
// ═══════════════════════════════════════════════════════════════════════════════

// logInternalTimings emits a single structured log block with the accumulated
// sub-stage breakdown. Call once at the end of Run() after all workers finish.
func (t *InternalTimings) log() {
	if t == nil {
		return
	}

	type row struct {
		name string
		sn   stageSnap
	}

	rows := []row{
		{"smali_parse", t.SmaliParse.snapshot()},
		{"method_features", t.MethodFeatures.snapshot()},
		{"cfg_build", t.CFGBuild.snapshot()},
		{"deobfuscation", t.Deobfuscation.snapshot()},
		{"pattern_match", t.PatternMatch.snapshot()},
		{"detectors", t.Detectors.snapshot()},
		{"collect_result", t.CollectResult.snapshot()},
	}

	// Skip the whole block if nothing was instrumented (e.g. empty run).
	anyData := false
	for _, r := range rows {
		if r.sn.calls > 0 {
			anyData = true
			break
		}
	}
	if !anyData {
		return
	}

	logger.Info("Internal stage timings (accumulated CPU-like time across all workers):")
	for _, r := range rows {
		sn := r.sn
		if sn.calls == 0 {
			continue
		}
		cacheStr := sn.hitRate()
		logger.Info(fmt.Sprintf("  %-16s calls=%-6d  total=%-8s  avg=%-8s  max=%-8s%s",
			r.name,
			sn.calls,
			fmtNs(sn.totalNs),
			fmtNs(sn.avgNs()),
			fmtNs(sn.maxNs),
			cacheStr,
		))
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// SYNC HELPER — avoids the atomic.Int64 zero-value gotcha in tests
// ═══════════════════════════════════════════════════════════════════════════════

// resetInternalTimings is used by resetRunState to start a fresh measurement
// window without reallocating the struct (avoids a heap allocation per run).
func resetInternalTimings(t *InternalTimings) {
	if t == nil {
		return
	}
	zero := func(c *StageCounter) {
		c.totalNs.Store(0)
		c.calls.Store(0)
		c.maxNs.Store(0)
		c.cacheHits.Store(0)
		c.cacheMiss.Store(0)
	}
	zero(&t.SmaliParse)
	zero(&t.MethodFeatures)
	zero(&t.CFGBuild)
	zero(&t.Deobfuscation)
	zero(&t.PatternMatch)
	zero(&t.Detectors)
	zero(&t.CollectResult)
}

// ensure atomic.Int64 alignment (no-op, Go guarantees it, but documents intent)
var _ [0]atomic.Int64
