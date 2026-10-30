// Package piracy — scoring_metrics.go
// Runtime metrics for observability
package piracy

import (
	"sync"
	"sync/atomic"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// SCORING METRICS — потокобезопасные метрики для мониторинга
// ═══════════════════════════════════════════════════════════════════════════════

type ScoringMetrics struct {
	TotalScored     atomic.Int64
	TotalHighRisk   atomic.Int64
	TotalCritical   atomic.Int64
	TotalBoosted    atomic.Int64 // сколько раз boost > 1.0
	MaxConfSeen     atomic.Int64 // stored as int64 (conf * 10000)
	TotalDurationNs atomic.Int64

	// Гистограмма по risk level
	mu         sync.RWMutex
	riskCounts map[RiskLevel]int64
}

func NewScoringMetrics() *ScoringMetrics {
	return &ScoringMetrics{
		riskCounts: make(map[RiskLevel]int64),
	}
}

func (m *ScoringMetrics) Record(result *ScoringResult, duration time.Duration) {
	m.TotalScored.Add(1)
	m.TotalDurationNs.Add(int64(duration))

	confInt := int64(result.FinalConfidence * 10000)
	for {
		old := m.MaxConfSeen.Load()
		if confInt <= old || m.MaxConfSeen.CompareAndSwap(old, confInt) {
			break
		}
	}

	if result.Boost > 1.0 {
		m.TotalBoosted.Add(1)
	}

	switch result.RiskLevel {
	case RiskHigh:
		m.TotalHighRisk.Add(1)
	case RiskCritical:
		m.TotalCritical.Add(1)
	}

	m.mu.Lock()
	m.riskCounts[result.RiskLevel]++
	m.mu.Unlock()
}

func (m *ScoringMetrics) Snapshot() map[string]interface{} {
	m.mu.RLock()
	counts := make(map[RiskLevel]int64, len(m.riskCounts))
	for k, v := range m.riskCounts {
		counts[k] = v
	}
	m.mu.RUnlock()

	total := m.TotalScored.Load()
	avgNs := int64(0)
	if total > 0 {
		avgNs = m.TotalDurationNs.Load() / total
	}

	return map[string]interface{}{
		"total_scored":      total,
		"total_high_risk":   m.TotalHighRisk.Load(),
		"total_critical":    m.TotalCritical.Load(),
		"total_boosted":     m.TotalBoosted.Load(),
		"max_confidence":    float64(m.MaxConfSeen.Load()) / 10000.0,
		"avg_duration_us":   avgNs / 1000,
		"risk_distribution": counts,
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// INSTRUMENTED ENGINE — обёртка с метриками
// ═══════════════════════════════════════════════════════════════════════════════

type InstrumentedScoringEngine struct {
	*ScoringEngine
	Metrics *ScoringMetrics
}

func NewInstrumentedScoringEngine() *InstrumentedScoringEngine {
	return &InstrumentedScoringEngine{
		ScoringEngine: NewScoringEngine(),
		Metrics:       NewScoringMetrics(),
	}
}

func (ise *InstrumentedScoringEngine) CalculateScore(findings []Finding) *ScoringResult {
	start := time.Now()
	result := ise.ScoringEngine.CalculateScore(findings)
	ise.Metrics.Record(result, time.Since(start))
	return result
}
