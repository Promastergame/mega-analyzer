package ml

import (
	"sync"

	"mega-analyzer/pkg/internal/cfg"
)

// SemanticGateDetectorAdapter adapts the existing semantic gate detection logic to the Detector interface.
type SemanticGateDetectorAdapter struct {
	detector  *SemanticGateDetector
	config    DetectorConfig
	statistics map[string]interface{}
	mu        sync.RWMutex
}

// NewSemanticGateDetectorAdapter creates a new adapter for semantic gate detection.
func NewSemanticGateDetectorAdapter() *SemanticGateDetectorAdapter {
	return &SemanticGateDetectorAdapter{
		detector:  NewSemanticGateDetector(),
		config:    DefaultDetectorConfig(),
		statistics: make(map[string]interface{}),
	}
}

// Name implements Detector interface.
func (s *SemanticGateDetectorAdapter) Name() string {
	return "SemanticGateDetector"
}

// Detect implements Detector interface.
func (s *SemanticGateDetectorAdapter) Detect(mi *MethodInfo) interface{} {
	// SemanticGateDetector requires CFG/DFG/StructuralSignals which we don't have here
	// For now, we'll use a simplified version with available data
	result := s.detector.Analyze(mi, nil, nil, nil, false)
	s.recordStatistics(result)
	return result
}

// DetectWithFullContext provides full context for more accurate detection.
func (s *SemanticGateDetectorAdapter) DetectWithFullContext(mi *MethodInfo, cg *cfg.ControlFlowGraph, structSigs *StructuralSignals, dfg *DFGInfo, crackConfirmed bool) *SemanticGateResult {
	result := s.detector.Analyze(mi, cg, structSigs, dfg, crackConfirmed)
	s.recordStatistics(result)
	return result
}

// IsInteresting implements Detector interface.
func (s *SemanticGateDetectorAdapter) IsInteresting(result interface{}) bool {
	if result == nil {
		return false
	}
	if gate, ok := result.(*SemanticGateResult); ok && gate != nil {
		return gate.Verdict == GateRealGate && gate.Score >= s.config.ConfidenceThreshold
	}
	return false
}

// GetStatistics implements Detector interface.
func (s *SemanticGateDetectorAdapter) GetStatistics() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	stats := make(map[string]interface{}, len(s.statistics))
	for k, v := range s.statistics {
		stats[k] = v
	}
	return stats
}

// Reset implements Detector interface.
func (s *SemanticGateDetectorAdapter) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.statistics = make(map[string]interface{})
}

// Config returns the detector's configuration.
func (s *SemanticGateDetectorAdapter) Config() DetectorConfig {
	return s.config
}

// SetConfig updates the detector's configuration.
func (s *SemanticGateDetectorAdapter) SetConfig(config DetectorConfig) {
	s.config = config
}

// SetDetector sets the underlying semantic gate detector.
func (s *SemanticGateDetectorAdapter) SetDetector(detector *SemanticGateDetector) {
	s.detector = detector
}

// recordStatistics updates detector statistics.
func (s *SemanticGateDetectorAdapter) recordStatistics(result *SemanticGateResult) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.statistics["total_analyzed"] = s.getIntStat("total_analyzed") + 1

	if result == nil {
		return
	}

	switch result.Verdict {
	case GateRealGate:
		s.statistics["real_gates_found"] = s.getIntStat("real_gates_found") + 1
	case GateWeakGate:
		s.statistics["weak_gates_found"] = s.getIntStat("weak_gates_found") + 1
	case GateNonGate:
		s.statistics["non_gates_found"] = s.getIntStat("non_gates_found") + 1
	}

	s.statistics["total_score_sum"] = s.getFloatStat("total_score_sum") + result.Score
	s.statistics["total_confidence_sum"] = s.getFloatStat("total_confidence_sum") + result.Confidence
}

func (s *SemanticGateDetectorAdapter) getIntStat(key string) int {
	if val, ok := s.statistics[key]; ok {
		if intVal, ok := val.(int); ok {
			return intVal
		}
	}
	return 0
}

func (s *SemanticGateDetectorAdapter) getFloatStat(key string) float64 {
	if val, ok := s.statistics[key]; ok {
		if floatVal, ok := val.(float64); ok {
			return floatVal
		}
	}
	return 0.0
}
