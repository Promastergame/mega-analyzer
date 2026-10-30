package ml

import (
	"sync"
)

// EntryPointDetectorAdapter adapts the existing entry point detection logic to the Detector interface.
type EntryPointDetectorAdapter struct {
	detector  EntryPointDetector
	config    DetectorConfig
	statistics map[string]interface{}
	mu        sync.RWMutex
}

// NewEntryPointDetectorAdapter creates a new adapter for entry point detection.
func NewEntryPointDetectorAdapter() *EntryPointDetectorAdapter {
	return &EntryPointDetectorAdapter{
		detector:  NewEntryPointDetector(),
		config:    DefaultDetectorConfig(),
		statistics: make(map[string]interface{}),
	}
}

// Name implements Detector interface.
func (e *EntryPointDetectorAdapter) Name() string {
	return "EntryPointDetector"
}

// Detect implements Detector interface.
func (e *EntryPointDetectorAdapter) Detect(mi *MethodInfo) interface{} {
	result := e.detector.Detect(mi)
	e.recordStatistics(result)
	return result
}

// IsInteresting implements Detector interface.
func (e *EntryPointDetectorAdapter) IsInteresting(result interface{}) bool {
	if result == nil {
		return false
	}
	if info, ok := result.(*EntryPointInfo); ok && info != nil {
		return e.detector.IsInteresting(info)
	}
	return false
}

// GetStatistics implements Detector interface.
func (e *EntryPointDetectorAdapter) GetStatistics() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()
	stats := make(map[string]interface{}, len(e.statistics))
	for k, v := range e.statistics {
		stats[k] = v
	}
	return stats
}

// Reset implements Detector interface.
func (e *EntryPointDetectorAdapter) Reset() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.statistics = make(map[string]interface{})
}

// Config returns the detector's configuration.
func (e *EntryPointDetectorAdapter) Config() DetectorConfig {
	return e.config
}

// SetConfig updates the detector's configuration.
func (e *EntryPointDetectorAdapter) SetConfig(config DetectorConfig) {
	e.config = config
}

// SetDetector sets the underlying entry point detector.
func (e *EntryPointDetectorAdapter) SetDetector(detector EntryPointDetector) {
	e.detector = detector
}

// recordStatistics updates detector statistics.
func (e *EntryPointDetectorAdapter) recordStatistics(result *EntryPointInfo) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.statistics["total_analyzed"] = e.getIntStat("total_analyzed") + 1

	if result == nil {
		return
	}

	if result.IsExported {
		e.statistics["exported_found"] = e.getIntStat("exported_found") + 1
	}
	if result.HasIntent {
		e.statistics["intent_handlers_found"] = e.getIntStat("intent_handlers_found") + 1
	}
	if result.HasBundle {
		e.statistics["bundle_handlers_found"] = e.getIntStat("bundle_handlers_found") + 1
	}
	if result.HasURL {
		e.statistics["url_handlers_found"] = e.getIntStat("url_handlers_found") + 1
	}
	if result.Priority >= 7 {
		e.statistics["high_priority_found"] = e.getIntStat("high_priority_found") + 1
	}
}

func (e *EntryPointDetectorAdapter) getIntStat(key string) int {
	if val, ok := e.statistics[key]; ok {
		if intVal, ok := val.(int); ok {
			return intVal
		}
	}
	return 0
}
