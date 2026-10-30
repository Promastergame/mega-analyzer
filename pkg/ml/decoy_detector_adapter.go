package ml

import (
	"sync"
)

// DecoyDetectorAdapter adapts the existing decoy detection logic to the Detector interface.
type DecoyDetectorAdapter struct {
	config    DetectorConfig
	statistics map[string]interface{}
	mu        sync.RWMutex
}

// NewDecoyDetectorAdapter creates a new adapter for decoy detection.
func NewDecoyDetectorAdapter() *DecoyDetectorAdapter {
	return &DecoyDetectorAdapter{
		config:    DefaultDetectorConfig(),
		statistics: make(map[string]interface{}),
	}
}

// Name implements Detector interface.
func (d *DecoyDetectorAdapter) Name() string {
	return "DecoyDetector"
}

// Detect implements Detector interface.
func (d *DecoyDetectorAdapter) Detect(mi *MethodInfo) interface{} {
	result := AnalyzeDecoy(mi)
	d.recordStatistics(result)
	return result
}

// IsInteresting implements Detector interface.
func (d *DecoyDetectorAdapter) IsInteresting(result interface{}) bool {
	if result == nil {
		return false
	}
	if decoy, ok := result.(*DecoyAnalysis); ok && decoy != nil {
		return decoy.IsDecoy && decoy.Confidence() >= d.config.ConfidenceThreshold
	}
	return false
}

// GetStatistics implements Detector interface.
func (d *DecoyDetectorAdapter) GetStatistics() map[string]interface{} {
	d.mu.RLock()
	defer d.mu.RUnlock()
	stats := make(map[string]interface{}, len(d.statistics))
	for k, v := range d.statistics {
		stats[k] = v
	}
	return stats
}

// Reset implements Detector interface.
func (d *DecoyDetectorAdapter) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.statistics = make(map[string]interface{})
}

// Config returns the detector's configuration.
func (d *DecoyDetectorAdapter) Config() DetectorConfig {
	return d.config
}

// SetConfig updates the detector's configuration.
func (d *DecoyDetectorAdapter) SetConfig(config DetectorConfig) {
	d.config = config
}

// recordStatistics updates detector statistics.
func (d *DecoyDetectorAdapter) recordStatistics(result *DecoyAnalysis) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if result == nil {
		d.statistics["total_analyzed"] = d.getIntStat("total_analyzed") + 1
		return
	}

	d.statistics["total_analyzed"] = d.getIntStat("total_analyzed") + 1
	if result.IsDecoy {
		d.statistics["decoys_found"] = d.getIntStat("decoys_found") + 1
	}
	d.statistics["total_penalty_sum"] = d.getFloatStat("total_penalty_sum") + result.TotalPenalty
}

func (d *DecoyDetectorAdapter) getIntStat(key string) int {
	if val, ok := d.statistics[key]; ok {
		if intVal, ok := val.(int); ok {
			return intVal
		}
	}
	return 0
}

func (d *DecoyDetectorAdapter) getFloatStat(key string) float64 {
	if val, ok := d.statistics[key]; ok {
		if floatVal, ok := val.(float64); ok {
			return floatVal
		}
	}
	return 0.0
}
