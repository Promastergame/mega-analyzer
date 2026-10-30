package ml

// ═══════════════════════════════════════════════════════════════════════════════
// DETECTOR INTERFACE — unified interface for all detector components
// ═══════════════════════════════════════════════════════════════════════════════
// This file provides a unified interface for all detector components to eliminate
// code duplication and ensure consistency across decoy, entry point, semantic gate,
// and other detectors.

// Detector is the unified interface for all detector components.
// Each detector analyzes a MethodInfo and produces a detection result.
type Detector interface {
	// Name returns the detector's name for logging and debugging.
	Name() string

	// Detect analyzes the method and returns a detection result.
	// The result type varies by detector implementation.
	Detect(mi *MethodInfo) interface{}

	// IsInteresting returns true if the detection result is interesting
	// and should be prioritized in analysis.
	IsInteresting(result interface{}) bool

	// GetStatistics returns detector-specific statistics for monitoring.
	GetStatistics() map[string]interface{}

	// Reset clears any internal state (caches, counters, etc.).
	Reset()
}

// DetectionResult is the base interface for all detection results.
// Specific detectors can extend this with their own result types.
type DetectionResult interface {
	// Confidence returns the detection confidence (0.0 to 1.0).
	Confidence() float64

	// Reason returns a human-readable explanation of the detection.
	Reason() string

	// ShouldFilter returns true if the method should be filtered based on this detection.
	ShouldFilter() bool
}

// BaseDetectionResult provides a default implementation of DetectionResult.
type BaseDetectionResult struct {
	ConfidenceValue float64
	ReasonText     string
	FilterDecision bool
}

func (r *BaseDetectionResult) Confidence() float64 {
	return r.ConfidenceValue
}

func (r *BaseDetectionResult) Reason() string {
	return r.ReasonText
}

func (r *BaseDetectionResult) ShouldFilter() bool {
	return r.FilterDecision
}

// DetectorConfig provides common configuration options for detectors.
type DetectorConfig struct {
	// Enabled determines if the detector is active.
	Enabled bool

	// ConfidenceThreshold is the minimum confidence for a detection to be considered valid.
	ConfidenceThreshold float64

	// CacheEnabled enables internal caching for performance.
	CacheEnabled bool

	// StatisticsEnabled enables statistics collection.
	StatisticsEnabled bool
}

// DefaultDetectorConfig returns the default detector configuration.
func DefaultDetectorConfig() DetectorConfig {
	return DetectorConfig{
		Enabled:             true,
		ConfidenceThreshold: 0.5,
		CacheEnabled:        true,
		StatisticsEnabled:   true,
	}
}

// DetectorChain allows chaining multiple detectors together.
type DetectorChain struct {
	detectors []Detector
	config    DetectorConfig
}

// NewDetectorChain creates a new detector chain with the given detectors.
func NewDetectorChain(detectors ...Detector) *DetectorChain {
	return &DetectorChain{
		detectors: detectors,
		config:    DefaultDetectorConfig(),
	}
}

// AddDetector appends a detector to the chain.
func (dc *DetectorChain) AddDetector(detector Detector) *DetectorChain {
	dc.detectors = append(dc.detectors, detector)
	return dc
}

// Detect runs all detectors in the chain and returns the first interesting result.
func (dc *DetectorChain) Detect(mi *MethodInfo) interface{} {
	for _, detector := range dc.detectors {
		result := detector.Detect(mi)
		if detector.IsInteresting(result) {
			return result
		}
	}
	return nil
}

// IsInteresting returns true if any detector in the chain finds the result interesting.
func (dc *DetectorChain) IsInteresting(result interface{}) bool {
	for _, detector := range dc.detectors {
		if detector.IsInteresting(result) {
			return true
		}
	}
	return false
}

// GetStatistics aggregates statistics from all detectors in the chain.
func (dc *DetectorChain) GetStatistics() map[string]interface{} {
	stats := make(map[string]interface{})
	for _, detector := range dc.detectors {
		detectorStats := detector.GetStatistics()
		for k, v := range detectorStats {
			stats[detector.Name()+"."+k] = v
		}
	}
	return stats
}

// Reset resets all detectors in the chain.
func (dc *DetectorChain) Reset() {
	for _, detector := range dc.detectors {
		detector.Reset()
	}
}

// Name returns the chain's name.
func (dc *DetectorChain) Name() string {
	return "DetectorChain"
}

// Config returns the chain's configuration.
func (dc *DetectorChain) Config() DetectorConfig {
	return dc.config
}

// SetConfig updates the chain's configuration.
func (dc *DetectorChain) SetConfig(config DetectorConfig) {
	dc.config = config
}
