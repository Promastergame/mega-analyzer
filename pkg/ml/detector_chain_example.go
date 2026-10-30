package ml

// ═══════════════════════════════════════════════════════════════════════════════
// DETECTOR CHAIN EXAMPLE
// ═══════════════════════════════════════════════════════════════════════════════
// This file provides an example of how to use the DetectorChain to combine
// multiple detectors for comprehensive method analysis.

// ExampleDetectorChain demonstrates how to create and use a detector chain.
func ExampleDetectorChain() *DetectorChain {
	// Create individual detector adapters
	decoyAdapter := NewDecoyDetectorAdapter()
	entryPointAdapter := NewEntryPointDetectorAdapter()
	semanticGateAdapter := NewSemanticGateDetectorAdapter()

	// Create a detector chain
	chain := NewDetectorChain(
		decoyAdapter,
		entryPointAdapter,
		semanticGateAdapter,
	)

	// Configure the chain
	chain.SetConfig(DetectorConfig{
		Enabled:             true,
		ConfidenceThreshold: 0.6,
		CacheEnabled:        true,
		StatisticsEnabled:   true,
	})

	return chain
}

// StandardDetectorChain returns a pre-configured chain with standard detectors.
func StandardDetectorChain() *DetectorChain {
	return NewDetectorChain(
		NewDecoyDetectorAdapter(),
		NewEntryPointDetectorAdapter(),
		NewSemanticGateDetectorAdapter(),
	)
}

// SecurityFocusedDetectorChain returns a chain optimized for security analysis.
func SecurityFocusedDetectorChain() *DetectorChain {
	decoyAdapter := NewDecoyDetectorAdapter()
	decoyAdapter.SetConfig(DetectorConfig{
		Enabled:             true,
		ConfidenceThreshold: 0.7, // Higher threshold for security analysis
		CacheEnabled:        true,
		StatisticsEnabled:   true,
	})

	semanticGateAdapter := NewSemanticGateDetectorAdapter()
	semanticGateAdapter.SetConfig(DetectorConfig{
		Enabled:             true,
		ConfidenceThreshold: 0.55, // Standard threshold for real gates
		CacheEnabled:        true,
		StatisticsEnabled:   true,
	})

	chain := NewDetectorChain(
		decoyAdapter,
		semanticGateAdapter,
	)
	// Chain-level config mirrors the security focus (0.7): Detect() itself
	// consults adapter thresholds, but callers inspecting chain.Config()
	// expect the security threshold here.
	chain.SetConfig(DetectorConfig{
		Enabled:             true,
		ConfidenceThreshold: 0.7,
		CacheEnabled:        true,
		StatisticsEnabled:   true,
	})
	return chain
}

// PerformanceOptimizedDetectorChain returns a chain optimized for performance.
func PerformanceOptimizedDetectorChain() *DetectorChain {
	decoyAdapter := NewDecoyDetectorAdapter()
	decoyAdapter.SetConfig(DetectorConfig{
		Enabled:             true,
		ConfidenceThreshold: 0.5,
		CacheEnabled:        true,
		StatisticsEnabled:  false, // Disable statistics for performance
	})

	chain := NewDetectorChain(
		decoyAdapter,
	)
	// Mirror the performance choice at chain level so chain.Config()
	// reports statistics disabled.
	chain.SetConfig(DetectorConfig{
		Enabled:             true,
		ConfidenceThreshold: 0.5,
		CacheEnabled:        true,
		StatisticsEnabled:   false,
	})
	return chain
}
