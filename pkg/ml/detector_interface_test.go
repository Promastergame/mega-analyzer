package ml

import (
	"testing"
)

func TestDetectorChain(t *testing.T) {
	chain := NewDetectorChain(
		NewDecoyDetectorAdapter(),
		NewEntryPointDetectorAdapter(),
	)

	// onCreate/MainActivity is an entry point (and a tiny body for the
	// decoy detector), so the Decoy+EntryPoint chain must return a result.
	// NOTE: isLicensed/LicenseChecker is NOT valid here — it has security
	// gate immunity (never a decoy) and is not an entry point, so the
	// chain correctly returns nil for it.
	mi := &MethodInfo{
		Name:      "onCreate",
		ClassName: "Lcom/example/MainActivity;",
		RawBody:   []string{"const/4 v0, 0x1", "return v0"},
	}

	result := chain.Detect(mi)
	if result == nil {
		t.Error("Expected result from detector chain")
	}

	stats := chain.GetStatistics()
	if stats == nil {
		t.Error("Expected statistics from detector chain")
	}

	chain.Reset()
	statsAfterReset := chain.GetStatistics()
	if len(statsAfterReset) != 0 {
		t.Error("Expected empty statistics after reset")
	}
}

func TestDecoyDetectorAdapter(t *testing.T) {
	adapter := NewDecoyDetectorAdapter()

	if adapter.Name() != "DecoyDetector" {
		t.Errorf("Expected name 'DecoyDetector', got '%s'", adapter.Name())
	}

	// Test with data class method
	mi := &MethodInfo{
		Name:      "equals",
		ClassName: "Lcom/example/Data;",
		RawBody:   []string{"const/4 v0, 0x1", "return v0"},
	}

	result := adapter.Detect(mi)
	if result == nil {
		t.Error("Expected result from decoy detector")
	}

	decoy, ok := result.(*DecoyAnalysis)
	if !ok {
		t.Error("Expected DecoyAnalysis result")
	}

	if !decoy.IsDecoy {
		t.Error("Expected decoy detection for equals method")
	}

	if !adapter.IsInteresting(result) {
		t.Error("Expected equals method to be interesting")
	}

	stats := adapter.GetStatistics()
	if stats["total_analyzed"] == nil {
		t.Error("Expected total_analyzed statistic")
	}

	adapter.Reset()
	statsAfterReset := adapter.GetStatistics()
	if len(statsAfterReset) != 0 {
		t.Error("Expected empty statistics after reset")
	}
}

func TestEntryPointDetectorAdapter(t *testing.T) {
	adapter := NewEntryPointDetectorAdapter()

	if adapter.Name() != "EntryPointDetector" {
		t.Errorf("Expected name 'EntryPointDetector', got '%s'", adapter.Name())
	}

	// Test with activity lifecycle method
	mi := &MethodInfo{
		Name:      "onCreate",
		ClassName: "Lcom/example/MainActivity;",
		RawBody:   []string{"const/4 v0, 0x1", "return v0"},
	}

	result := adapter.Detect(mi)
	if result == nil {
		t.Error("Expected result from entry point detector")
	}

	info, ok := result.(*EntryPointInfo)
	if !ok {
		t.Error("Expected EntryPointInfo result")
	}

	if !adapter.IsInteresting(result) {
		t.Error("Expected onCreate to be interesting")
	}

	if info.Type != EntryPointActivity {
		t.Errorf("Expected EntryPointActivity, got %v", info.Type)
	}

	stats := adapter.GetStatistics()
	if stats["total_analyzed"] == nil {
		t.Error("Expected total_analyzed statistic")
	}

	adapter.Reset()
	statsAfterReset := adapter.GetStatistics()
	if len(statsAfterReset) != 0 {
		t.Error("Expected empty statistics after reset")
	}
}

func TestSemanticGateDetectorAdapter(t *testing.T) {
	adapter := NewSemanticGateDetectorAdapter()

	if adapter.Name() != "SemanticGateDetector" {
		t.Errorf("Expected name 'SemanticGateDetector', got '%s'", adapter.Name())
	}

	// Test with a method
	mi := &MethodInfo{
		Name:      "checkLicense",
		ClassName: "Lcom/example/LicenseChecker;",
		RawBody:   []string{"const/4 v0, 0x1", "return v0"},
	}

	result := adapter.Detect(mi)
	if result == nil {
		t.Error("Expected result from semantic gate detector")
	}

	gate, ok := result.(*SemanticGateResult)
	if !ok {
		t.Error("Expected SemanticGateResult result")
	}

	// Without full context, we expect a weak or non-gate result
	if gate.Verdict == GateRealGate {
		t.Log("Got real gate without full context - this may be expected for some methods")
	}

	stats := adapter.GetStatistics()
	if stats["total_analyzed"] == nil {
		t.Error("Expected total_analyzed statistic")
	}

	adapter.Reset()
	statsAfterReset := adapter.GetStatistics()
	if len(statsAfterReset) != 0 {
		t.Error("Expected empty statistics after reset")
	}
}

func TestDetectorConfig(t *testing.T) {
	config := DefaultDetectorConfig()

	if !config.Enabled {
		t.Error("Expected enabled by default")
	}

	if config.ConfidenceThreshold != 0.5 {
		t.Errorf("Expected confidence threshold 0.5, got %f", config.ConfidenceThreshold)
	}

	if !config.CacheEnabled {
		t.Error("Expected cache enabled by default")
	}

	if !config.StatisticsEnabled {
		t.Error("Expected statistics enabled by default")
	}
}

func TestBaseDetectionResult(t *testing.T) {
	result := &BaseDetectionResult{
		ConfidenceValue: 0.8,
		ReasonText:      "Test reason",
		FilterDecision:  true,
	}

	if result.Confidence() != 0.8 {
		t.Errorf("Expected confidence 0.8, got %f", result.Confidence())
	}

	if result.Reason() != "Test reason" {
		t.Errorf("Expected reason 'Test reason', got '%s'", result.Reason())
	}

	if !result.ShouldFilter() {
		t.Error("Expected ShouldFilter to return true")
	}
}

func TestExampleDetectorChain(t *testing.T) {
	chain := ExampleDetectorChain()
	if chain == nil {
		t.Error("Expected non-nil detector chain")
	}

	if chain.Name() != "DetectorChain" {
		t.Errorf("Expected name 'DetectorChain', got '%s'", chain.Name())
	}

	config := chain.Config()
	if !config.Enabled {
		t.Error("Expected chain to be enabled")
	}
}

func TestStandardDetectorChain(t *testing.T) {
	chain := StandardDetectorChain()
	if chain == nil {
		t.Error("Expected non-nil standard detector chain")
	}

	// Same rationale as TestDetectorChain: use an entry-point method so
	// the chain has an interesting result to return. isLicensed with nil
	// CFG/DFG is a NON_GATE for SemanticGate, immune for Decoy and not an
	// entry point — the chain correctly returns nil for it.
	mi := &MethodInfo{
		Name:      "onCreate",
		ClassName: "Lcom/example/MainActivity;",
		RawBody:   []string{"const/4 v0, 0x1", "return v0"},
	}

	result := chain.Detect(mi)
	// Should get a result from one of the detectors
	if result == nil {
		t.Error("Expected result from standard detector chain")
	}
}

func TestSecurityFocusedDetectorChain(t *testing.T) {
	chain := SecurityFocusedDetectorChain()
	if chain == nil {
		t.Error("Expected non-nil security focused detector chain")
	}

	config := chain.Config()
	if config.ConfidenceThreshold != 0.7 {
		t.Errorf("Expected confidence threshold 0.7 for security chain, got %f", config.ConfidenceThreshold)
	}
}

func TestPerformanceOptimizedDetectorChain(t *testing.T) {
	chain := PerformanceOptimizedDetectorChain()
	if chain == nil {
		t.Error("Expected non-nil performance optimized detector chain")
	}

	config := chain.Config()
	if config.StatisticsEnabled {
		t.Error("Expected statistics disabled for performance chain")
	}
}
