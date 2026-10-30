package apkloader

import (
	"strings"
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// UNIT TESTS: Dynamic Code Loading Resolver
// ═══════════════════════════════════════════════════════════════════════════════

// TestNewDynamicCodeLoadingResolver tests resolver initialization.
func TestNewDynamicCodeLoadingResolver(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	resolver := NewDynamicCodeLoadingResolver(cfg, ssa)

	if resolver == nil {
		t.Fatal("Expected resolver to be created, got nil")
	}
	if resolver.CFG != cfg {
		t.Error("Expected CFG to be set")
	}
	if resolver.SSA != ssa {
		t.Error("Expected SSA to be set")
	}
	if len(resolver.Patterns) != 0 {
		t.Error("Expected empty patterns initially")
	}
	if resolver.Changes != 0 {
		t.Error("Expected zero changes initially")
	}
}

// TestDetectDynamicCodeLoading_EmptyCFG tests detection on empty CFG.
func TestDetectDynamicCodeLoading_EmptyCFG(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	resolver := NewDynamicCodeLoadingResolver(cfg, ssa)
	resolver.DetectDynamicCodeLoading()

	if len(resolver.Patterns) != 0 {
		t.Error("Expected no patterns on empty CFG")
	}
	if resolver.Changes != 0 {
		t.Error("Expected no changes on empty CFG")
	}
}

// TestDetectDynamicCodeLoading_UnreachableBlocks tests that unreachable blocks are skipped.
func TestDetectDynamicCodeLoading_UnreachableBlocks(t *testing.T) {
	// Create a CFG with an unreachable block
	block := &BasicBlock{
		ID:          0,
		Start:       0,
		End:         1,
		IsReachable: false,
		Insns: []MIRInsn{
			{
				Kind:   MIR_INVOKE,
				Offset: 0,
			},
		},
	}

	cfg := &CFG{
		Blocks: []*BasicBlock{block},
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	resolver := NewDynamicCodeLoadingResolver(cfg, ssa)
	resolver.DetectDynamicCodeLoading()

	// Unreachable blocks should be skipped
	if len(resolver.Patterns) != 0 {
		t.Error("Expected no patterns from unreachable blocks")
	}
}

// TestDynamicLoadingType_String tests the string representation of loading types.
func TestDynamicLoadingType_String(t *testing.T) {
	tests := []struct {
		t        DynamicLoadingType
		expected string
	}{
		{DynamicLoadingDexClassLoader, "DexClassLoader"},
		{DynamicLoadingPathClassLoader, "PathClassLoader"},
		{DynamicLoadingClassForName, "Class.forName"},
		{DynamicLoadingGetMethod, "getMethod"},
		{DynamicLoadingGetDeclaredMethod, "getDeclaredMethod"},
		{DynamicLoadingInvoke, "invoke"},
		{DynamicLoadingBytecodeInjection, "BytecodeInjection"},
		{DynamicLoadingReflectionChain, "ReflectionChain"},
		{DynamicLoadingUnknown, "Unknown"},
	}

	for _, test := range tests {
		result := test.t.String()
		if result != test.expected {
			t.Errorf("Expected %s, got %s", test.expected, result)
		}
	}
}

// TestGetPatterns tests pattern retrieval.
func TestGetPatterns(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	resolver := NewDynamicCodeLoadingResolver(cfg, ssa)

	// Add some test patterns
	pattern1 := &DynamicCodeLoadingPattern{
		Type:       DynamicLoadingClassForName,
		Confidence: 80,
	}
	pattern2 := &DynamicCodeLoadingPattern{
		Type:       DynamicLoadingGetMethod,
		Confidence: 70,
	}

	resolver.Patterns = append(resolver.Patterns, pattern1, pattern2)

	patterns := resolver.GetPatterns()
	if len(patterns) != 2 {
		t.Errorf("Expected 2 patterns, got %d", len(patterns))
	}
}

// TestGetPatternsByType tests filtering patterns by type.
func TestGetPatternsByType(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	resolver := NewDynamicCodeLoadingResolver(cfg, ssa)

	// Add patterns of different types
	resolver.Patterns = append(resolver.Patterns,
		&DynamicCodeLoadingPattern{Type: DynamicLoadingClassForName, Confidence: 80},
		&DynamicCodeLoadingPattern{Type: DynamicLoadingGetMethod, Confidence: 70},
		&DynamicCodeLoadingPattern{Type: DynamicLoadingClassForName, Confidence: 75},
	)

	forNamePatterns := resolver.GetPatternsByType(DynamicLoadingClassForName)
	if len(forNamePatterns) != 2 {
		t.Errorf("Expected 2 Class.forName patterns, got %d", len(forNamePatterns))
	}

	getMethodPatterns := resolver.GetPatternsByType(DynamicLoadingGetMethod)
	if len(getMethodPatterns) != 1 {
		t.Errorf("Expected 1 getMethod pattern, got %d", len(getMethodPatterns))
	}
}

// TestGetResolvablePatterns tests filtering resolvable patterns.
func TestGetResolvablePatterns(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	resolver := NewDynamicCodeLoadingResolver(cfg, ssa)

	// Add patterns with different resolvability
	resolver.Patterns = append(resolver.Patterns,
		&DynamicCodeLoadingPattern{IsResolvable: true, Confidence: 80},
		&DynamicCodeLoadingPattern{IsResolvable: false, Confidence: 40},
		&DynamicCodeLoadingPattern{IsResolvable: true, Confidence: 75},
	)

	resolvable := resolver.GetResolvablePatterns()
	if len(resolvable) != 2 {
		t.Errorf("Expected 2 resolvable patterns, got %d", len(resolvable))
	}
}

// TestGetUnresolvablePatterns tests filtering unresolvable patterns.
func TestGetUnresolvablePatterns(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	resolver := NewDynamicCodeLoadingResolver(cfg, ssa)

	// Add patterns with different resolvability
	resolver.Patterns = append(resolver.Patterns,
		&DynamicCodeLoadingPattern{IsResolvable: true, Confidence: 80},
		&DynamicCodeLoadingPattern{IsResolvable: false, Confidence: 40},
		&DynamicCodeLoadingPattern{IsResolvable: false, Confidence: 35},
	)

	unresolvable := resolver.GetUnresolvablePatterns()
	if len(unresolvable) != 2 {
		t.Errorf("Expected 2 unresolvable patterns, got %d", len(unresolvable))
	}
}

// TestGetResolutionStats tests resolution statistics.
func TestGetResolutionStats(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	resolver := NewDynamicCodeLoadingResolver(cfg, ssa)

	// Add patterns
	resolver.Patterns = append(resolver.Patterns,
		&DynamicCodeLoadingPattern{IsResolvable: true},
		&DynamicCodeLoadingPattern{IsResolvable: false},
		&DynamicCodeLoadingPattern{IsResolvable: true},
	)
	resolver.ResolvableCount = 2
	resolver.UnresolvableCount = 1

	total, resolvable, unresolvable := resolver.GetResolutionStats()

	if total != 3 {
		t.Errorf("Expected total 3, got %d", total)
	}
	if resolvable != 2 {
		t.Errorf("Expected resolvable 2, got %d", resolvable)
	}
	if unresolvable != 1 {
		t.Errorf("Expected unresolvable 1, got %d", unresolvable)
	}
}

// TestGetResolutionRate tests resolution rate calculation.
func TestGetResolutionRate(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	resolver := NewDynamicCodeLoadingResolver(cfg, ssa)

	// Test with no patterns
	rate := resolver.GetResolutionRate()
	if rate != 0.0 {
		t.Errorf("Expected 0.0 rate with no patterns, got %f", rate)
	}

	// Test with patterns
	resolver.Patterns = append(resolver.Patterns,
		&DynamicCodeLoadingPattern{IsResolvable: true},
		&DynamicCodeLoadingPattern{IsResolvable: false},
	)
	resolver.ResolvableCount = 1
	resolver.UnresolvableCount = 1

	rate = resolver.GetResolutionRate()
	expected := 50.0
	if rate != expected {
		t.Errorf("Expected %.1f%% rate, got %.1f%%", expected, rate)
	}
}

// TestGetAverageConfidence tests average confidence calculation.
func TestGetAverageConfidence(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	resolver := NewDynamicCodeLoadingResolver(cfg, ssa)

	// Test with no patterns
	avg := resolver.GetAverageConfidence()
	if avg != 0 {
		t.Errorf("Expected 0 average with no patterns, got %d", avg)
	}

	// Test with patterns
	resolver.Patterns = append(resolver.Patterns,
		&DynamicCodeLoadingPattern{Confidence: 80},
		&DynamicCodeLoadingPattern{Confidence: 60},
		&DynamicCodeLoadingPattern{Confidence: 70},
	)

	avg = resolver.GetAverageConfidence()
	expected := 70
	if avg != expected {
		t.Errorf("Expected average %d, got %d", expected, avg)
	}
}

// TestGetPatternsByConfidence tests filtering patterns by confidence threshold.
func TestGetPatternsByConfidence(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	resolver := NewDynamicCodeLoadingResolver(cfg, ssa)

	// Add patterns with different confidence levels
	resolver.Patterns = append(resolver.Patterns,
		&DynamicCodeLoadingPattern{Confidence: 80},
		&DynamicCodeLoadingPattern{Confidence: 60},
		&DynamicCodeLoadingPattern{Confidence: 75},
		&DynamicCodeLoadingPattern{Confidence: 40},
	)

	// Get patterns with confidence >= 70
	highConf := resolver.GetPatternsByConfidence(70)
	if len(highConf) != 2 {
		t.Errorf("Expected 2 patterns with confidence >= 70, got %d", len(highConf))
	}

	// Get patterns with confidence >= 50
	mediumConf := resolver.GetPatternsByConfidence(50)
	if len(mediumConf) != 3 {
		t.Errorf("Expected 3 patterns with confidence >= 50, got %d", len(mediumConf))
	}
}

// TestGetTrace tests trace retrieval.
func TestGetTrace(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	resolver := NewDynamicCodeLoadingResolver(cfg, ssa)

	// Add some trace entries
	resolver.Trace = append(resolver.Trace, "Trace entry 1")
	resolver.Trace = append(resolver.Trace, "Trace entry 2")

	trace := resolver.GetTrace()
	if len(trace) != 2 {
		t.Errorf("Expected 2 trace entries, got %d", len(trace))
	}
}

// TestGetChangeCount tests change count retrieval.
func TestGetChangeCount(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	resolver := NewDynamicCodeLoadingResolver(cfg, ssa)

	if resolver.GetChangeCount() != 0 {
		t.Error("Expected 0 changes initially")
	}

	resolver.Changes = 5
	if resolver.GetChangeCount() != 5 {
		t.Error("Expected 5 changes after update")
	}
}

// TestGenerateReport tests report generation.
func TestGenerateReport(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	resolver := NewDynamicCodeLoadingResolver(cfg, ssa)

	// Add some patterns
	block := &BasicBlock{ID: 0}
	resolver.Patterns = append(resolver.Patterns,
		&DynamicCodeLoadingPattern{
			Type:              DynamicLoadingClassForName,
			Location:          block,
			InsnIndex:         0,
			Confidence:        80,
			IsResolvable:      true,
			ClassName:         "com.example.MyClass",
			PartialResolution: "Class.forName resolved to: com.example.MyClass",
		},
		&DynamicCodeLoadingPattern{
			Type:              DynamicLoadingGetMethod,
			Location:          block,
			InsnIndex:         1,
			Confidence:        70,
			IsResolvable:      false,
			PartialResolution: "getMethod pattern detected",
		},
	)
	resolver.ResolvableCount = 1
	resolver.UnresolvableCount = 1

	report := resolver.GenerateReport()

	// Verify report contains expected sections
	if !strings.Contains(report, "DYNAMIC CODE LOADING ANALYSIS REPORT") {
		t.Error("Report should contain title")
	}
	if !strings.Contains(report, "Total Patterns Detected: 2") {
		t.Error("Report should contain pattern count")
	}
	if !strings.Contains(report, "Resolvable Patterns: 1") {
		t.Error("Report should contain resolvable count")
	}
	if !strings.Contains(report, "Unresolvable Patterns: 1") {
		t.Error("Report should contain unresolvable count")
	}
	if !strings.Contains(report, "Patterns by Type:") {
		t.Error("Report should contain patterns by type section")
	}
	if !strings.Contains(report, "High-Confidence Patterns") {
		t.Error("Report should contain high-confidence section")
	}
	if !strings.Contains(report, "Resolvable Patterns:") {
		t.Error("Report should contain resolvable patterns section")
	}
}

// TestAnalyzeDexClassLoaderPattern tests DexClassLoader pattern analysis.
func TestAnalyzeDexClassLoaderPattern(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	resolver := NewDynamicCodeLoadingResolver(cfg, ssa)

	block := &BasicBlock{
		ID:          0,
		IsReachable: true,
		Insns: []MIRInsn{
			{Kind: MIR_NEW_INSTANCE, Offset: 0},
		},
	}

	pattern := resolver.analyzeDexClassLoaderPattern(block, 0, &block.Insns[0])

	if pattern.Type != DynamicLoadingDexClassLoader {
		t.Error("Expected DexClassLoader pattern type")
	}
	if pattern.Location != block {
		t.Error("Expected pattern location to be set")
	}
	if pattern.InsnIndex != 0 {
		t.Error("Expected instruction index to be 0")
	}
	if pattern.Confidence == 0 {
		t.Error("Expected non-zero confidence")
	}
}

// TestAnalyzePathClassLoaderPattern tests PathClassLoader pattern analysis.
func TestAnalyzePathClassLoaderPattern(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	resolver := NewDynamicCodeLoadingResolver(cfg, ssa)

	block := &BasicBlock{
		ID:          0,
		IsReachable: true,
		Insns: []MIRInsn{
			{Kind: MIR_NEW_INSTANCE, Offset: 0},
		},
	}

	pattern := resolver.analyzePathClassLoaderPattern(block, 0, &block.Insns[0])

	if pattern.Type != DynamicLoadingPathClassLoader {
		t.Error("Expected PathClassLoader pattern type")
	}
	if pattern.Confidence == 0 {
		t.Error("Expected non-zero confidence")
	}
}

// TestAnalyzeClassForNamePattern tests Class.forName pattern analysis.
func TestAnalyzeClassForNamePattern(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	resolver := NewDynamicCodeLoadingResolver(cfg, ssa)

	block := &BasicBlock{
		ID:          0,
		IsReachable: true,
		Insns: []MIRInsn{
			{Kind: MIR_INVOKE, Offset: 0},
		},
	}

	pattern := resolver.analyzeClassForNamePattern(block, 0, &block.Insns[0])

	if pattern.Type != DynamicLoadingClassForName {
		t.Error("Expected Class.forName pattern type")
	}
	if pattern.Confidence == 0 {
		t.Error("Expected non-zero confidence")
	}
}

// TestAnalyzeGetMethodPattern tests getMethod pattern analysis.
func TestAnalyzeGetMethodPattern(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	resolver := NewDynamicCodeLoadingResolver(cfg, ssa)

	block := &BasicBlock{
		ID:          0,
		IsReachable: true,
		Insns: []MIRInsn{
			{Kind: MIR_INVOKE, Offset: 0},
		},
	}

	pattern := resolver.analyzeGetMethodPattern(block, 0, &block.Insns[0])

	if pattern.Type != DynamicLoadingGetMethod {
		t.Error("Expected getMethod pattern type")
	}
	if pattern.Confidence == 0 {
		t.Error("Expected non-zero confidence")
	}
}

// TestAnalyzeInvokePattern tests invoke pattern analysis.
func TestAnalyzeInvokePattern(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	resolver := NewDynamicCodeLoadingResolver(cfg, ssa)

	block := &BasicBlock{
		ID:          0,
		IsReachable: true,
		Insns: []MIRInsn{
			{Kind: MIR_INVOKE, Offset: 0},
		},
	}

	pattern := resolver.analyzeInvokePattern(block, 0, &block.Insns[0])

	if pattern.Type != DynamicLoadingInvoke {
		t.Error("Expected invoke pattern type")
	}
	if pattern.Confidence == 0 {
		t.Error("Expected non-zero confidence")
	}
}

// TestAnalyzeBytecodeInjectionPattern tests bytecode injection pattern analysis.
func TestAnalyzeBytecodeInjectionPattern(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	resolver := NewDynamicCodeLoadingResolver(cfg, ssa)

	block := &BasicBlock{
		ID:          0,
		IsReachable: true,
		Insns: []MIRInsn{
			{Kind: MIR_INVOKE, Offset: 0},
		},
	}

	pattern := resolver.analyzeBytecodeInjectionPattern(block, 0, &block.Insns[0])

	if pattern.Type != DynamicLoadingBytecodeInjection {
		t.Error("Expected bytecode injection pattern type")
	}
	if pattern.Confidence == 0 {
		t.Error("Expected non-zero confidence")
	}
}

// TestReflectionChainDetection tests detection of reflection chains.
func TestReflectionChainDetection(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	resolver := NewDynamicCodeLoadingResolver(cfg, ssa)

	block := &BasicBlock{ID: 0}

	// Add multiple patterns in the same block
	resolver.Patterns = append(resolver.Patterns,
		&DynamicCodeLoadingPattern{
			Type:       DynamicLoadingClassForName,
			Location:   block,
			Confidence: 80,
		},
		&DynamicCodeLoadingPattern{
			Type:       DynamicLoadingGetMethod,
			Location:   block,
			Confidence: 75,
		},
	)

	initialCount := len(resolver.Patterns)
	resolver.analyzeReflectionChains()

	// Should have added a reflection chain pattern
	if len(resolver.Patterns) <= initialCount {
		t.Error("Expected reflection chain pattern to be added")
	}

	// Find the chain pattern
	var chainPattern *DynamicCodeLoadingPattern
	for _, p := range resolver.Patterns {
		if p.Type == DynamicLoadingReflectionChain {
			chainPattern = p
			break
		}
	}

	if chainPattern == nil {
		t.Error("Expected to find reflection chain pattern")
	} else if chainPattern.Location != block {
		t.Error("Expected chain pattern to be in the same block")
	}
}

// TestEdgeCases tests edge cases and boundary conditions.
func TestEdgeCases(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	resolver := NewDynamicCodeLoadingResolver(cfg, ssa)

	// Test with nil CFG
	resolver.CFG = nil
	resolver.DetectDynamicCodeLoading()
	if len(resolver.Patterns) != 0 {
		t.Error("Expected no patterns with nil CFG")
	}

	// Test with nil SSA
	resolver.CFG = cfg
	resolver.SSA = nil
	resolver.DetectDynamicCodeLoading()
	if len(resolver.Patterns) != 0 {
		t.Error("Expected no patterns with nil SSA")
	}

	// Test with empty patterns
	resolver.SSA = ssa
	if resolver.GetAverageConfidence() != 0 {
		t.Error("Expected 0 average confidence with no patterns")
	}
	if resolver.GetResolutionRate() != 0.0 {
		t.Error("Expected 0.0 resolution rate with no patterns")
	}
}

// TestPatternMetadata tests pattern metadata fields.
func TestPatternMetadata(t *testing.T) {
	pattern := &DynamicCodeLoadingPattern{
		Type:              DynamicLoadingClassForName,
		ClassName:         "com.example.MyClass",
		MethodName:        "myMethod",
		DexPath:           "/data/app/myapp.dex",
		Confidence:        85,
		IsResolvable:      true,
		PartialResolution: "Resolved to com.example.MyClass",
		Rationale:         "Class.forName with constant string argument",
	}

	if pattern.Type != DynamicLoadingClassForName {
		t.Error("Expected correct pattern type")
	}
	if pattern.ClassName != "com.example.MyClass" {
		t.Error("Expected correct class name")
	}
	if pattern.MethodName != "myMethod" {
		t.Error("Expected correct method name")
	}
	if pattern.DexPath != "/data/app/myapp.dex" {
		t.Error("Expected correct DEX path")
	}
	if pattern.Confidence != 85 {
		t.Error("Expected correct confidence")
	}
	if !pattern.IsResolvable {
		t.Error("Expected pattern to be resolvable")
	}
	if pattern.PartialResolution != "Resolved to com.example.MyClass" {
		t.Error("Expected correct partial resolution")
	}
	if pattern.Rationale != "Class.forName with constant string argument" {
		t.Error("Expected correct rationale")
	}
}

// TestResolveClassForName tests Class.forName resolution.
func TestResolveClassForName(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	resolver := NewDynamicCodeLoadingResolver(cfg, ssa)

	pattern := &DynamicCodeLoadingPattern{
		Type:         DynamicLoadingClassForName,
		ClassName:    "com.example.MyClass",
		IsResolvable: true,
	}

	resolver.resolveClassForName(pattern)

	if !strings.Contains(pattern.PartialResolution, "com.example.MyClass") {
		t.Error("Expected class name in partial resolution")
	}
}

// TestResolveGetMethod tests getMethod resolution.
func TestResolveGetMethod(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	resolver := NewDynamicCodeLoadingResolver(cfg, ssa)

	pattern := &DynamicCodeLoadingPattern{
		Type:         DynamicLoadingGetMethod,
		ClassName:    "com.example.MyClass",
		MethodName:   "myMethod",
		IsResolvable: true,
	}

	resolver.resolveGetMethod(pattern)

	if !strings.Contains(pattern.PartialResolution, "com.example.MyClass") {
		t.Error("Expected class name in partial resolution")
	}
	if !strings.Contains(pattern.PartialResolution, "myMethod") {
		t.Error("Expected method name in partial resolution")
	}
}

// TestResolveGetDeclaredMethod tests getDeclaredMethod resolution.
func TestResolveGetDeclaredMethod(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	resolver := NewDynamicCodeLoadingResolver(cfg, ssa)

	pattern := &DynamicCodeLoadingPattern{
		Type:         DynamicLoadingGetDeclaredMethod,
		ClassName:    "com.example.MyClass",
		MethodName:   "myMethod",
		IsResolvable: true,
	}

	resolver.resolveGetDeclaredMethod(pattern)

	if !strings.Contains(pattern.PartialResolution, "com.example.MyClass") {
		t.Error("Expected class name in partial resolution")
	}
	if !strings.Contains(pattern.PartialResolution, "myMethod") {
		t.Error("Expected method name in partial resolution")
	}
}

// TestIsDexClassLoaderPattern tests DexClassLoader pattern detection.
func TestIsDexClassLoaderPattern(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	resolver := NewDynamicCodeLoadingResolver(cfg, ssa)

	// Test with invoke-direct (constructor call) with Imm > 0
	insn := &MIRInsn{
		Kind:       MIR_INVOKE,
		InvokeKind: InvokeDirect,
		Imm:        1,
	}

	if !resolver.isDexClassLoaderPattern(insn) {
		t.Error("Expected DexClassLoader pattern to be detected with Imm > 0")
	}

	// Test with invoke-direct with RefIdx > 0
	insnWithRef := &MIRInsn{
		Kind:       MIR_INVOKE,
		InvokeKind: InvokeDirect,
		RefIdx:     1,
	}

	if !resolver.isDexClassLoaderPattern(insnWithRef) {
		t.Error("Expected DexClassLoader pattern to be detected with RefIdx > 0")
	}

	// Test with invoke-direct but both Imm and RefIdx == 0
	insnNoImm := &MIRInsn{
		Kind:       MIR_INVOKE,
		InvokeKind: InvokeDirect,
		Imm:        0,
		RefIdx:     0,
	}

	if resolver.isDexClassLoaderPattern(insnNoImm) {
		t.Error("Expected pattern with Imm=0 and RefIdx=0 to not match")
	}

	// Test with non-invoke instruction
	nonInvokeInsn := &MIRInsn{
		Kind: MIR_CONST,
	}

	if resolver.isDexClassLoaderPattern(nonInvokeInsn) {
		t.Error("Expected non-invoke instruction to not match")
	}

	// Test with nil instruction
	if resolver.isDexClassLoaderPattern(nil) {
		t.Error("Expected nil instruction to not match")
	}
}

// TestIsPathClassLoaderPattern tests PathClassLoader pattern detection.
func TestIsPathClassLoaderPattern(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	resolver := NewDynamicCodeLoadingResolver(cfg, ssa)

	// Test with invoke-direct (constructor call)
	insn := &MIRInsn{
		Kind:       MIR_INVOKE,
		InvokeKind: InvokeDirect,
		Imm:        1,
	}

	if !resolver.isPathClassLoaderPattern(insn) {
		t.Error("Expected PathClassLoader pattern to be detected")
	}

	// Test with non-invoke instruction
	nonInvokeInsn := &MIRInsn{
		Kind: MIR_CONST,
	}

	if resolver.isPathClassLoaderPattern(nonInvokeInsn) {
		t.Error("Expected non-invoke instruction to not match")
	}
}

// TestIsClassForNamePattern tests Class.forName pattern detection.
func TestIsClassForNamePattern(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	resolver := NewDynamicCodeLoadingResolver(cfg, ssa)

	// Test with invoke-static (Class.forName is static)
	insn := &MIRInsn{
		Kind:       MIR_INVOKE,
		InvokeKind: InvokeStatic,
	}

	if !resolver.isClassForNamePattern(insn) {
		t.Error("Expected Class.forName pattern to be detected")
	}

	// Test with non-static invoke
	nonStaticInsn := &MIRInsn{
		Kind:       MIR_INVOKE,
		InvokeKind: InvokeVirtual,
	}

	if resolver.isClassForNamePattern(nonStaticInsn) {
		t.Error("Expected non-static invoke to not match")
	}
}

// TestIsGetMethodPattern tests getMethod pattern detection.
func TestIsGetMethodPattern(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	resolver := NewDynamicCodeLoadingResolver(cfg, ssa)

	// Test with invoke-virtual (getMethod is virtual)
	insn := &MIRInsn{
		Kind:       MIR_INVOKE,
		InvokeKind: InvokeVirtual,
	}

	if !resolver.isGetMethodPattern(insn) {
		t.Error("Expected getMethod pattern to be detected")
	}

	// Test with non-virtual invoke
	nonVirtualInsn := &MIRInsn{
		Kind:       MIR_INVOKE,
		InvokeKind: InvokeStatic,
	}

	if resolver.isGetMethodPattern(nonVirtualInsn) {
		t.Error("Expected non-virtual invoke to not match")
	}
}

// TestIsInvokePattern tests invoke pattern detection.
func TestIsInvokePattern(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	resolver := NewDynamicCodeLoadingResolver(cfg, ssa)

	// Test with invoke-virtual (Method.invoke is virtual)
	insn := &MIRInsn{
		Kind:       MIR_INVOKE,
		InvokeKind: InvokeVirtual,
	}

	if !resolver.isInvokePattern(insn) {
		t.Error("Expected invoke pattern to be detected")
	}

	// Test with non-invoke instruction
	nonInvokeInsn := &MIRInsn{
		Kind: MIR_CONST,
	}

	if resolver.isInvokePattern(nonInvokeInsn) {
		t.Error("Expected non-invoke instruction to not match")
	}
}

// TestIsBytecodeInjectionPattern tests bytecode injection pattern detection.
func TestIsBytecodeInjectionPattern(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	resolver := NewDynamicCodeLoadingResolver(cfg, ssa)

	// Test with invoke-virtual
	insn := &MIRInsn{
		Kind:       MIR_INVOKE,
		InvokeKind: InvokeVirtual,
	}

	if !resolver.isBytecodeInjectionPattern(insn) {
		t.Error("Expected bytecode injection pattern to be detected")
	}

	// Test with invoke-static
	staticInsn := &MIRInsn{
		Kind:       MIR_INVOKE,
		InvokeKind: InvokeStatic,
	}

	if !resolver.isBytecodeInjectionPattern(staticInsn) {
		t.Error("Expected bytecode injection pattern to be detected for static invoke")
	}

	// Test with non-invoke instruction
	nonInvokeInsn := &MIRInsn{
		Kind: MIR_CONST,
	}

	if resolver.isBytecodeInjectionPattern(nonInvokeInsn) {
		t.Error("Expected non-invoke instruction to not match")
	}
}

// TestExtractDexPath tests DEX path extraction.
func TestExtractDexPath(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	resolver := NewDynamicCodeLoadingResolver(cfg, ssa)

	// Test with block containing const instructions
	block := &BasicBlock{
		ID:          0,
		IsReachable: true,
		Insns: []MIRInsn{
			{Kind: MIR_CONST, Imm: 1},
			{Kind: MIR_CONST, Imm: 2},
			{Kind: MIR_INVOKE, Imm: 3},
		},
	}

	path := resolver.extractDexPath(block, 2)
	if path == "" {
		t.Error("Expected DEX path to be extracted")
	}

	// Test with nil block
	nilPath := resolver.extractDexPath(nil, 0)
	if nilPath != "" {
		t.Error("Expected empty path for nil block")
	}

	// Test with invalid index
	invalidPath := resolver.extractDexPath(block, 10)
	if invalidPath != "" {
		t.Error("Expected empty path for invalid index")
	}
}

// TestExtractClassPath tests class path extraction.
func TestExtractClassPath(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	resolver := NewDynamicCodeLoadingResolver(cfg, ssa)

	// Test with block containing const instructions
	block := &BasicBlock{
		ID:          0,
		IsReachable: true,
		Insns: []MIRInsn{
			{Kind: MIR_CONST, Imm: 1},
			{Kind: MIR_INVOKE, Imm: 2},
		},
	}

	path := resolver.extractClassPath(block, 1)
	if path == "" {
		t.Error("Expected class path to be extracted")
	}

	// Test with nil block
	nilPath := resolver.extractClassPath(nil, 0)
	if nilPath != "" {
		t.Error("Expected empty path for nil block")
	}
}

// TestExtractClassNameFromForName tests class name extraction from Class.forName.
func TestExtractClassNameFromForName(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	resolver := NewDynamicCodeLoadingResolver(cfg, ssa)

	// Test with block containing const instructions
	block := &BasicBlock{
		ID:          0,
		IsReachable: true,
		Insns: []MIRInsn{
			{Kind: MIR_CONST, Imm: 1},
			{Kind: MIR_INVOKE, Imm: 2},
		},
	}

	className := resolver.extractClassNameFromForName(block, 1)
	if className == "" {
		t.Error("Expected class name to be extracted")
	}

	// Test with nil block
	nilClassName := resolver.extractClassNameFromForName(nil, 0)
	if nilClassName != "" {
		t.Error("Expected empty class name for nil block")
	}
}

// TestExtractMethodName tests method name extraction from getMethod.
func TestExtractMethodName(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	resolver := NewDynamicCodeLoadingResolver(cfg, ssa)

	// Test with block containing const instructions
	block := &BasicBlock{
		ID:          0,
		IsReachable: true,
		Insns: []MIRInsn{
			{Kind: MIR_CONST, Imm: 1},
			{Kind: MIR_INVOKE, Imm: 2},
		},
	}

	methodName := resolver.extractMethodName(block, 1)
	if methodName == "" {
		t.Error("Expected method name to be extracted")
	}

	// Test with nil block
	nilMethodName := resolver.extractMethodName(nil, 0)
	if nilMethodName != "" {
		t.Error("Expected empty method name for nil block")
	}
}

// TestResolveDynamicCodeLoading tests the resolution process.
func TestResolveDynamicCodeLoading(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	resolver := NewDynamicCodeLoadingResolver(cfg, ssa)

	// Add resolvable patterns
	resolver.Patterns = append(resolver.Patterns,
		&DynamicCodeLoadingPattern{
			Type:         DynamicLoadingClassForName,
			ClassName:    "com.example.MyClass",
			IsResolvable: true,
		},
		&DynamicCodeLoadingPattern{
			Type:         DynamicLoadingGetMethod,
			ClassName:    "com.example.MyClass",
			MethodName:   "myMethod",
			IsResolvable: true,
		},
		&DynamicCodeLoadingPattern{
			Type:         DynamicLoadingInvoke,
			IsResolvable: false,
		},
	)

	resolver.ResolveDynamicCodeLoading()

	// Check that resolvable patterns were processed
	if !strings.Contains(resolver.Patterns[0].PartialResolution, "com.example.MyClass") {
		t.Error("Expected Class.forName to be resolved")
	}
	if !strings.Contains(resolver.Patterns[1].PartialResolution, "com.example.MyClass") {
		t.Error("Expected getMethod to be resolved")
	}
}

// TestResolvePattern tests individual pattern resolution.
func TestResolvePattern(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	resolver := NewDynamicCodeLoadingResolver(cfg, ssa)

	// Test resolving a Class.forName pattern
	pattern := &DynamicCodeLoadingPattern{
		Type:         DynamicLoadingClassForName,
		ClassName:    "com.example.MyClass",
		IsResolvable: true,
	}

	resolver.resolvePattern(pattern)

	if !strings.Contains(pattern.PartialResolution, "com.example.MyClass") {
		t.Error("Expected pattern to be resolved")
	}
}

// TestDetectDynamicCodeLoading_WithPatterns tests detection with actual patterns.
func TestDetectDynamicCodeLoading_WithPatterns(t *testing.T) {
	block := &BasicBlock{
		ID:          0,
		IsReachable: true,
		Insns: []MIRInsn{
			{Kind: MIR_CONST, Imm: 1},
			{Kind: MIR_INVOKE, InvokeKind: InvokeStatic, Imm: 2},
			{Kind: MIR_INVOKE, InvokeKind: InvokeVirtual, Imm: 3},
		},
	}

	cfg := &CFG{
		Blocks: []*BasicBlock{block},
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	resolver := NewDynamicCodeLoadingResolver(cfg, ssa)
	resolver.DetectDynamicCodeLoading()

	// Should detect at least some patterns
	if len(resolver.Patterns) == 0 {
		t.Error("Expected patterns to be detected")
	}

	// Verify patterns have valid locations (except for reflection chains which may not)
	for _, pattern := range resolver.Patterns {
		if pattern.Type != DynamicLoadingReflectionChain {
			if pattern.Location == nil {
				t.Errorf("Expected pattern of type %s to have a valid location", pattern.Type.String())
			}
		}
	}
}

// TestConfidenceThreshold tests confidence threshold filtering.
func TestConfidenceThreshold(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	resolver := NewDynamicCodeLoadingResolver(cfg, ssa)
	resolver.ConfidenceThreshold = 60

	// Add patterns with different confidence levels
	resolver.Patterns = append(resolver.Patterns,
		&DynamicCodeLoadingPattern{Confidence: 80},
		&DynamicCodeLoadingPattern{Confidence: 50},
		&DynamicCodeLoadingPattern{Confidence: 70},
	)

	// Get patterns above threshold
	highConf := resolver.GetPatternsByConfidence(resolver.ConfidenceThreshold)
	if len(highConf) != 2 {
		t.Errorf("Expected 2 patterns above threshold, got %d", len(highConf))
	}
}

// TestMultipleBlockAnalysis tests analysis across multiple blocks.
func TestMultipleBlockAnalysis(t *testing.T) {
	block1 := &BasicBlock{
		ID:          0,
		IsReachable: true,
		Insns: []MIRInsn{
			{Kind: MIR_INVOKE, InvokeKind: InvokeStatic, Imm: 1},
		},
	}

	block2 := &BasicBlock{
		ID:          1,
		IsReachable: true,
		Insns: []MIRInsn{
			{Kind: MIR_INVOKE, InvokeKind: InvokeVirtual, Imm: 2},
		},
	}

	cfg := &CFG{
		Blocks: []*BasicBlock{block1, block2},
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	resolver := NewDynamicCodeLoadingResolver(cfg, ssa)
	resolver.DetectDynamicCodeLoading()

	// Should detect patterns in both blocks
	if len(resolver.Patterns) == 0 {
		t.Error("Expected patterns to be detected in multiple blocks")
	}
}

// TestReflectionChainAnalysis tests reflection chain detection.
func TestReflectionChainAnalysis(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	resolver := NewDynamicCodeLoadingResolver(cfg, ssa)

	block := &BasicBlock{ID: 0}

	// Add multiple patterns in the same block to form a chain
	resolver.Patterns = append(resolver.Patterns,
		&DynamicCodeLoadingPattern{
			Type:       DynamicLoadingClassForName,
			Location:   block,
			Confidence: 80,
		},
		&DynamicCodeLoadingPattern{
			Type:       DynamicLoadingGetMethod,
			Location:   block,
			Confidence: 75,
		},
		&DynamicCodeLoadingPattern{
			Type:       DynamicLoadingInvoke,
			Location:   block,
			Confidence: 70,
		},
	)

	initialCount := len(resolver.Patterns)
	resolver.analyzeReflectionChains()

	// Should have added a reflection chain pattern
	if len(resolver.Patterns) <= initialCount {
		t.Error("Expected reflection chain pattern to be added")
	}

	// Find the chain pattern
	var chainPattern *DynamicCodeLoadingPattern
	for _, p := range resolver.Patterns {
		if p.Type == DynamicLoadingReflectionChain {
			chainPattern = p
			break
		}
	}

	if chainPattern == nil {
		t.Error("Expected to find reflection chain pattern")
	} else if chainPattern.Confidence == 0 {
		t.Error("Expected chain pattern to have non-zero confidence")
	}
}

// TestStatisticsCalculation tests statistics calculation.
func TestStatisticsCalculation(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	resolver := NewDynamicCodeLoadingResolver(cfg, ssa)

	// Add patterns with various properties
	resolver.Patterns = append(resolver.Patterns,
		&DynamicCodeLoadingPattern{Type: DynamicLoadingClassForName, Confidence: 80, IsResolvable: true},
		&DynamicCodeLoadingPattern{Type: DynamicLoadingGetMethod, Confidence: 70, IsResolvable: true},
		&DynamicCodeLoadingPattern{Type: DynamicLoadingInvoke, Confidence: 50, IsResolvable: false},
		&DynamicCodeLoadingPattern{Type: DynamicLoadingClassForName, Confidence: 60, IsResolvable: false},
	)
	resolver.ResolvableCount = 2
	resolver.UnresolvableCount = 2

	// Test statistics
	total, resolvable, unresolvable := resolver.GetResolutionStats()
	if total != 4 {
		t.Errorf("Expected total 4, got %d", total)
	}
	if resolvable != 2 {
		t.Errorf("Expected resolvable 2, got %d", resolvable)
	}
	if unresolvable != 2 {
		t.Errorf("Expected unresolvable 2, got %d", unresolvable)
	}

	// Test resolution rate
	rate := resolver.GetResolutionRate()
	expected := 50.0
	if rate != expected {
		t.Errorf("Expected %.1f%% rate, got %.1f%%", expected, rate)
	}

	// Test average confidence
	avg := resolver.GetAverageConfidence()
	expectedAvg := 65 // (80 + 70 + 50 + 60) / 4
	if avg != expectedAvg {
		t.Errorf("Expected average %d, got %d", expectedAvg, avg)
	}
}

// TestReportGeneration tests comprehensive report generation.
func TestReportGeneration(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	resolver := NewDynamicCodeLoadingResolver(cfg, ssa)

	block := &BasicBlock{ID: 0}

	// Add various patterns
	resolver.Patterns = append(resolver.Patterns,
		&DynamicCodeLoadingPattern{
			Type:              DynamicLoadingClassForName,
			Location:          block,
			InsnIndex:         0,
			Confidence:        85,
			IsResolvable:      true,
			ClassName:         "com.example.MyClass",
			PartialResolution: "Class.forName resolved to: com.example.MyClass",
		},
		&DynamicCodeLoadingPattern{
			Type:              DynamicLoadingGetMethod,
			Location:          block,
			InsnIndex:         1,
			Confidence:        75,
			IsResolvable:      true,
			MethodName:        "myMethod",
			PartialResolution: "getMethod resolved to: myMethod",
		},
		&DynamicCodeLoadingPattern{
			Type:              DynamicLoadingInvoke,
			Location:          block,
			InsnIndex:         2,
			Confidence:        50,
			IsResolvable:      false,
			PartialResolution: "Method.invoke call detected",
		},
	)
	resolver.ResolvableCount = 2
	resolver.UnresolvableCount = 1

	report := resolver.GenerateReport()

	// Verify report contains all expected sections
	if !strings.Contains(report, "DYNAMIC CODE LOADING ANALYSIS REPORT") {
		t.Error("Report should contain title")
	}
	if !strings.Contains(report, "Total Patterns Detected: 3") {
		t.Error("Report should contain correct pattern count")
	}
	if !strings.Contains(report, "Resolvable Patterns: 2") {
		t.Error("Report should contain correct resolvable count")
	}
	if !strings.Contains(report, "Unresolvable Patterns: 1") {
		t.Error("Report should contain correct unresolvable count")
	}
	if !strings.Contains(report, "Patterns by Type:") {
		t.Error("Report should contain patterns by type section")
	}
	if !strings.Contains(report, "High-Confidence Patterns") {
		t.Error("Report should contain high-confidence section")
	}
	if !strings.Contains(report, "Resolvable Patterns:") {
		t.Error("Report should contain resolvable patterns section")
	}
	if !strings.Contains(report, "com.example.MyClass") {
		t.Error("Report should contain resolved class name")
	}
	if !strings.Contains(report, "myMethod") {
		t.Error("Report should contain resolved method name")
	}
}
