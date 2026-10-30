package apkloader

import (
	"strings"
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// UNIT TESTS: Virtualization Detection
// ═══════════════════════════════════════════════════════════════════════════════

// TestNewVirtualizationDetector tests detector initialization.
func TestNewVirtualizationDetector(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	detector := NewVirtualizationDetector(cfg, ssa)

	if detector == nil {
		t.Fatal("Expected detector to be created, got nil")
	}
	if detector.CFG != cfg {
		t.Error("Expected CFG to be set")
	}
	if detector.SSA != ssa {
		t.Error("Expected SSA to be set")
	}
	if len(detector.Patterns) != 0 {
		t.Error("Expected empty patterns initially")
	}
	if len(detector.Trace) != 0 {
		t.Error("Expected empty trace initially")
	}
	if detector.Changes != 0 {
		t.Error("Expected zero changes initially")
	}
	if detector.ConfidenceThreshold != 50 {
		t.Error("Expected default confidence threshold of 50")
	}
}

// TestDetectVirtualization_EmptyCFG tests detection on empty CFG.
func TestDetectVirtualization_EmptyCFG(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	detector := NewVirtualizationDetector(cfg, ssa)
	detector.DetectVirtualization()

	if len(detector.Patterns) != 0 {
		t.Error("Expected no patterns on empty CFG")
	}
	if detector.Changes != 0 {
		t.Error("Expected no changes on empty CFG")
	}
	if len(detector.Trace) == 0 {
		t.Error("Expected trace to be recorded")
	}
}

// TestVirtualizationTechnique_String tests the string representation of techniques.
func TestVirtualizationTechnique_String(t *testing.T) {
	tests := []struct {
		technique VirtualizationTechnique
		expected  string
	}{
		{VirtualizationDispatcher, "Dispatcher"},
		{VirtualizationInterpreter, "Interpreter"},
		{VirtualizationJIT, "JIT"},
		{VirtualizationObfuscatedBytecode, "ObfuscatedBytecode"},
		{VirtualizationCustomVM, "CustomVM"},
		{VirtualizationUnknown, "Unknown"},
	}

	for _, test := range tests {
		result := test.technique.String()
		if result != test.expected {
			t.Errorf("Expected %s, got %s", test.expected, result)
		}
	}
}

// TestDetectDispatcherPatterns tests dispatcher pattern detection.
func TestDetectDispatcherPatterns(t *testing.T) {
	// Create a block with switch-like structure (many successors)
	block := &BasicBlock{
		ID:    0,
		Start: 0,
		End:   10,
		Insns: []MIRInsn{
			{Kind: MIR_CONST, Offset: 0, Dst: 0},
			{Kind: MIR_SWITCH, Offset: 2},
		},
		Succs: make([]*BasicBlock, 6),
	}

	// Create successor blocks
	for i := 0; i < 6; i++ {
		block.Succs[i] = &BasicBlock{
			ID:    i + 1,
			Start: 10 + i*5,
			End:   15 + i*5,
			Insns: []MIRInsn{
				{Kind: MIR_CONST, Offset: uint32(10 + i*5), Dst: 0},
			},
		}
	}

	cfg := &CFG{
		Blocks: []*BasicBlock{block},
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	detector := NewVirtualizationDetector(cfg, ssa)
	detector.DetectVirtualization()

	if len(detector.Patterns) == 0 {
		t.Error("Expected dispatcher patterns to be detected")
	}

	for _, pattern := range detector.Patterns {
		if pattern.Technique != VirtualizationDispatcher {
			t.Errorf("Expected dispatcher technique, got %v", pattern.Technique)
		}
	}
}

// TestDetectTableDispatcher tests table-based dispatcher detection.
func TestDetectTableDispatcher(t *testing.T) {
	// Create a block with array access (table dispatch)
	block := &BasicBlock{
		ID:    0,
		Start: 0,
		End:   10,
		Insns: []MIRInsn{
			{Kind: MIR_ARRAY_GET, Offset: 0, Dst: 0},
			{Kind: MIR_GOTO, Offset: 2},
		},
	}

	cfg := &CFG{
		Blocks: []*BasicBlock{block},
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	detector := NewVirtualizationDetector(cfg, ssa)
	detector.DetectVirtualization()

	if len(detector.Patterns) == 0 {
		t.Error("Expected table dispatcher patterns to be detected")
	}

	for _, pattern := range detector.Patterns {
		if pattern.DispatcherType != "table" {
			t.Errorf("Expected table dispatcher type, got %s", pattern.DispatcherType)
		}
	}
}

// TestDetectComputedGotoDispatcher tests computed goto dispatcher detection.
func TestDetectComputedGotoDispatcher(t *testing.T) {
	// Create a block with arithmetic operations followed by goto
	block := &BasicBlock{
		ID:    0,
		Start: 0,
		End:   10,
		Insns: []MIRInsn{
			{Kind: MIR_ADD, Offset: 0, Dst: 0},
			{Kind: MIR_GOTO, Offset: 2},
		},
	}

	cfg := &CFG{
		Blocks: []*BasicBlock{block},
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	detector := NewVirtualizationDetector(cfg, ssa)
	detector.DetectVirtualization()

	if len(detector.Patterns) == 0 {
		t.Error("Expected computed goto dispatcher patterns to be detected")
	}

	for _, pattern := range detector.Patterns {
		if pattern.DispatcherType != "computed_goto" {
			t.Errorf("Expected computed_goto dispatcher type, got %s", pattern.DispatcherType)
		}
	}
}

// TestDetectInterpreterLoop tests interpreter loop detection.
func TestDetectInterpreterLoop(t *testing.T) {
	// Create a block with state machine pattern (field get/put)
	block := &BasicBlock{
		ID:    0,
		Start: 0,
		End:   10,
		Insns: []MIRInsn{
			{Kind: MIR_FIELD_GET, Offset: 0, Dst: 0},
			{Kind: MIR_FIELD_GET, Offset: 2, Dst: 1},
			{Kind: MIR_FIELD_PUT, Offset: 4, Src1: 0},
		},
		Succs: []*BasicBlock{},
	}

	// Create a back edge to simulate loop
	block.Succs = append(block.Succs, block)

	cfg := &CFG{
		Blocks: []*BasicBlock{block},
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	detector := NewVirtualizationDetector(cfg, ssa)
	detector.DetectVirtualization()

	if len(detector.Patterns) == 0 {
		t.Error("Expected interpreter loop patterns to be detected")
	}

	for _, pattern := range detector.Patterns {
		if pattern.Technique != VirtualizationInterpreter {
			t.Errorf("Expected interpreter technique, got %v", pattern.Technique)
		}
	}
}

// TestDetectObfuscatedBytecode tests obfuscated bytecode detection.
func TestDetectObfuscatedBytecode(t *testing.T) {
	// Create a block with many arithmetic operations
	block := &BasicBlock{
		ID:    0,
		Start: 0,
		End:   10,
		Insns: []MIRInsn{
			{Kind: MIR_ADD, Offset: 0, Dst: 0},
			{Kind: MIR_XOR, Offset: 2, Dst: 1},
			{Kind: MIR_MUL, Offset: 4, Dst: 2},
		},
	}

	cfg := &CFG{
		Blocks: []*BasicBlock{block},
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	detector := NewVirtualizationDetector(cfg, ssa)
	detector.DetectVirtualization()

	if len(detector.Patterns) == 0 {
		t.Error("Expected obfuscated bytecode patterns to be detected")
	}

	for _, pattern := range detector.Patterns {
		if pattern.Technique != VirtualizationObfuscatedBytecode {
			t.Errorf("Expected obfuscated bytecode technique, got %v", pattern.Technique)
		}
	}
}

// TestDetectCustomVM tests custom VM detection.
func TestDetectCustomVM(t *testing.T) {
	// Create a block with initialization operations
	block := &BasicBlock{
		ID:    0,
		Start: 0,
		End:   10,
		Insns: []MIRInsn{
			{Kind: MIR_CONST, Offset: 0, Dst: 0},
			{Kind: MIR_NEW_ARRAY, Offset: 2, Dst: 1},
		},
	}

	cfg := &CFG{
		Blocks: []*BasicBlock{block},
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	detector := NewVirtualizationDetector(cfg, ssa)
	detector.DetectVirtualization()

	if len(detector.Patterns) == 0 {
		t.Error("Expected custom VM patterns to be detected")
	}

	for _, pattern := range detector.Patterns {
		if pattern.Technique != VirtualizationCustomVM {
			t.Errorf("Expected custom VM technique, got %v", pattern.Technique)
		}
	}
}

// TestGetPatternsByTechnique tests filtering patterns by technique.
func TestGetPatternsByTechnique(t *testing.T) {
	// Create blocks with different virtualization techniques
	dispatcherBlock := &BasicBlock{
		ID:    0,
		Start: 0,
		End:   10,
		Insns: []MIRInsn{
			{Kind: MIR_SWITCH, Offset: 0},
		},
		Succs: make([]*BasicBlock, 6),
	}

	for i := 0; i < 6; i++ {
		dispatcherBlock.Succs[i] = &BasicBlock{
			ID:    i + 1,
			Start: 10 + i*5,
			End:   15 + i*5,
			Insns: []MIRInsn{
				{Kind: MIR_CONST, Offset: uint32(10 + i*5), Dst: 0},
			},
		}
	}

	interpreterBlock := &BasicBlock{
		ID:    10,
		Start: 50,
		End:   60,
		Insns: []MIRInsn{
			{Kind: MIR_FIELD_GET, Offset: 50, Dst: 0},
			{Kind: MIR_FIELD_GET, Offset: 52, Dst: 1},
			{Kind: MIR_FIELD_PUT, Offset: 54, Src1: 0},
		},
		Succs: []*BasicBlock{},
	}
	interpreterBlock.Succs = append(interpreterBlock.Succs, interpreterBlock)

	cfg := &CFG{
		Blocks: []*BasicBlock{dispatcherBlock, interpreterBlock},
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	detector := NewVirtualizationDetector(cfg, ssa)
	detector.DetectVirtualization()

	dispatcherPatterns := detector.GetPatternsByTechnique(VirtualizationDispatcher)
	interpreterPatterns := detector.GetPatternsByTechnique(VirtualizationInterpreter)

	if len(dispatcherPatterns) == 0 {
		t.Error("Expected dispatcher patterns")
	}
	if len(interpreterPatterns) == 0 {
		t.Error("Expected interpreter patterns")
	}

	for _, pattern := range dispatcherPatterns {
		if pattern.Technique != VirtualizationDispatcher {
			t.Error("Expected all patterns to be dispatcher type")
		}
	}

	for _, pattern := range interpreterPatterns {
		if pattern.Technique != VirtualizationInterpreter {
			t.Error("Expected all patterns to be interpreter type")
		}
	}
}

// TestGetDetectionStats tests detection statistics.
func TestGetDetectionStats(t *testing.T) {
	// Create blocks with different techniques
	dispatcherBlock := &BasicBlock{
		ID:    0,
		Start: 0,
		End:   10,
		Insns: []MIRInsn{
			{Kind: MIR_SWITCH, Offset: 0},
		},
		Succs: make([]*BasicBlock, 6),
	}

	for i := 0; i < 6; i++ {
		dispatcherBlock.Succs[i] = &BasicBlock{
			ID:    i + 1,
			Start: 10 + i*5,
			End:   15 + i*5,
			Insns: []MIRInsn{
				{Kind: MIR_CONST, Offset: uint32(10 + i*5), Dst: 0},
			},
		}
	}

	cfg := &CFG{
		Blocks: []*BasicBlock{dispatcherBlock},
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	detector := NewVirtualizationDetector(cfg, ssa)
	detector.DetectVirtualization()

	total, dispatcher, interpreter, jit, obfuscated, customVM := detector.GetDetectionStats()

	if total == 0 {
		t.Error("Expected total patterns to be greater than 0")
	}
	if dispatcher == 0 {
		t.Error("Expected dispatcher count to be greater than 0")
	}
	if total != dispatcher+interpreter+jit+obfuscated+customVM {
		t.Error("Expected total to equal sum of all techniques")
	}
}

// TestExtractBytecode tests bytecode extraction.
func TestExtractBytecode(t *testing.T) {
	block := &BasicBlock{
		ID:    0,
		Start: 0,
		End:   10,
		Insns: []MIRInsn{
			{Kind: MIR_CONST, Offset: 0, Dst: 0},
			{Kind: MIR_ADD, Offset: 2, Dst: 1},
		},
	}

	pattern := &VirtualizationPattern{
		Technique:             VirtualizationDispatcher,
		Location:              block,
		VirtualOpcodes:        make([]uint32, 0),
		AnnotatedInstructions: make([]string, 0),
	}

	cfg := &CFG{
		Blocks: []*BasicBlock{block},
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	detector := NewVirtualizationDetector(cfg, ssa)
	bytecode := detector.ExtractBytecode(pattern)

	if bytecode == nil {
		t.Error("Expected bytecode to be extracted")
	}
	if len(bytecode) == 0 {
		t.Error("Expected bytecode to have content")
	}
	if pattern.ExtractedBytecode == nil {
		t.Error("Expected pattern to have extracted bytecode")
	}
}

// TestAnnotateVirtualization tests virtualization annotation.
func TestAnnotateVirtualization(t *testing.T) {
	block := &BasicBlock{
		ID:    0,
		Start: 0,
		End:   10,
		Insns: []MIRInsn{
			{Kind: MIR_SWITCH, Offset: 0},
		},
		Succs: make([]*BasicBlock, 6),
	}

	for i := 0; i < 6; i++ {
		block.Succs[i] = &BasicBlock{
			ID:    i + 1,
			Start: 10 + i*5,
			End:   15 + i*5,
			Insns: []MIRInsn{
				{Kind: MIR_CONST, Offset: uint32(10 + i*5), Dst: 0},
			},
		}
	}

	cfg := &CFG{
		Blocks: []*BasicBlock{block},
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	detector := NewVirtualizationDetector(cfg, ssa)
	detector.DetectVirtualization()

	annotations := detector.AnnotateVirtualization()

	if len(annotations) == 0 {
		t.Error("Expected annotations to be generated")
	}

	for _, annotation := range annotations {
		if !strings.Contains(annotation, "virtualization detected") {
			t.Error("Expected annotation to contain 'virtualization detected'")
		}
		if !strings.Contains(annotation, "confidence") {
			t.Error("Expected annotation to contain 'confidence'")
		}
	}
}

// TestGenerateReportVirt tests report generation.
func TestGenerateReportVirt(t *testing.T) {
	block := &BasicBlock{
		ID:    0,
		Start: 0,
		End:   10,
		Insns: []MIRInsn{
			{Kind: MIR_SWITCH, Offset: 0},
		},
		Succs: make([]*BasicBlock, 6),
	}

	for i := 0; i < 6; i++ {
		block.Succs[i] = &BasicBlock{
			ID:    i + 1,
			Start: 10 + i*5,
			End:   15 + i*5,
			Insns: []MIRInsn{
				{Kind: MIR_CONST, Offset: uint32(10 + i*5), Dst: 0},
			},
		}
	}

	cfg := &CFG{
		Blocks: []*BasicBlock{block},
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	detector := NewVirtualizationDetector(cfg, ssa)
	detector.DetectVirtualization()

	report := detector.GenerateReportVirt()

	if report == "" {
		t.Error("Expected report to be generated")
	}
	if !strings.Contains(report, "VIRTUALIZATION DETECTION REPORT") {
		t.Error("Expected report to contain title")
	}
	if !strings.Contains(report, "Total Patterns Detected") {
		t.Error("Expected report to contain pattern count")
	}
	if !strings.Contains(report, "Average Confidence") {
		t.Error("Expected report to contain average confidence")
	}
}

// TestMultiplePatterns tests detection of multiple patterns.
func TestMultiplePatterns(t *testing.T) {
	// Create multiple blocks with different virtualization techniques
	dispatcherBlock := &BasicBlock{
		ID:    0,
		Start: 0,
		End:   10,
		Insns: []MIRInsn{
			{Kind: MIR_SWITCH, Offset: 0},
		},
		Succs: make([]*BasicBlock, 6),
	}

	for i := 0; i < 6; i++ {
		dispatcherBlock.Succs[i] = &BasicBlock{
			ID:    i + 1,
			Start: 10 + i*5,
			End:   15 + i*5,
			Insns: []MIRInsn{
				{Kind: MIR_CONST, Offset: uint32(10 + i*5), Dst: 0},
			},
		}
	}

	interpreterBlock := &BasicBlock{
		ID:    10,
		Start: 50,
		End:   60,
		Insns: []MIRInsn{
			{Kind: MIR_FIELD_GET, Offset: 50, Dst: 0},
			{Kind: MIR_FIELD_GET, Offset: 52, Dst: 1},
			{Kind: MIR_FIELD_PUT, Offset: 54, Src1: 0},
		},
		Succs: []*BasicBlock{},
	}
	interpreterBlock.Succs = append(interpreterBlock.Succs, interpreterBlock)

	obfuscatedBlock := &BasicBlock{
		ID:    20,
		Start: 100,
		End:   110,
		Insns: []MIRInsn{
			{Kind: MIR_ADD, Offset: 100, Dst: 0},
			{Kind: MIR_XOR, Offset: 102, Dst: 1},
			{Kind: MIR_MUL, Offset: 104, Dst: 2},
		},
	}

	cfg := &CFG{
		Blocks: []*BasicBlock{dispatcherBlock, interpreterBlock, obfuscatedBlock},
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	detector := NewVirtualizationDetector(cfg, ssa)
	detector.DetectVirtualization()

	if len(detector.Patterns) < 3 {
		t.Errorf("Expected at least 3 patterns, got %d", len(detector.Patterns))
	}

	total, _, _, _, _, _ := detector.GetDetectionStats()
	if total == 0 {
		t.Error("Expected total patterns to be greater than 0")
	}
}

// TestTraceGeneration tests trace generation during detection.
func TestTraceGeneration(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	detector := NewVirtualizationDetector(cfg, ssa)
	detector.DetectVirtualization()

	trace := detector.GetTraceVirt()

	if len(trace) == 0 {
		t.Error("Expected trace to be generated")
	}

	// Check that trace contains expected messages
	traceStr := strings.Join(trace, " ")
	if !strings.Contains(traceStr, "virtualization detection") && !strings.Contains(traceStr, "No CFG blocks") {
		t.Error("Expected trace to contain 'virtualization detection' or 'No CFG blocks'")
	}
}

// TestGetPatternsByConfidenceVirt tests filtering patterns by confidence.
func TestGetPatternsByConfidenceVirt(t *testing.T) {
	block := &BasicBlock{
		ID:    0,
		Start: 0,
		End:   10,
		Insns: []MIRInsn{
			{Kind: MIR_SWITCH, Offset: 0},
		},
		Succs: make([]*BasicBlock, 6),
	}

	for i := 0; i < 6; i++ {
		block.Succs[i] = &BasicBlock{
			ID:    i + 1,
			Start: 10 + i*5,
			End:   15 + i*5,
			Insns: []MIRInsn{
				{Kind: MIR_CONST, Offset: uint32(10 + i*5), Dst: 0},
			},
		}
	}

	cfg := &CFG{
		Blocks: []*BasicBlock{block},
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	detector := NewVirtualizationDetector(cfg, ssa)
	detector.DetectVirtualization()

	highConfidencePatterns := detector.GetPatternsByConfidenceVirt(70)
	lowConfidencePatterns := detector.GetPatternsByConfidenceVirt(50)

	if len(lowConfidencePatterns) < len(highConfidencePatterns) {
		t.Error("Expected more patterns at lower confidence threshold")
	}

	for _, pattern := range highConfidencePatterns {
		if pattern.Confidence < 70 {
			t.Error("Expected all patterns to have confidence >= 70")
		}
	}
}

// TestGetAverageConfidenceVirt tests average confidence calculation.
func TestGetAverageConfidenceVirt(t *testing.T) {
	block := &BasicBlock{
		ID:    0,
		Start: 0,
		End:   10,
		Insns: []MIRInsn{
			{Kind: MIR_SWITCH, Offset: 0},
		},
		Succs: make([]*BasicBlock, 6),
	}

	for i := 0; i < 6; i++ {
		block.Succs[i] = &BasicBlock{
			ID:    i + 1,
			Start: 10 + i*5,
			End:   15 + i*5,
			Insns: []MIRInsn{
				{Kind: MIR_CONST, Offset: uint32(10 + i*5), Dst: 0},
			},
		}
	}

	cfg := &CFG{
		Blocks: []*BasicBlock{block},
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	detector := NewVirtualizationDetector(cfg, ssa)
	detector.DetectVirtualization()

	avgConfidence := detector.GetAverageConfidenceVirt()

	if avgConfidence < 0 || avgConfidence > 100 {
		t.Errorf("Expected average confidence between 0 and 100, got %d", avgConfidence)
	}

	if len(detector.Patterns) > 0 && avgConfidence == 0 {
		t.Error("Expected non-zero average confidence when patterns exist")
	}
}

// TestNilCFG tests handling of nil CFG.
func TestNilCFG(t *testing.T) {
	detector := NewVirtualizationDetector(nil, nil)
	detector.DetectVirtualization()

	if len(detector.Patterns) != 0 {
		t.Error("Expected no patterns with nil CFG")
	}
	if len(detector.Trace) == 0 {
		t.Error("Expected trace to be recorded even with nil CFG")
	}
}

// TestNilBlocks tests handling of nil blocks in CFG.
func TestNilBlocks(t *testing.T) {
	cfg := &CFG{
		Blocks: []*BasicBlock{nil, nil},
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	detector := NewVirtualizationDetector(cfg, ssa)
	detector.DetectVirtualization()

	if len(detector.Patterns) != 0 {
		t.Error("Expected no patterns with nil blocks")
	}
}

// TestEmptyBlocks tests handling of empty instruction blocks.
func TestEmptyBlocks(t *testing.T) {
	block := &BasicBlock{
		ID:    0,
		Start: 0,
		End:   10,
		Insns: make([]MIRInsn, 0),
	}

	cfg := &CFG{
		Blocks: []*BasicBlock{block},
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	detector := NewVirtualizationDetector(cfg, ssa)
	detector.DetectVirtualization()

	if len(detector.Patterns) != 0 {
		t.Error("Expected no patterns with empty blocks")
	}
}

// TestChangeCount tests change counting.
func TestChangeCount(t *testing.T) {
	block := &BasicBlock{
		ID:    0,
		Start: 0,
		End:   10,
		Insns: []MIRInsn{
			{Kind: MIR_SWITCH, Offset: 0},
		},
		Succs: make([]*BasicBlock, 6),
	}

	for i := 0; i < 6; i++ {
		block.Succs[i] = &BasicBlock{
			ID:    i + 1,
			Start: 10 + i*5,
			End:   15 + i*5,
			Insns: []MIRInsn{
				{Kind: MIR_CONST, Offset: uint32(10 + i*5), Dst: 0},
			},
		}
	}

	cfg := &CFG{
		Blocks: []*BasicBlock{block},
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	detector := NewVirtualizationDetector(cfg, ssa)
	detector.DetectVirtualization()

	changeCount := detector.GetChangeCountVirt()

	if changeCount == 0 && len(detector.Patterns) > 0 {
		t.Error("Expected change count to be greater than 0 when patterns detected")
	}
}
