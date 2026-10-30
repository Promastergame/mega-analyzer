package cfg

import (
	"testing"
)

func TestDefaultBuildOptionsCoverage(t *testing.T) {
	opts := DefaultBuildOptions()

	if !opts.SplitCriticalEdges {
		t.Error("SplitCriticalEdges should be true by default")
	}
}

func TestNewCFGBuilderCoverage(t *testing.T) {
	builder := NewCFGBuilder()
	if builder == nil {
		t.Error("NewCFGBuilder returned nil")
	}
}

func TestNewCFGBuilderWithOptionsCoverage(t *testing.T) {
	opts := DefaultBuildOptions()
	opts.SplitCriticalEdges = false

	builder := NewCFGBuilderWithOptions(opts)
	if builder == nil {
		t.Error("NewCFGBuilderWithOptions returned nil")
	}
}

func TestCFGBuilder_BuildCoverage(t *testing.T) {
	builder := NewCFGBuilder()

	input := BuildInput{
		MethodName: "testMethod",
		Instructions: []Instruction{
			{Opcode: "const", Operands: []string{"v0", "0"}},
			{Opcode: "return-void", Operands: []string{}},
		},
		Labels: []Label{},
	}

	res := builder.BuildEx(input)
	cfg := res.CFG
	if cfg == nil {
		t.Fatal("Build returned nil")
	}
	if cfg.Entry == nil {
		t.Error("CFG should have entry node")
	}
}

func TestCFGBuilder_BuildEmptyCoverage(t *testing.T) {
	builder := NewCFGBuilder()

	input := BuildInput{
		MethodName:   "emptyMethod",
		Instructions: []Instruction{{Opcode: "return-void"}},
		Labels:       []Label{},
	}

	cfg := builder.Build(input)
	if cfg == nil {
		t.Error("Build should produce CFG for method with instructions")
	}
}

func TestDefaultCacheConfigCoverage(t *testing.T) {
	cfg := DefaultCacheConfig()

	if cfg.Capacity <= 0 {
		t.Error("Capacity should be positive")
	}
}

func TestNewCFGCacheCoverage(t *testing.T) {
	cache := NewCFGCache(100)
	if cache == nil {
		t.Error("NewCFGCache returned nil")
	}
}

func TestNewCFGCacheWithConfigCoverage(t *testing.T) {
	cfg := DefaultCacheConfig()
	cfg.Capacity = 50

	cache := NewCFGCacheWithConfig(cfg)
	if cache == nil {
		t.Error("NewCFGCacheWithConfig returned nil")
	}
}

func TestCFGCache_GetOrBuildCoverage(t *testing.T) {
	cache := NewCFGCache(100)

	input := BuildInput{
		MethodName: "testMethod",
		Instructions: []Instruction{
			{Opcode: "const", Operands: []string{"v0", "0"}},
		},
	}

	// First call should build
	cfg1 := cache.GetOrBuild(input)
	if cfg1 == nil {
		t.Error("GetOrBuild returned nil on first call")
	}

	// Second call should return cached
	cfg2 := cache.GetOrBuild(input)
	if cfg2 == nil {
		t.Error("GetOrBuild returned nil on second call")
	}
}

func TestCFGCache_GetCoverage(t *testing.T) {
	cache := NewCFGCache(100)

	input := BuildInput{
		MethodName: "testMethod",
		Instructions: []Instruction{
			{Opcode: "const", Operands: []string{"v0", "0"}},
		},
	}

	// Get before building should return nil
	cfg := cache.Get(input)
	if cfg != nil {
		t.Error("Get should return nil for non-existent entry")
	}

	// Build it
	cache.GetOrBuild(input)

	// Now Get should return it
	cfg = cache.Get(input)
	if cfg == nil {
		t.Error("Get should return entry after building")
	}
}

func TestNewLabelIndexCoverage(t *testing.T) {
	idx := NewLabelIndex()
	if idx == nil {
		t.Error("NewLabelIndex returned nil")
	}
}

func TestLabelIndex_BuildFromMethodCoverage(t *testing.T) {
	idx := NewLabelIndex()

	instructions := []Instruction{
		{Line: 1, Opcode: "const", Operands: []string{"v0", "0"}},
		{Line: 2, Opcode: "if-eq", Operands: []string{"v0", ":cond_0"}},
		{Line: 3, Opcode: "return-void", Operands: []string{}},
	}

	labels := []Label{
		{Name: "cond_0", Line: 2},
	}

	idx.BuildFromMethod(instructions, labels)

	// Should be able to get label index
	labelIdx, ok := idx.GetInstructionIndex("cond_0")
	if !ok {
		t.Error("Should find label cond_0")
	}
	if labelIdx != 2 {
		t.Errorf("Label index = %d, want 2", labelIdx)
	}
}

func TestLabelIndex_HasLabelCoverage(t *testing.T) {
	idx := NewLabelIndex()

	labels := []Label{
		{Name: "cond_0", Line: 1},
	}

	idx.BuildFromMethod([]Instruction{{Line: 1}}, labels)

	if !idx.HasLabel("cond_0") {
		t.Error("HasLabel should return true for existing label")
	}
	if idx.HasLabel("nonexistent") {
		t.Error("HasLabel should return false for non-existing label")
	}
}

func TestGuardType_StringCoverage(t *testing.T) {
	tests := []struct {
		guard    GuardType
		expected string
	}{
		{GuardTypeUnknown, "unknown"},
		{GuardTypeNull, "null"},
		{GuardTypePermission, "permission"},
		{GuardTypeNetwork, "network"},
	}

	for _, tc := range tests {
		result := tc.guard.String()
		if result != tc.expected {
			t.Errorf("GuardType(%d).String() = %q, want %q", tc.guard, result, tc.expected)
		}
	}
}

func TestNodeType_StringCoverage(t *testing.T) {
	tests := []struct {
		nodeType NodeType
	}{
		{NodeTypeEntry},
		{NodeTypeExit},
		{NodeTypeBasic},
		{NodeTypeCondition},
		{NodeTypeSynthetic},
	}

	for _, tc := range tests {
		result := tc.nodeType.String()
		if result == "" {
			t.Errorf("NodeType(%d).String() returned empty string", tc.nodeType)
		}
	}
}

func TestNodeType_IsTerminatorCoverage(t *testing.T) {
	tests := []struct {
		nodeType NodeType
		expected bool
	}{
		{NodeTypeEntry, false},
		{NodeTypeExit, true},
		{NodeTypeBasic, false},
		{NodeTypeCondition, false},
	}

	for _, tc := range tests {
		result := tc.nodeType.IsTerminator()
		if result != tc.expected {
			t.Errorf("NodeType(%d).IsTerminator() = %v, want %v", tc.nodeType, result, tc.expected)
		}
	}
}

func TestNodeType_IsBranchingCoverage(t *testing.T) {
	tests := []struct {
		nodeType NodeType
		expected bool
	}{
		{NodeTypeEntry, false},
		{NodeTypeExit, false},
		{NodeTypeBasic, false},
		{NodeTypeCondition, true},
	}

	for _, tc := range tests {
		result := tc.nodeType.IsBranching()
		if result != tc.expected {
			t.Errorf("NodeType(%d).IsBranching() = %v, want %v", tc.nodeType, result, tc.expected)
		}
	}
}

func TestExitKind_StringCoverage(t *testing.T) {
	tests := []struct {
		kind ExitKind
	}{
		{ExitNormal},
		{ExitException},
		{ExitUnreachable},
	}

	for _, tc := range tests {
		result := tc.kind.String()
		if result == "" {
			t.Errorf("ExitKind(%d).String() returned empty string", tc.kind)
		}
	}
}

func TestNewDominatorAnalyzerCoverage(t *testing.T) {
	cfg := &ControlFlowGraph{
		Entry: &CFGNode{ID: 0, Type: NodeTypeEntry},
	}

	analyzer := NewDominatorAnalyzer(cfg)
	if analyzer == nil {
		t.Error("NewDominatorAnalyzer returned nil")
	}
}

func TestNewLoopAnalyzerCoverage(t *testing.T) {
	cfg := &ControlFlowGraph{
		Entry: &CFGNode{ID: 0, Type: NodeTypeEntry},
	}

	analyzer := NewLoopAnalyzer(cfg)
	if analyzer == nil {
		t.Error("NewLoopAnalyzer returned nil")
	}
}

func TestNewMetricsCoverage(t *testing.T) {
	cfg := &ControlFlowGraph{
		Entry: &CFGNode{ID: 0, Type: NodeTypeEntry},
	}

	metrics := NewMetrics(cfg)
	if metrics == nil {
		t.Error("NewMetrics returned nil")
	}
}

func TestNewPatternAnalyzerCoverage(t *testing.T) {
	cfg := &ControlFlowGraph{
		Entry: &CFGNode{ID: 0, Type: NodeTypeEntry},
	}

	analyzer := NewPatternAnalyzer(cfg)
	if analyzer == nil {
		t.Error("NewPatternAnalyzer returned nil")
	}
}

func TestNewSSABuilderCoverage(t *testing.T) {
	cfg := &ControlFlowGraph{
		Entry: &CFGNode{ID: 0, Type: NodeTypeEntry},
	}

	builder := NewSSABuilder(cfg)
	if builder == nil {
		t.Error("NewSSABuilder returned nil")
	}
}

func TestPhiNode_StringCoverage(t *testing.T) {
	phi := &PhiNode{
		Register: "v0",
		Operands: make(map[*CFGNode]*ValueRef),
	}

	result := phi.String()
	if result == "" {
		t.Error("PhiNode.String() returned empty string")
	}
}
