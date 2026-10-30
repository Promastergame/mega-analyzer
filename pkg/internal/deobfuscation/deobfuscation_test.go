package deobfuscation

import (
	"mega-analyzer/pkg/internal/cfg"
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS: DEOBFUSCATION ENGINE
// ═══════════════════════════════════════════════════════════════════════════════

func TestNewEngine(t *testing.T) {
	e := NewDefaultEngine()
	if e == nil {
		t.Fatal("NewEngine returned nil")
	}
	if !e.EnableCFF {
		t.Error("expected EnableCFF=true")
	}
	if !e.EnableOpaque {
		t.Error("expected EnableOpaque=true")
	}
	if !e.EnableDeadCode {
		t.Error("expected EnableDeadCode=true")
	}
}

func TestAnalyze_NilGraph(t *testing.T) {
	e := NewDefaultEngine()
	result := e.Analyze(nil)
	if result == nil {
		t.Fatal("expected non-nil result for nil graph")
	}
	if result.CFFFDetected {
		t.Error("expected no CFF detection on nil graph")
	}
}

func TestAnalyze_EmptyGraph(t *testing.T) {
	e := NewDefaultEngine()
	graph := &cfg.ControlFlowGraph{}
	result := e.Analyze(graph)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.OpaquePredicatesFound != 0 {
		t.Errorf("expected 0 opaque predicates, got %d", result.OpaquePredicatesFound)
	}
}

func TestAnalyze_SimpleGraph(t *testing.T) {
	graph := buildSimpleTestGraph()
	e := NewDefaultEngine()
	result := e.Analyze(graph)

	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.OriginalComplexity < 0 {
		t.Errorf("expected non-negative complexity, got %d", result.OriginalComplexity)
	}
}

func TestOpaquePredicateDetection_SameSuccessors(t *testing.T) {
	// Граф где обе ветки условия ведут в одну ноду
	target := &cfg.CFGNode{ID: 2, Type: cfg.NodeTypeBasic}
	condNode := &cfg.CFGNode{
		ID:         1,
		Type:       cfg.NodeTypeCondition,
		Successors: []*cfg.CFGNode{target, target},
		Condition: &cfg.ConditionInfo{
			Op:        cfg.CondEqZero,
			Register1: "v0",
		},
	}
	entry := &cfg.CFGNode{
		ID:         0,
		Type:       cfg.NodeTypeEntry,
		Successors: []*cfg.CFGNode{condNode},
	}
	condNode.Predecessors = []*cfg.CFGNode{entry}
	target.Predecessors = []*cfg.CFGNode{condNode, condNode}

	graph := &cfg.ControlFlowGraph{
		Entry: entry,
		Nodes: []*cfg.CFGNode{entry, condNode, target},
		Edges: []*cfg.CFGEdge{
			{From: entry, To: condNode},
			{From: condNode, To: target},
		},
	}

	e := NewDefaultEngine()
	result := e.Analyze(graph)

	if result.OpaquePredicatesFound == 0 {
		t.Error("expected at least 1 opaque predicate (same successors)")
	}
}

func TestOpaquePredicateDetection_SelfComparison(t *testing.T) {
	// if-eq v0, v0 → всегда true
	target := &cfg.CFGNode{ID: 2, Type: cfg.NodeTypeBasic}
	falseTarget := &cfg.CFGNode{ID: 3, Type: cfg.NodeTypeBasic}
	condNode := &cfg.CFGNode{
		ID:         1,
		Type:       cfg.NodeTypeCondition,
		Successors: []*cfg.CFGNode{target, falseTarget},
		Condition: &cfg.ConditionInfo{
			Op:        cfg.CondEq,
			Register1: "v0",
			Register2: "v0",
		},
	}
	entry := &cfg.CFGNode{
		ID:         0,
		Type:       cfg.NodeTypeEntry,
		Successors: []*cfg.CFGNode{condNode},
	}
	condNode.Predecessors = []*cfg.CFGNode{entry}

	graph := &cfg.ControlFlowGraph{
		Entry: entry,
		Nodes: []*cfg.CFGNode{entry, condNode, target, falseTarget},
		Edges: []*cfg.CFGEdge{
			{From: entry, To: condNode},
			{From: condNode, To: target},
			{From: condNode, To: falseTarget},
		},
	}

	e := NewDefaultEngine()
	result := e.Analyze(graph)

	if result.OpaquePredicatesFound == 0 {
		t.Error("expected opaque predicate for self-comparison (if-eq v0, v0)")
	}
}

func TestDeadCodeElimination(t *testing.T) {
	// Граф с недоступной нодой
	entry := &cfg.CFGNode{ID: 0, Type: cfg.NodeTypeEntry}
	reachable := &cfg.CFGNode{ID: 1, Type: cfg.NodeTypeBasic}
	unreachable := &cfg.CFGNode{ID: 2, Type: cfg.NodeTypeBasic}

	entry.Successors = []*cfg.CFGNode{reachable}
	reachable.Predecessors = []*cfg.CFGNode{entry}
	// unreachable ни от кого не зависит

	graph := &cfg.ControlFlowGraph{
		Entry: entry,
		Nodes: []*cfg.CFGNode{entry, reachable, unreachable},
		Edges: []*cfg.CFGEdge{
			{From: entry, To: reachable},
		},
	}

	e := NewDefaultEngine()
	result := e.Analyze(graph)

	if result.DeadNodesFound != 1 {
		t.Errorf("expected 1 dead node, got %d", result.DeadNodesFound)
	}
}

func TestStringEncryptionDetection(t *testing.T) {
	e := NewDefaultEngine()

	// Base64 строка
	if !e.looksEncrypted("SGVsbG8gV29ybGQgVGhpcyBpcyBhIHRlc3Q=") {
		t.Error("expected Base64 string to be detected as encrypted")
	}

	// Hex строка
	if !e.looksEncrypted("4a6f686e446f65456d61696c41646472") {
		t.Error("expected hex string to be detected as encrypted")
	}

	// Обычная строка
	if e.looksEncrypted("Hello") {
		t.Error("expected short string NOT to be detected as encrypted")
	}
}

func TestReductionPercent(t *testing.T) {
	e := NewDefaultEngine()
	// Граф с дохлым кодом
	entry := &cfg.CFGNode{ID: 0, Type: cfg.NodeTypeEntry}
	dead1 := &cfg.CFGNode{ID: 1, Type: cfg.NodeTypeBasic}
	dead2 := &cfg.CFGNode{ID: 2, Type: cfg.NodeTypeBasic}

	graph := &cfg.ControlFlowGraph{
		Entry: entry,
		Nodes: []*cfg.CFGNode{entry, dead1, dead2},
		Edges: []*cfg.CFGEdge{},
	}

	result := e.Analyze(graph)
	if result.ProjectedReductionPercent < 0 {
		t.Errorf("expected non-negative reduction, got %.2f", result.ProjectedReductionPercent)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

func buildSimpleTestGraph() *cfg.ControlFlowGraph {
	entry := &cfg.CFGNode{ID: 0, Type: cfg.NodeTypeEntry}
	body := &cfg.CFGNode{ID: 1, Type: cfg.NodeTypeBasic}
	exit := &cfg.CFGNode{ID: 2, Type: cfg.NodeTypeReturn}

	entry.Successors = []*cfg.CFGNode{body}
	body.Predecessors = []*cfg.CFGNode{entry}
	body.Successors = []*cfg.CFGNode{exit}
	exit.Predecessors = []*cfg.CFGNode{body}

	return &cfg.ControlFlowGraph{
		Entry: entry,
		Nodes: []*cfg.CFGNode{entry, body, exit},
		Edges: []*cfg.CFGEdge{
			{From: entry, To: body},
			{From: body, To: exit},
		},
	}
}

func TestStringDecryptionSolver(t *testing.T) {
	// 1. Base64 decoded string
	const want = "https://license.example.com/verify"
	res, _ := tryDecryptString(base64Std([]byte(want)))
	if res != want {
		t.Errorf("expected %q, got %q", want, res)
	}

	// 2. Programmatically cracked XOR string
	original := "This is a verified license premium key!"
	key := byte(42)
	xorData := make([]byte, len(original))
	for i := range original {
		xorData[i] = original[i] ^ key
	}

	cracked, resolvedKey := crackXOR(xorData)
	if cracked != original {
		t.Errorf("expected cracked to be '%s', got '%s'", original, cracked)
	}
	if resolvedKey != key {
		t.Errorf("expected resolved key to be %d, got %d", key, resolvedKey)
	}
}
