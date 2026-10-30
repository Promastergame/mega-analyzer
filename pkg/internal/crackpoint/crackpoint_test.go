package crackpoint

import (
	"mega-analyzer/pkg/internal/cfg"
	"strings"
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS: CRACK POINT FINDER
// ═══════════════════════════════════════════════════════════════════════════════

func TestNewFinder(t *testing.T) {
	f := NewFinder()
	if f == nil {
		t.Fatal("NewFinder returned nil")
	}
	if len(f.gatePatterns) == 0 {
		t.Error("expected gate patterns to be populated")
	}
	if len(f.fieldPatterns) == 0 {
		t.Error("expected field patterns to be populated")
	}
}

func TestFindCrackPoints_NilGraph(t *testing.T) {
	f := NewFinder()
	result := f.FindCrackPoints(nil, "Lcom/test/Test;")
	if result == nil {
		t.Fatal("expected non-nil result for nil graph")
	}
	if result.TotalFound != 0 {
		t.Errorf("expected 0 crack points, got %d", result.TotalFound)
	}
}

func TestFindCrackPoints_GateMethod(t *testing.T) {
	// Граф с вызовом isPremium
	node := &cfg.CFGNode{
		ID:   1,
		Type: cfg.NodeTypeBasic,
		Instructions: []cfg.InstructionRef{
			{
				Index:  0,
				Opcode: "invoke-virtual",
				Raw:    "invoke-virtual {v0}, Lcom/app/User;->isPremium()Z",
			},
		},
	}
	entry := &cfg.CFGNode{
		ID:         0,
		Type:       cfg.NodeTypeEntry,
		Successors: []*cfg.CFGNode{node},
	}
	node.Predecessors = []*cfg.CFGNode{entry}

	graph := &cfg.ControlFlowGraph{
		Entry: entry,
		Nodes: []*cfg.CFGNode{entry, node},
		Edges: []*cfg.CFGEdge{{From: entry, To: node}},
	}

	f := NewFinder()
	result := f.FindCrackPoints(graph, "Lcom/app/Main;")

	if result.TotalFound == 0 {
		t.Error("expected to find crack point for isPremium")
	}

	if result.TotalFound > 0 {
		cp := result.CrackPoints[0]
		if cp.Category != "premium" {
			t.Errorf("expected category 'premium', got '%s'", cp.Category)
		}
		if cp.Confidence < 0.8 {
			t.Errorf("expected high confidence, got %.2f", cp.Confidence)
		}
	}
}

func TestFindCrackPoints_RootDetection(t *testing.T) {
	node := &cfg.CFGNode{
		ID:   1,
		Type: cfg.NodeTypeBasic,
		Instructions: []cfg.InstructionRef{
			{
				Index:  0,
				Opcode: "invoke-static",
				Raw:    "invoke-static {}, Lcom/sec/RootChecker;->isDeviceRooted()Z",
			},
		},
	}
	entry := &cfg.CFGNode{
		ID:         0,
		Type:       cfg.NodeTypeEntry,
		Successors: []*cfg.CFGNode{node},
	}
	node.Predecessors = []*cfg.CFGNode{entry}

	graph := &cfg.ControlFlowGraph{
		Entry: entry,
		Nodes: []*cfg.CFGNode{entry, node},
		Edges: []*cfg.CFGEdge{{From: entry, To: node}},
	}

	f := NewFinder()
	result := f.FindCrackPoints(graph, "Lcom/app/Security;")

	if result.TotalFound == 0 {
		t.Error("expected root detection crack point")
	}

	if result.TotalFound > 0 {
		cp := result.CrackPoints[0]
		if cp.Category != "root" {
			t.Errorf("expected category 'root', got '%s'", cp.Category)
		}
	}
}

func TestFindCrackPoints_FieldCheck(t *testing.T) {
	node := &cfg.CFGNode{
		ID:   1,
		Type: cfg.NodeTypeBasic,
		Instructions: []cfg.InstructionRef{
			{
				Index:  0,
				Opcode: "iget-boolean",
				Raw:    "iget-boolean v0, p0, Lcom/app/Config;->isPremium:Z",
			},
		},
	}
	entry := &cfg.CFGNode{
		ID:         0,
		Type:       cfg.NodeTypeEntry,
		Successors: []*cfg.CFGNode{node},
	}
	node.Predecessors = []*cfg.CFGNode{entry}

	graph := &cfg.ControlFlowGraph{
		Entry: entry,
		Nodes: []*cfg.CFGNode{entry, node},
		Edges: []*cfg.CFGEdge{{From: entry, To: node}},
	}

	f := NewFinder()
	result := f.FindCrackPoints(graph, "Lcom/app/Activity;")

	if result.TotalFound == 0 {
		t.Error("expected field-based crack point for isPremium")
	}
}

func TestCrackSuggestions(t *testing.T) {
	f := NewFinder()

	result := &AnalysisResult{
		CrackPoints: []CrackPoint{
			{Category: "premium", ReturnType: "boolean"},
			{Category: "root", ReturnType: "boolean"},
			{Category: "billing"},
			{Category: "ads", ReturnType: "boolean"},
		},
	}

	f.generateSuggestions(result)

	tests := []struct {
		idx          int
		expectAction string
		expectRisk   string
	}{
		{0, "Return true", "medium"},
		{1, "Return false", "low"},
		{2, "Analyze billing", "critical"},
		{3, "Return true", "low"},
	}

	for _, tt := range tests {
		cp := result.CrackPoints[tt.idx]
		if !strings.Contains(cp.SuggestedAction, tt.expectAction) {
			t.Errorf("[%d] expected action containing '%s', got '%s'", tt.idx, tt.expectAction, cp.SuggestedAction)
		}
		if cp.PatchRisk != tt.expectRisk {
			t.Errorf("[%d] expected risk '%s', got '%s'", tt.idx, tt.expectRisk, cp.PatchRisk)
		}
	}
}

func TestExtractMethodName(t *testing.T) {
	f := NewFinder()

	tests := []struct {
		raw    string
		expect string
	}{
		{"invoke-virtual {v0}, Lcom/app/User;->isPremium()Z", "isPremium"},
		{"invoke-static {}, Lcom/sec/Check;->isRooted()Z", "isRooted"},
		{"no arrow here", "no arrow here"},
	}

	for _, tt := range tests {
		got := f.extractMethodName(tt.raw)
		if got != tt.expect {
			t.Errorf("extractMethodName(%q) = %q, want %q", tt.raw, got, tt.expect)
		}
	}
}

func TestCategoriesCount(t *testing.T) {
	f := NewFinder()

	node1 := &cfg.CFGNode{
		ID: 1, Type: cfg.NodeTypeBasic,
		Instructions: []cfg.InstructionRef{
			{Opcode: "invoke-virtual", Raw: "invoke-virtual {v0}, Lcom/app;->isPremium()Z"},
			{Opcode: "invoke-static", Raw: "invoke-static {}, Lcom/app;->isRooted()Z"},
		},
	}
	entry := &cfg.CFGNode{ID: 0, Type: cfg.NodeTypeEntry, Successors: []*cfg.CFGNode{node1}}
	node1.Predecessors = []*cfg.CFGNode{entry}

	graph := &cfg.ControlFlowGraph{
		Entry: entry,
		Nodes: []*cfg.CFGNode{entry, node1},
		Edges: []*cfg.CFGEdge{{From: entry, To: node1}},
	}

	result := f.FindCrackPoints(graph, "Test")

	if len(result.Categories) == 0 {
		t.Error("expected at least one category")
	}
}
