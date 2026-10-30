package analyzer

import (
	"mega-analyzer/pkg/internal/types"
	"testing"
)

func TestCallGraphBuilder_Coverage(t *testing.T) {
	builder := NewCallGraphBuilder()

	method := &types.SmaliMethod{
		Name:       "check",
		Params:     "Ljava/lang/String;",
		ReturnType: "Z",
		Invokes: []types.Invoke{
			{Class: "Lcom/app/Lib;", Method: "verify", Params: "()V", ReturnType: "V"},
		},
	}

	builder.AddMethod("com.app.Test", method, "Test.smali")

	// Add same method again (test de-duplication)
	builder.AddMethod("com.app.Test", method, "Test.smali")

	if builder.NodeCount() != 2 { // Test.check and Lib.verify
		t.Errorf("NodeCount = %d, want 2", builder.NodeCount())
	}

	graph := builder.Build()
	if len(graph.Nodes) != 2 {
		t.Errorf("Graph nodes count = %d", len(graph.Nodes))
	}
}

func TestGraphAnalyzer_Coverage(t *testing.T) {
	builder := NewCallGraphBuilder()

	// Node 1: Entry Point
	builder.AddMethod("Entry", &types.SmaliMethod{
		Name:       "start",
		Params:     "",
		ReturnType: "V",
		Invokes: []types.Invoke{
			{Class: "Mid", Method: "process", Params: "", ReturnType: "V"},
		},
	}, "Entry.smali")

	// Node 2: Middle / Bottleneck
	builder.AddMethod("Mid", &types.SmaliMethod{
		Name:       "process",
		Params:     "",
		ReturnType: "V",
		Invokes: []types.Invoke{
			{Class: "Leaf", Method: "end", Params: "", ReturnType: "V"},
			{Class: "Ljava/lang/System", Method: "exit", Params: "I", ReturnType: "V"}, // suspicious enforce
		},
	}, "Mid.smali")

	// Special case: check-method
	builder.AddMethod("Check", &types.SmaliMethod{
		Name:       "isLicensed",
		Params:     "",
		ReturnType: "Z",
	}, "Check.smali")

	builder.AddMethod("Leaf", &types.SmaliMethod{
		Name:       "end",
		Params:     "",
		ReturnType: "V",
	}, "Leaf.smali")

	// Orchestrator for Protection Flow
	builder.AddMethod("Orchestrator", &types.SmaliMethod{
		Name:       "run",
		Params:     "",
		ReturnType: "V",
		Invokes: []types.Invoke{
			{Class: "Check", Method: "isLicensed", Params: "", ReturnType: "Z"},
			{Class: "Ljava/lang/System", Method: "exit", Params: "I", ReturnType: "V"},
		},
	}, "Orchestrator.smali")

	graph := builder.Build()
	analyzer := NewGraphAnalyzer(graph)

	stats := analyzer.Stats()
	if stats.TotalNodes == 0 {
		t.Error("Stats should have nodes")
	}

	entries := analyzer.EntryPoints()
	if len(entries) == 0 {
		t.Error("Should have entry points")
	}

	leaves := analyzer.LeafNodes()
	if len(leaves) == 0 {
		t.Error("Should have leaf nodes")
	}

	critical := analyzer.FindCriticalMethods(10)
	_ = critical

	mostCalled := analyzer.MostCalled(5)
	if len(mostCalled) == 0 {
		// Mid.process and Leaf.end and System.exit and Check.isLicensed
	}

	mostCalling := analyzer.MostCalling(5)
	_ = mostCalling

	path := analyzer.FindPath("LEntry;->start()V", "LLeaf;->end()V", 5)
	if len(path) != 3 {
		t.Errorf("Path length = %d, want 3", len(path))
	}

	reachable := analyzer.Reachable("LEntry;->start()V", 5)
	if len(reachable) < 3 {
		t.Error("Should reach at least 3 nodes")
	}

	callers := analyzer.Callers("LLeaf;->end()V", 5)
	if len(callers) < 2 {
		t.Errorf("Should have at least 2 callers, got %v", len(callers))
	}

	flows := analyzer.FindProtectionFlows()
	if len(flows) == 0 {
		t.Error("Should find protection flow in Orchestrator")
	}

	byClass := analyzer.MethodsByClass()
	if len(byClass) < 4 {
		t.Error("Should have several classes")
	}

	filtered := analyzer.FilterByKeywords([]string{"Licensed", "start"})
	if len(filtered) < 2 {
		t.Error("Should filter at least 2 nodes")
	}
}

func TestHelpers_Coverage(t *testing.T) {
	if extractMethodName("Lcom/app/Foo;->isLicensed(...)Z") != "isLicensed" {
		t.Error("Failed to extract method name")
	}
	if extractMethodName("invalid") != "" {
		t.Error("Should return empty for invalid name")
	}

	if !isCheckMethod("islicensed") {
		t.Error("Should recognize islicensed")
	}
	if !isEnforceMethod("finish") {
		t.Error("Should recognize finish")
	}
}
