package arbiter

import (
	"testing"

	"mega-analyzer/pkg/internal/cfg"
)

func namedGraph(class, method string, instrSets ...[]string) *cfg.ControlFlowGraph {
	g := linearGraph(instrSets...)
	g.ClassName = class
	g.MethodName = method
	return g
}

func TestDiffVersions_AddedAndRemoved(t *testing.T) {
	old := []*cfg.ControlFlowGraph{
		namedGraph("LFoo;", "gone", []string{"const/4 v0, 0x0"}),
	}
	new := []*cfg.ControlFlowGraph{
		namedGraph("LFoo;", "brand_new", []string{"const/4 v0, 0x0"}),
	}

	diffs := DiffVersions(old, new)
	if len(diffs) != 2 {
		t.Fatalf("expected 2 diffs, got %d: %+v", len(diffs), diffs)
	}

	byKey := map[string]MethodDiff{}
	for _, d := range diffs {
		byKey[d.Key] = d
	}

	if d, ok := byKey["LFoo;.gone"]; !ok || d.Status != "removed" {
		t.Errorf("expected LFoo;.gone to be removed, got %+v", d)
	}
	if d, ok := byKey["LFoo;.brand_new"]; !ok || d.Status != "added" {
		t.Errorf("expected LFoo;.brand_new to be added, got %+v", d)
	}
}

func TestDiffVersions_UnchangedMethod(t *testing.T) {
	mk := func() []*cfg.ControlFlowGraph {
		return []*cfg.ControlFlowGraph{
			namedGraph("LFoo;", "same",
				[]string{"const/4 v0, 0x0"},
				[]string{"invoke-virtual {v0}, Ljava/lang/String;->length()"},
			),
		}
	}

	diffs := DiffVersions(mk(), mk())
	if len(diffs) != 1 {
		t.Fatalf("expected 1 diff, got %d", len(diffs))
	}
	if diffs[0].Status != "unchanged" {
		t.Errorf("expected identical method to be 'unchanged', got %+v", diffs[0])
	}
	if diffs[0].Sim < 0.99 {
		t.Errorf("expected sim ~1.0 for identical method, got %v", diffs[0].Sim)
	}
}

func TestDiffVersions_ModifiedMethod(t *testing.T) {
	oldG := []*cfg.ControlFlowGraph{
		namedGraph("LFoo;", "changed", []string{"const/4 v0, 0x0"}),
	}
	newG := []*cfg.ControlFlowGraph{
		namedGraph("LFoo;", "changed",
			[]string{"const/4 v0, 0x0"},
			[]string{"invoke-virtual {v0}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)"},
			[]string{"if-eqz v0, :label"},
			[]string{"throw v0"},
		),
	}

	diffs := DiffVersions(oldG, newG)
	if len(diffs) != 1 {
		t.Fatalf("expected 1 diff, got %d", len(diffs))
	}
	if diffs[0].Status != "modified" {
		t.Errorf("expected structurally different method body to be 'modified', got %+v", diffs[0])
	}
}

func TestDiffVersions_ClassNameFallback(t *testing.T) {
	old := []*cfg.ControlFlowGraph{
		{MethodName: "onlyMethod", Nodes: []*cfg.CFGNode{mkNode(0, "const/4 v0, 0x0")}},
	}
	diffs := DiffVersions(old, nil)
	if len(diffs) != 1 || diffs[0].Key != "onlyMethod" {
		t.Fatalf("expected key to fall back to bare method name, got %+v", diffs)
	}
}
