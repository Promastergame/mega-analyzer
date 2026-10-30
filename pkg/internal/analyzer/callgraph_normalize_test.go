// callgraph_normalize_test.go — invoke node-name normalization (audit D1).
package analyzer

import (
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func TestNormalizeClassDescriptor_Forms(t *testing.T) {
	cases := map[string]string{
		"com.example.App":   "Lcom/example/App;",
		"com/example/App":   "Lcom/example/App;",
		"Lcom/example/App;": "Lcom/example/App;",
		"App":               "LApp;",
		"License":           "LLicense;", // bare leading L must survive
		"Lcom/Target":       "Lcom/Target;",
	}
	for input, want := range cases {
		if got := normalizeClassDescriptor(input); got != want {
			t.Errorf("normalizeClassDescriptor(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestCallGraph_DotFormInvokeJoinsDeclaredMethod(t *testing.T) {
	// The parser stores invoke targets in DOT form while declared classes
	// are keyed separately; before D1 the two never joined (orphan nodes).
	builder := NewCallGraphBuilder()

	builder.AddMethod("com.example.Caller", &types.SmaliMethod{
		Name: "run", ReturnType: "V",
		Invokes: []types.Invoke{
			{Class: "com.example.Target", Method: "helper", ReturnType: "V"},
		},
	}, "Caller.smali")

	builder.AddMethod("com.example.Target", &types.SmaliMethod{
		Name: "helper", ReturnType: "V",
	}, "Target.smali")

	graph := builder.Build()
	targetKey := formatMethodFullName("com.example.Target", "helper", "", "V")

	node, ok := graph.Nodes[targetKey]
	if !ok {
		t.Fatalf("target node %q missing; nodes: %v", targetKey, nodeKeys(graph))
	}
	if len(node.CalledBy) != 1 {
		t.Fatalf("expected dot-form invoke to join the declared method (CalledBy=%v)", node.CalledBy)
	}
	if node.File != "Target.smali" {
		t.Errorf("joined node must keep the declared definition site, File=%q", node.File)
	}

	ga := NewGraphAnalyzer(graph)
	from := formatMethodFullName("com.example.Caller", "run", "", "V")
	if path := ga.FindPath(from, targetKey, 5); path == nil {
		t.Error("expected Caller.run → Target.helper path after normalization")
	}
}

func TestCallGraph_SlashedAndDottedClassNamesJoin(t *testing.T) {
	// Same class addressed in slashed and dotted spellings must collapse
	// into ONE node.
	builder := NewCallGraphBuilder()
	builder.AddMethod("com.example.App", &types.SmaliMethod{
		Name: "a", ReturnType: "V",
	}, "Dotted.smali")
	builder.AddMethod("com/example/App", &types.SmaliMethod{
		Name: "b", ReturnType: "V",
	}, "Slashed.smali")

	graph := builder.Build()
	if len(graph.Nodes) != 2 {
		t.Fatalf("dotted/slashed spellings must share one class: nodes=%v", nodeKeys(graph))
	}
}

func nodeKeys(graph *types.CallGraph) []string {
	keys := make([]string, 0, len(graph.Nodes))
	for key := range graph.Nodes {
		keys = append(keys, key)
	}
	return keys
}
