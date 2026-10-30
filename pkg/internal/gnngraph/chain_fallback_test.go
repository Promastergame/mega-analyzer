package gnngraph

import (
	"reflect"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func chainTestMethod(body []string) *types.SmaliMethod {
	return &types.SmaliMethod{
		Name:       "f",
		Params:     "(Ljava/lang/String;)",
		ReturnType: "V",
		Body:       body,
	}
}

func TestChainFallbackCoversStraightLine(t *testing.T) {
	body := []string{
		`const-string v0, "key"`,
		`invoke-static {v0}, LTest;->use(Ljava/lang/String;)V`,
		`return-void`,
	}
	m := chainTestMethod(body)

	// The real CFG collapses a straight-line body to a single block.
	realCFG := BuildMethodCFG(nil, "LTest;", m)
	if realCFG == nil || len(realCFG.Nodes) != 1 {
		t.Fatalf("precondition: straight-line body should give 1 CFG node, got %+v", realCFG)
	}

	chainCFG := BuildChainCFG("LTest;", m)
	if chainCFG == nil {
		t.Fatal("BuildChainCFG returned nil for a 3-instruction body")
	}
	if len(chainCFG.Nodes) != 3 {
		t.Fatalf("chain CFG nodes = %d, want 3", len(chainCFG.Nodes))
	}
	if chainCFG.Entry != chainCFG.Nodes[0] {
		t.Fatal("chain CFG entry must be the first node")
	}
	wantName := "LTest;->f(Ljava/lang/String;)V"
	if chainCFG.FullName != wantName {
		t.Fatalf("FullName = %q, want %q", chainCFG.FullName, wantName)
	}

	var b Builder
	g := b.Build(chainCFG)
	if g == nil || g.NumNodes != 3 {
		t.Fatalf("chain graph nodes = %+v, want 3", g)
	}
	// Every row keeps its explicit self-loop.
	for i := uint64(0); i < g.NumNodes; i++ {
		found := false
		for k := g.RowPtrs[i]; k < g.RowPtrs[i+1]; k++ {
			if g.ColIndices[k] == i {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("row %d has no self-loop", i)
		}
	}

	// Deterministic: a fresh builder over a fresh chain CFG is identical.
	var b2 Builder
	g2 := b2.Build(BuildChainCFG("LTest;", m))
	if !reflect.DeepEqual(g, g2) {
		t.Fatal("chain fallback is not deterministic")
	}
}

func TestChainFallbackRejectsTinyBodies(t *testing.T) {
	if BuildChainCFG("LTest;", nil) != nil {
		t.Fatal("nil method must give nil")
	}
	if BuildChainCFG("LTest;", chainTestMethod(nil)) != nil {
		t.Fatal("empty body must give nil")
	}
	if BuildChainCFG("LTest;", chainTestMethod([]string{"return-void"})) != nil {
		t.Fatal("1-instruction body must give nil")
	}
	if BuildChainCFG("LTest;", chainTestMethod([]string{"const-string v0, \"a\"", "return-void"})) != nil {
		t.Fatal("2-instruction body must give nil")
	}
}

func TestChainFallbackKeepsCallSignal(t *testing.T) {
	body := []string{
		`const-string v0, "key"`,
		`invoke-static {v0}, LTest;->use(Ljava/lang/String;)V`,
		`return-void`,
	}
	var b Builder
	g := b.Build(BuildChainCFG("LTest;", chainTestMethod(body)))
	if g == nil {
		t.Fatal("nil graph")
	}
	// Feature 18 is the isCall flag; the invoke node (index 1) must carry it.
	if g.Features[1*FeatureDim+18] != 1 {
		t.Fatalf("invoke node lost isCall flag: %v", g.Features[1*FeatureDim:(2*FeatureDim)])
	}
	if g.Features[0*FeatureDim+18] != 0 {
		t.Fatalf("const node must not carry isCall flag: %v", g.Features[0:FeatureDim])
	}
}
