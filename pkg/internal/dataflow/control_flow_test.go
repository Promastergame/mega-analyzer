package dataflow

import (
	"context"
	"strings"
	"testing"
)

func TestCFGUnknownControlFlowIsExplicitlyIncomplete(t *testing.T) {
	p := NewProgram(DefaultConfig())
	addMethod(p, "Lfixture/Unknown;", "run", "Landroid/content/Intent;", "V", true,
		`.locals 3`, `const-string v1, "input"`, `invoke-virtual {p0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;`, `move-result-object v0`,
		`goto :missing`, `const-string v0, "fixed"`, `invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;`, `move-result-object v2`,
		`invoke-virtual {v2, v0}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;`, `return-void`)
	r := p.Analyze(context.Background())
	if !r.Stats.LimitReached || r.Stats.CFGIncompleteMethods != 1 {
		t.Fatalf("unsupported branch misreported as complete: %+v", r.Stats)
	}
	if len(r.Findings) == 0 {
		t.Fatal("unsupported branch unsoundly treated as safe")
	}
}
func TestCFGDuplicateLabelsAreNotProofOfSafety(t *testing.T) {
	g := buildMethodCFG(methodData{Body: []string{":x", "nop", ":x", "return-void"}}, context.Background())
	if !g.incomplete {
		t.Fatal("duplicate labels accepted as a complete graph")
	}
}
func TestCFGOpcodeWidthsMatchRepresentativeDEXFormats(t *testing.T) {
	for op, w := range map[string]int{"goto": 1, "goto/16": 2, "goto/32": 3, "if-eqz": 2, "invoke-virtual": 3, "const-string": 2, "const-string/jumbo": 3, "packed-switch": 3, "const-wide": 5, "invoke-polymorphic": 4} {
		if cfgOpcodeUnits[op] != w {
			t.Fatalf("%s: got %d want %d", op, cfgOpcodeUnits[op], w)
		}
	}
	n, e := cfgRelativeOffset("0xfffffff8")
	if e != nil || n != -8 {
		t.Fatalf("unsigned hex sign-extension: %d %v", n, e)
	}
}
func FuzzCFGConstruction(f *testing.F) {
	for _, seed := range []string{".locals 2\n:entry\nif-eqz p0, :entry\nreturn-void", "packed-switch v0, :table\nreturn-void\n:table\n.packed-switch 0x0\n:missing\n.end packed-switch", ".array-data 0x8\n0x1L\n.end array-data", ".catchall {:begin .. :end} :handler"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 8192 {
			return
		}
		g := buildMethodCFG(methodData{Body: strings.Split(body, "\n")}, context.Background())
		for _, id := range g.order {
			if g.nodes[id] == nil {
				t.Fatal("dangling instruction")
			}
			for _, to := range g.nodes[id].succ {
				if g.nodes[to] == nil {
					t.Fatal("dangling edge")
				}
			}
		}
	})
}
