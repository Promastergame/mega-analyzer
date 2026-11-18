package dataflow

import (
	"context"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func TestInterfaceSliceRetainsUnresolvedCallTarget(t *testing.T) {
	for _, multiple := range []bool{false, true} {
		program := NewProgram(DefaultConfig())
		program.AddClass("Loader.smali", &types.SmaliClass{Name: "app.Loader", Methods: []types.SmaliMethod{{Name: "load", Params: "Ljava/lang/String;", ReturnType: "V", Access: types.AccessAbstract}}})
		program.AddClass("Impl.smali", &types.SmaliClass{Name: "app.Impl", Interfaces: []string{"app.Loader"}, Methods: []types.SmaliMethod{{Name: "load", Params: "Ljava/lang/String;", ReturnType: "V", Body: []string{"invoke-static {p1}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;", "return-void"}}}})
		if multiple {
			program.AddClass("Other.smali", &types.SmaliClass{Name: "app.Other", Interfaces: []string{"app.Loader"}, Methods: []types.SmaliMethod{{Name: "load", Params: "Ljava/lang/String;", ReturnType: "V", Body: []string{"return-void"}}}})
		}
		addMethod(program, "Lapp/Entry;", "run", "Landroid/content/Intent;Ljava/lang/String;", "V", true,
			"invoke-virtual {p0, p1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;", "move-result-object v0",
			"invoke-interface {v8, v0}, Lapp/Loader;->load(Ljava/lang/String;)V", "return-void")
		result := program.Analyze(context.Background())
		if len(result.Findings) != 1 {
			t.Fatalf("lost candidate: %+v", result.Findings)
		}
		unresolved := false
		for _, step := range result.Findings[0].Path {
			unresolved = unresolved || step.Type == "unresolved_dispatch"
		}
		if unresolved != multiple {
			t.Fatalf("multiple=%v unresolved=%v path=%+v", multiple, unresolved, result.Findings[0].Path)
		}
	}
}
