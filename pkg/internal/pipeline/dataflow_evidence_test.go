package pipeline

import (
	"context"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/dataflow"
	"mega-analyzer/pkg/internal/types"
)

func TestDataFlowRetainsFilesAcrossArrayHelperCalls(t *testing.T) {
	graph := dataflow.NewProgram(dataflow.DefaultConfig())
	graph.AddClass("smali/app/Source.smali", &types.SmaliClass{Name: "Lapp/Source;", Methods: []types.SmaliMethod{{
		Name: "read", Params: "Landroid/content/Intent;", ReturnType: "Ljava/lang/String;", Access: types.AccessPublic | types.AccessStatic,
		SourceRange: types.SourceRange{LineStart: 30}, Body: []string{
			`.locals 2`, `const-string v1, "command"`,
			`invoke-virtual {p0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;`,
			`move-result-object v0`, `return-object v0`,
		},
	}}})
	graph.AddClass("smali/app/Helper.smali", &types.SmaliClass{Name: "Lapp/Helper;", Methods: []types.SmaliMethod{{
		Name: "pack", Params: "Ljava/lang/String;", ReturnType: "[Ljava/lang/String;", Access: types.AccessPublic | types.AccessStatic,
		SourceRange: types.SourceRange{LineStart: 50}, Body: []string{
			`.locals 3`, `const-string v0, "sh"`, `const-string v1, "-c"`,
			`filled-new-array {v0, v1, p0}, [Ljava/lang/String;`, `move-result-object v2`, `return-object v2`,
		},
	}}})
	graph.AddClass("smali/app/Sink.smali", &types.SmaliClass{Name: "Lapp/Sink;", Methods: []types.SmaliMethod{{
		Name: "run", Params: "Landroid/content/Intent;Ljava/lang/Runtime;", ReturnType: "V", Access: types.AccessPublic | types.AccessStatic,
		SourceRange: types.SourceRange{LineStart: 70}, Body: []string{
			`.locals 1`, `invoke-static {p0}, Lapp/Source;->read(Landroid/content/Intent;)Ljava/lang/String;`, `move-result-object v0`,
			`invoke-static {v0}, Lapp/Helper;->pack(Ljava/lang/String;)[Ljava/lang/String;`, `move-result-object v0`,
			`invoke-virtual {p1, v0}, Ljava/lang/Runtime;->exec([Ljava/lang/String;)Ljava/lang/Process;`, `return-void`,
		},
	}}})
	p := &Pipeline{dataFlow: graph, result: types.NewAnalysisResult("fixture")}
	p.runDataFlow(context.Background())
	if len(p.result.DataFlows) != 1 {
		t.Fatalf("expected one array command flow, got %+v", p.result.DataFlows)
	}
	flow := p.result.DataFlows[0]
	item := typedFindingFromDataFlow(flow)
	if len(item.Steps) != len(flow.Path) || len(item.Steps) < 5 {
		t.Fatalf("report lost the evidence chain: %+v", item.Steps)
	}
	seen := make(map[string]bool)
	for _, step := range item.Steps {
		class := strings.TrimPrefix(strings.SplitN(step.Method, ";", 2)[0], "L")
		want := "smali/" + class + ".smali"
		if step.File != want || step.Line <= 0 {
			t.Errorf("wrong evidence location: %+v; want file %s", step, want)
		}
		seen[step.File] = true
	}
	if len(seen) != 3 || item.Steps[0].File != "smali/app/Source.smali" || item.Steps[0].Line != 32 ||
		item.Steps[len(item.Steps)-1].File != "smali/app/Sink.smali" || item.Steps[len(item.Steps)-1].Line != 75 {
		t.Fatalf("source/helper/sink locations are incomplete: %+v", item.Steps)
	}
}
