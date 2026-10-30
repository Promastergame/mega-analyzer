package pipeline

import (
	"context"
	"mega-analyzer/pkg/internal/dataflow"
	"mega-analyzer/pkg/internal/types"
	"testing"
)

func TestDataFlowV2MainPipelineUsesCFGAndKeepsObservations(t *testing.T) {
	graph := dataflow.NewProgram(dataflow.DefaultConfig())
	graph.AddClass("fixture.smali", &types.SmaliClass{Name: "Lfixture/MainIntegration;", Methods: []types.SmaliMethod{{
		Name: "run", Params: "ZLandroid/content/Intent;", ReturnType: "V", Access: types.AccessPublic | types.AccessStatic, SourceRange: types.SourceRange{LineStart: 1},
		Body: []string{`.locals 3`, `const-string v1, "input"`, `invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;`, `move-result-object v2`,
			`if-eqz p0, :safe`, `invoke-virtual {p1, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;`, `move-result-object v0`, `goto :join`,
			`:safe`, `const-string v0, "fixed"`, `:join`, `invoke-virtual {v2, v0}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;`,
			`invoke-static {v1, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I`, `return-void`},
	}}})
	p := &Pipeline{dataFlow: graph, result: types.NewAnalysisResult("fixture")}
	p.runDataFlow(context.Background())
	if len(p.result.DataFlows) != 1 || p.result.DataFlows[0].Category != "command_injection" {
		t.Fatalf("main pipeline lost branch-derived command flow: %+v", p.result.DataFlows)
	}
	if len(p.result.DataFlowObservations) != 1 || p.result.DataFlowObservations[0].Category != "untrusted_log_input" {
		t.Fatalf("ordinary input incorrectly promoted to sensitive leakage: %+v", p.result.DataFlowObservations)
	}
	if p.result.DataFlowStats.CFGNodes == 0 || p.result.DataFlowStats.InformationalFlows != 1 {
		t.Fatalf("main pipeline dropped diagnostics: %+v", p.result.DataFlowStats)
	}
}
