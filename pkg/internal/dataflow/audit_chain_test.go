package dataflow

import (
	"context"
	"mega-analyzer/pkg/internal/types"
	"testing"
)

func TestAuditOverwrittenParameterIsNotAnIPCSource(t *testing.T) {
	p := NewProgram(DefaultConfig())
	addMethod(p, "Lapp/Receiver;", "onNewIntent", "Landroid/content/Intent;", "V", false,
		".registers 2", "const/4 p1, 0x0",
		"invoke-virtual {p0, p1}, Landroid/app/Activity;->startActivity(Landroid/content/Intent;)V", "return-void")
	if f := p.Analyze(context.Background()).Findings; len(f) != 0 {
		t.Fatalf("overwritten parameter tainted: %+v", f)
	}
}
func TestAuditPhysicalRegisterAliasesReachIPCParameter(t *testing.T) {
	p := NewProgram(DefaultConfig())
	addMethod(p, "Lapp/Receiver;", "onNewIntent", "Landroid/content/Intent;", "V", false,
		".registers 5", "invoke-virtual {v3, v4}, Landroid/app/Activity;->startActivity(Landroid/content/Intent;)V", "return-void")
	if f := p.Analyze(context.Background()).Findings; len(f) != 1 {
		t.Fatalf("v4=p1 alias missed: %+v", f)
	}
}
func TestAuditCallsiteReturnBindingDoesNotMixCallers(t *testing.T) {
	p := NewProgram(DefaultConfig())
	addMethod(p, "Lapp/Helper;", "identity", "Ljava/lang/String;", "Ljava/lang/String;", true, "return-object p0")
	addMethod(p, "Lapp/Entry;", "unsafe", "Landroid/content/Intent;", "V", true,
		"invoke-virtual {p0, v9}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;", "move-result-object v0",
		"invoke-static {v0}, Lapp/Helper;->identity(Ljava/lang/String;)Ljava/lang/String;", "move-result-object v1",
		"invoke-virtual {v9, v1}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;", "return-void")
	addMethod(p, "Lapp/Entry;", "safe", "", "V", true,
		"const-string v0, \"fixed\"", "invoke-static {v0}, Lapp/Helper;->identity(Ljava/lang/String;)Ljava/lang/String;", "move-result-object v1",
		"invoke-virtual {v9, v1}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;", "return-void")
	f := p.Analyze(context.Background()).Findings
	if len(f) != 1 || f[0].Location.Method != "Lapp/Entry;->unsafe(Landroid/content/Intent;)V" {
		t.Fatalf("call sites contaminated: %+v", f)
	}
}
func TestAuditSameSourceAndSinkRetainDifferentCategories(t *testing.T) {
	p := NewProgram(DefaultConfig())
	addMethod(p, "Lapp/Entry;", "send", "", "V", true,
		"invoke-virtual {v9, v8}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;", "move-result-object v0",
		"invoke-virtual {v9, v0}, Landroid/content/Context;->sendBroadcast(Landroid/content/Intent;)V", "return-void")
	r := p.Analyze(context.Background())
	// Verify each applicable catalog category can survive the same source/sink key.
	models := sinksFor("Landroid/content/Context;->sendBroadcast(Landroid/content/Intent;)V")
	expected := map[string]bool{}
	for _, model := range models {
		if model.labels&(LabelIntent|LabelUserInput) != 0 {
			expected[model.category] = true
		}
	}
	found := map[string]bool{}
	for _, f := range r.Findings {
		found[f.Category] = true
	}
	for c := range expected {
		if !found[c] {
			t.Errorf("lost category %s: %+v", c, r.Findings)
		}
	}
}
func TestAuditDescriptorStartingWithLIsNotTruncated(t *testing.T) {
	if s := normalizeClassDescriptor("Local.app.Type"); s != "LLocal/app/Type;" {
		t.Fatalf("descriptor=%s", s)
	}
}
func TestAuditCancelledProgramDoesNotIndexWholeInput(t *testing.T) {
	p := NewProgram(DefaultConfig())
	p.AddClass("A.smali", &types.SmaliClass{Name: "Lapp/A;", Methods: []types.SmaliMethod{{Name: "a", ReturnType: "V", Body: []string{"return-void"}}}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if r := p.Analyze(ctx); !r.Stats.LimitReached {
		t.Fatal("cancelled result must be explicitly incomplete")
	}
}
