package dataflow

import (
	"context"
	"fmt"
	"testing"
)

func TestAuditPerSinkBudgetDoesNotStarveLaterSinks(t *testing.T) {
	config := DefaultConfig()
	config.MaxSliceSteps = 1000
	config.MaxSliceStepsPerSink = 8
	p := NewProgram(config)
	body := []string{`.locals 30`, `const-string v0, "fixed"`}
	for i := 1; i < 24; i++ {
		body = append(body, fmt.Sprintf("move-object v%d, v%d", i, i-1))
	}
	body = append(body, "invoke-virtual {v25, v23}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;", "return-void")
	addMethod(p, "Lapp/A;", "expensive", "", "V", true, body...)
	addMethod(p, "Lapp/Z;", "simple", "Landroid/content/Intent;", "V", true,
		`invoke-virtual {p0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;`,
		`move-result-object v0`,
		`invoke-virtual {v2, v0}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;`, "return-void")
	r := p.Analyze(context.Background())
	if !r.Stats.LimitReached || r.Stats.SlicesTruncated != 1 || r.Stats.SinksVisited != 2 {
		t.Fatalf("unreported fairness limit: %+v", r.Stats)
	}
	if len(r.Findings) != 1 || r.Findings[0].Location.Method != "Lapp/Z;->simple(Landroid/content/Intent;)V" {
		t.Fatalf("later simple sink starved: %+v", r.Findings)
	}
}
