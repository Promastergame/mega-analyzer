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

// TestAuditPrioritySchedulingProtectsCriticalSinks reproduces the 2026-11-03
// corpus failure: file-order tracing let many low-value log sinks drain the
// whole-run step budget before the critical sink in a later file was traced.
// Sink-rank scheduling must trace critical sinks first, so the starved
// remainder is the least sensitive work.
func TestAuditPrioritySchedulingProtectsCriticalSinks(t *testing.T) {
	config := DefaultConfig()
	config.MaxSliceSteps = 1000
	config.MaxSliceStepsPerSink = 400
	p := NewProgram(config)

	// Lapp/A sorts before Lapp/Z and holds 30 log sinks, each behind a
	// 100-instruction move chain: ~3000 steps of medium-value work.
	body := []string{`.locals 130`,
		"invoke-virtual {p0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;",
		"move-result-object v0"}
	for i := 1; i <= 100; i++ {
		body = append(body, fmt.Sprintf("move-object v%d, v%d", i, i-1))
	}
	for i := 0; i < 30; i++ {
		body = append(body, "invoke-static {v101, v102}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I")
	}
	body = append(body, "return-void")
	addMethod(p, "Lapp/A;", "noisy", "Landroid/content/Intent;", "V", true, body...)

	addMethod(p, "Lapp/Z;", "simple", "Landroid/content/Intent;", "V", true,
		"invoke-virtual {p0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;",
		"move-result-object v0",
		"invoke-virtual {v2, v0}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;", "return-void")

	r := p.Analyze(context.Background())
	if !r.Stats.LimitReached {
		t.Fatalf("expected the run budget to be reported as reached: %+v", r.Stats)
	}
	for _, f := range r.Findings {
		if f.Category == "command_injection" && f.Location.Method == "Lapp/Z;->simple(Landroid/content/Intent;)V" {
			return // the critical sink was traced despite the noisy prefix
		}
	}
	t.Fatalf("critical sink starved behind %d low-value sink(s): visited=%d truncated=%d findings=%+v",
		30, r.Stats.SinksVisited, r.Stats.SlicesTruncated, r.Findings)
}
