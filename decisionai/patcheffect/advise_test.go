package patcheffect

import (
	"strings"
	"testing"

	"decisionai/engine"
	"decisionai/smalirole"
)

func withAdvisor(t *testing.T, ctx func(string) *smalirole.Ctx) {
	old := engine.PatchAdvisor
	engine.PatchAdvisor = Advisor(model(t), ctx)
	t.Cleanup(func() { engine.PatchAdvisor = old })
}

func req(code string, line int, before, after int64) engine.Request {
	return engine.Request{ID: "t", Code: code, State: map[string]any{}, Scope: "defensive",
		Meta:  engine.Meta{AppOwned: true, Evidence: []string{}},
		Patch: &engine.PatchRequest{Line: line, Expected: before, Replacement: after}}
}

const delay = ".method public start(Landroid/os/Handler;Ljava/lang/Runnable;)V\n.registers 5\nconst-wide/16 v0, 0x1f4\ninvoke-virtual {p1, p2, v0, v1}, Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z\nreturn-void\n.end method"

func TestAdvisorExplainsPlan(t *testing.T) {
	withAdvisor(t, nil)
	thr := engine.Thresholds{Finding: 0, Patch: 0}
	r := req(delay, 3, 500, 100)
	r.Threshold = &thr
	rep, err := engine.Analyze(r, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	// engine's own planner cannot rewrite const-wide; the advisor's wide plan is used.
	if rep.Plan == nil || !strings.Contains(rep.Plan.Patched, "0x64") && !strings.Contains(rep.Plan.Patched, "100") {
		t.Fatalf("plan=%+v reasons=%v", rep.Plan, rep.Reasons)
	}
	if rep.Advice == nil || rep.Advice.Role != "duration_ms" || rep.Advice.ChangeKind != "lower_duration" {
		t.Fatalf("advice=%+v", rep.Advice)
	}
	if strings.Contains(rep.Plan.Explanation, "не установлены") || !strings.Contains(rep.Plan.Explanation, "длительност") {
		t.Fatal(rep.Plan.Explanation)
	}
	if rep.Decision != "candidate_for_review" {
		t.Fatalf("decision=%s reasons=%v", rep.Decision, rep.Reasons)
	}
}

func TestAdvisorBlocksCancelledPatch(t *testing.T) {
	withAdvisor(t, nil)
	code := ".method public static f()I\n.registers 2\nconst/16 v0, 0x32\nconst/16 v1, 0x32\ninvoke-static {v0, v1}, Ljava/lang/Math;->min(II)I\nmove-result v0\nreturn v0\n.end method"
	thr := engine.Thresholds{Finding: 0, Patch: 0}
	r := req(code, 3, 50, 99)
	r.Threshold = &thr
	rep, _ := engine.Analyze(r, nil, nil)
	if rep.Decision != "blocked" || rep.Advice == nil || rep.Advice.Verdict != "blocked" {
		t.Fatalf("decision=%s advice=%+v", rep.Decision, rep.Advice)
	}
}

func TestAdvisorNeverLoosens(t *testing.T) {
	withAdvisor(t, nil)
	r := req(delay, 3, 500, 100)
	r.Meta.Library = true
	rep, _ := engine.Analyze(r, nil, nil)
	if rep.Decision != "blocked" {
		t.Fatal(rep.Decision)
	}
}

// With an app index the advisor follows a static field into another class.
func TestAdvisorUsesAppFields(t *testing.T) {
	cfg := ".method static constructor <clinit>()V\n.registers 2\nconst-wide/16 v0, 0x7d0\nsput-wide v0, Lcom/x/Cfg;->RETRY:J\nreturn-void\n.end method"
	user := ".method public run(Landroid/os/Handler;Ljava/lang/Runnable;)V\n.registers 5\nsget-wide v0, Lcom/x/Cfg;->RETRY:J\ninvoke-virtual {p1, p2, v0, v1}, Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z\nreturn-void\n.end method"
	app := &smalirole.App{Methods: map[string]*smalirole.Method{}, Reads: map[string][]smalirole.FieldRead{}}
	app.Add(smalirole.ParseMethod("Lcom/x/Cfg;", cfg))
	app.Add(smalirole.ParseMethod("Lcom/x/Job;", user))
	if c := app.Locate(cfg); c != "Lcom/x/Cfg;" {
		t.Fatalf("locate=%q", c)
	}
	withAdvisor(t, func(string) *smalirole.Ctx { return app.Ctx() })
	rep, _ := engine.Analyze(req(cfg, 3, 2000, 500), nil, nil)
	if rep.Advice == nil || rep.Advice.Role != "duration_ms" {
		t.Fatalf("advice=%+v", rep.Advice)
	}
}

// A constructor default that onCreate overwrites: the patch is very likely useless.
func TestFieldOverwrittenDefault(t *testing.T) {
	ctor := ".method public constructor <init>()V\n.registers 3\ninvoke-direct {p0}, Landroid/app/Activity;-><init>()V\nconst-wide/16 v0, 0x0\niput-wide v0, p0, Lcom/x/Splash;->timeout:J\nreturn-void\n.end method"
	onCreate := ".method protected onCreate(Landroid/os/Bundle;)V\n.registers 4\nconst-wide/16 v0, 0x3e8\niput-wide v0, p0, Lcom/x/Splash;->timeout:J\nreturn-void\n.end method"
	onResume := ".method protected onResume()V\n.registers 5\nnew-instance v0, Ljava/util/Timer;\nnew-instance v1, Lcom/x/Task;\niget-wide v2, p0, Lcom/x/Splash;->timeout:J\ninvoke-virtual {v0, v1, v2, v3}, Ljava/util/Timer;->schedule(Ljava/util/TimerTask;J)V\nreturn-void\n.end method"
	app := &smalirole.App{Methods: map[string]*smalirole.Method{}, Reads: map[string][]smalirole.FieldRead{}}
	for _, c := range []string{ctor, onCreate, onResume} {
		app.Add(smalirole.ParseMethod("Lcom/x/Splash;", c))
	}
	r, err := AnalyzeCtx(Request{Code: ctor, Class: app.Locate(ctor), Line: 4, Expected: 0, Replacement: 3000, AppOwned: true}, model(t), app.Ctx())
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Overwrites) != 1 || !r.Overwrites[0].DefaultOnly || r.Success.Probability > 0.45 || r.Effort.Level == "trivial" {
		t.Fatalf("ow=%+v p=%.2f effort=%s", r.Overwrites, r.Success.Probability, r.Effort.Level)
	}
	if r.Role.Answer != "duration_ms" || !strings.Contains(r.WhatItDoes, "перезаписывается") {
		t.Fatalf("%s: %s", r.Role.Answer, r.WhatItDoes)
	}
	if a := ToAdvice(0, 3000, r); a.Verdict != "review" {
		t.Fatal(a.Verdict)
	}
}
