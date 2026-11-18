package patcheffect

import (
	"strings"
	"testing"

	"decisionai/smalirole"
)

const clamped = ".method public static maxItems()I\n    .registers 2\n    const/16 v0, 0xa\n    const/16 v1, 0x32\n    if-le v0, v1, :cond_0\n    move v0, v1\n    :cond_0\n    return v0\n.end method"

func model(t *testing.T) *smalirole.Model {
	m, err := smalirole.LoadModel("../models/smalirole-model.json")
	if err != nil {
		t.Skip("no bundled model")
	}
	return m
}

func TestClampCutsValue(t *testing.T) {
	r, err := Analyze(Request{Code: clamped, Line: 3, Expected: 10, Replacement: 100, AppOwned: true}, model(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Effective == nil || *r.Effective != 50 {
		t.Fatalf("effective = %v, want 50", r.Effective)
	}
	if r.Success.Probability > 0.4 || r.Success.Band != "partial" {
		t.Fatalf("success %.2f %s", r.Success.Probability, r.Success.Band)
	}
	if !strings.Contains(r.WhatItDoes, "фактически получится 50") {
		t.Fatal(r.WhatItDoes)
	}
	if r.Effort.Level == "trivial" {
		t.Fatal("clamp needs a second edit")
	}
}

func TestClampWithinBounds(t *testing.T) {
	r, _ := Analyze(Request{Code: clamped, Line: 3, Expected: 10, Replacement: 30, AppOwned: true}, model(t), nil)
	if r.Effective == nil || *r.Effective != 30 || r.Success.Probability > 0.9 || r.Success.Band != "high" {
		t.Fatalf("eff=%v p=%.2f band=%s", r.Effective, r.Success.Probability, r.Success.Band)
	}
}

func TestClampCancelsPatch(t *testing.T) {
	code := ".method public static f()I\n.registers 2\nconst/16 v0, 0x32\nconst/16 v1, 0x32\ninvoke-static {v0, v1}, Ljava/lang/Math;->min(II)I\nmove-result v0\nreturn v0\n.end method"
	r, _ := Analyze(Request{Code: code, Line: 3, Expected: 50, Replacement: 99, AppOwned: true}, model(t), nil)
	if r.Effective == nil || *r.Effective != 50 {
		t.Fatalf("eff=%v clamps=%v", r.Effective, r.Clamps)
	}
	found := false
	for _, f := range r.Success.Factors {
		if f.Name == "clamp_cancels" {
			found = true
		}
	}
	if !found || r.Success.Probability > 0.2 {
		t.Fatalf("p=%.2f factors=%v", r.Success.Probability, r.Success.Factors)
	}
}

func TestUnusedValueLow(t *testing.T) {
	code := ".method public foo()V\n.registers 2\nconst/16 v0, 0xa\nreturn-void\n.end method"
	r, _ := Analyze(Request{Code: code, Line: 3, Expected: 10, Replacement: 20, AppOwned: true}, model(t), nil)
	if r.Success.Band != "low" {
		t.Fatalf("unused const should be low, got %.2f", r.Success.Probability)
	}
}

func TestBooleanEnable(t *testing.T) {
	code := ".method public isPremium()Z\n.registers 2\nconst/4 v0, 0x0\nreturn v0\n.end method"
	r, _ := Analyze(Request{Code: code, Line: 3, Expected: 0, Replacement: 1, AppOwned: true}, model(t), nil)
	if r.ChangeKind != "enable" || r.Success.Band != "high" || r.Effort.Level != "trivial" {
		t.Fatalf("kind=%s band=%s effort=%s", r.ChangeKind, r.Success.Band, r.Effort.Level)
	}
}

func TestServerDependencyLowers(t *testing.T) {
	code := ".method public isPremium()Z\n.registers 2\nconst/4 v0, 0x0\nreturn v0\n.end method"
	a, _ := Analyze(Request{Code: code, Line: 3, Expected: 0, Replacement: 1, AppOwned: true}, model(t), nil)
	b, _ := Analyze(Request{Code: code, Line: 3, Expected: 0, Replacement: 1, AppOwned: true, ServerDependency: true}, model(t), nil)
	if !(b.Success.Probability < a.Success.Probability) {
		t.Fatalf("server dep should lower: %.2f vs %.2f", b.Success.Probability, a.Success.Probability)
	}
}

func TestStaleLiteralBlocked(t *testing.T) {
	r, _ := Analyze(Request{Code: clamped, Line: 3, Expected: 11, Replacement: 20, AppOwned: true}, model(t), nil)
	if len(r.Blocked) == 0 || r.Plan != nil {
		t.Fatal("stale literal must block")
	}
}

func TestWideDelayPatch(t *testing.T) {
	code := ".method private s()V\n    .registers 5\n    iget-object v1, p0, Lcom/app/Main;->handler:Landroid/os/Handler;\n    const/4 v0, 0x0\n    const-wide/16 v2, 0x1388\n    invoke-virtual {v1, v0, v2, v3}, Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z\n    return-void\n.end method"
	r, err := Analyze(Request{Code: code, Line: 5, Expected: 5000, Replacement: 100000, AppOwned: true}, model(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Plan == nil || !strings.Contains(r.Plan.Patched, "const-wide/32 v2, 0x186a0") || len(r.Blocked) > 0 {
		t.Fatalf("plan=%v blocked=%v", r.Plan, r.Blocked)
	}
	if r.ChangeKind != "raise_duration" || !strings.Contains(r.WhatItDoes, "5 с → 1.67 мин") {
		t.Fatalf("%s | %s", r.ChangeKind, r.WhatItDoes)
	}
	if r.Plan.Validation.Status == "fail" {
		t.Fatal(r.Plan.Validation.Issues)
	}
}
