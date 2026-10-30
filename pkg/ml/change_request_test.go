package ml

import (
	"strings"
	"testing"

	"mega-analyzer/pkg/ml/internal/shared"
)

// booleanFixture — минимальный boolean-метод с одним возвратом через invoke.
func booleanFixture() *shared.MethodInfo {
	return &shared.MethodInfo{
		Name:           "isRooted",
		ClassName:      "RootBeer",
		FilePath:       "com/example/RootBeer.smali",
		FullSignature:  "Lcom/example/RootBeer;->isRooted()Z",
		ReturnType:     "Z",
		ReturnsBoolean: true,
		MethodHeader:   ".method public isRooted()Z",
		RawBody: []string{
			".method public isRooted()Z",
			"    .registers 2",
			"    invoke-virtual {p0}, Lcom/example/RootBeer;->checkSu()Z",
			"    move-result v0",
			"    return v0",
			".end method",
		},
	}
}

func rootBypassSignal() VulnSignal {
	return VulnSignal{Kind: VulnRootDetectionBypass, Severity: "high", Confidence: 0.9}
}

// TestChangeRequestHonorsSignalOutcome — ядро P1#1: сигнал требует
// return_false, контекстные эвристики в defensive-режиме говорят return_true.
// Планировщик обязан выдать return_false, а не противоположный результат.
func TestChangeRequestHonorsSignalOutcome(t *testing.T) {
	mi := booleanFixture()
	signals := []VulnSignal{rootBypassSignal()}

	req, err := BuildChangeRequest(mi, PatchModeDefensive, signals)
	if err != nil {
		t.Fatalf("BuildChangeRequest: %v", err)
	}
	if req.Desired != PatchReturnFalse {
		t.Fatalf("Desired = %s, want %s", req.Desired, PatchReturnFalse)
	}

	legacy, err := NewConstantInjectionStrategy().Generate(mi, PatchModeDefensive)
	if err != nil {
		t.Fatalf("legacy Generate: %v", err)
	}
	t.Logf("legacy heuristic outcome: %s", legacy.PatchType)

	sel := NewStrategySelector()
	planned := sel.PlanPatch(req)
	if planned == nil || planned.Patch == nil {
		t.Fatal("planner returned no patch")
	}
	if planned.Patch.PatchType != PatchReturnFalse {
		t.Errorf("planner delivered %s, request wanted %s",
			planned.Patch.PatchType, PatchReturnFalse)
	}
	if planned.StrategyID == "" {
		t.Error("planner did not record producing strategy")
	}
}

// TestChangeRequestBothOutcomes — намерение течёт в обе стороны.
func TestChangeRequestBothOutcomes(t *testing.T) {
	mi := booleanFixture()
	sel := NewStrategySelector()
	for _, want := range []PatchType{PatchReturnTrue, PatchReturnFalse} {
		req := &ChangeRequest{
			Method: mi, Mode: PatchModeResearch, Desired: want,
			Evidence: BuildMethodEvidence(mi.RawBody, defaultSecurityMarkers()),
		}
		planned := sel.PlanPatch(req)
		if planned == nil || planned.Patch == nil {
			t.Fatalf("no patch for desired %s", want)
		}
		if planned.Patch.PatchType != want {
			t.Errorf("desired %s, delivered %s", want, planned.Patch.PatchType)
		}
	}
}

// TestChangeRequestConflict — противоречащие сигналы: отказ с объяснением,
// никакого молчаливого выбора по порядку.
func TestChangeRequestConflict(t *testing.T) {
	mi := booleanFixture()
	signals := []VulnSignal{
		{Kind: VulnRootDetectionBypass, Confidence: 0.9},
		{Kind: VulnPremiumFeatureGate, Confidence: 0.8},
	}
	req, err := BuildChangeRequest(mi, PatchModeResearch, signals)
	if err == nil {
		t.Fatal("expected conflict error, got nil")
	}
	if req.Desired != "" {
		t.Errorf("Desired = %s on conflict, want empty", req.Desired)
	}
	if len(req.Conflicting) != 2 {
		t.Errorf("Conflicting = %d signals, want 2", len(req.Conflicting))
	}
	// Конфликт требует отказа: legacy-путь не имеет права угадывать исход.
	pg := NewPatchGenerator()
	point := &PatchPoint{
		MethodName:      "isRooted",
		MethodSignature: "Lcom/example/RootBeer;->isRooted()Z",
		ReturnType:      "Z",
		MethodBody:      mi.RawBody,
		MethodHeader:    mi.MethodHeader,
		VulnSignals:     &VulnerabilitySignals{Signals: signals},
	}
	patch := pg.GenerateWithMode(point, PatchModeResearch)
	if patch != nil {
		t.Fatal("conflicting signals must not generate a legacy fallback patch")
	}
}

// TestVerifyPatchAgainstRequest — контракт: несоответствие отвергается.
func TestVerifyPatchAgainstRequest(t *testing.T) {
	req := &ChangeRequest{Desired: PatchReturnFalse, Method: booleanFixture()}
	bad := &GeneratedPatch{PatchedCode: "const/4 v0, 0x1\nreturn v0", PatchType: PatchReturnTrue, MethodName: "isRooted"}
	if err := VerifyPatchAgainstRequest(req, bad); err == nil {
		t.Error("expected contract mismatch error, got nil")
	} else if !strings.Contains(err.Error(), "contract mismatch") {
		t.Errorf("unexpected error: %v", err)
	}
	good := &GeneratedPatch{PatchedCode: "const/4 v0, 0x0\nreturn v0", PatchType: PatchReturnFalse, MethodName: "isRooted"}
	if err := VerifyPatchAgainstRequest(req, good); err != nil {
		t.Errorf("valid patch rejected: %v", err)
	}
}

// TestEvidenceSelectsTarget — P1#2: цель выбирается по данным (invoke→
// move-result→if), а не по текстовой близости.
func TestEvidenceSelectsTarget(t *testing.T) {
	body := []string{
		".method public isRooted()Z",
		"    .registers 2",
		"    invoke-virtual {p0}, Lcom/example/RootBeer;->checkSu()Z",
		"    move-result v0",
		"    if-eqz v0, :cond_1",
		"    const/4 v0, 0x1",
		"    return v0",
		"    :cond_1",
		"    const/4 v0, 0x0",
		"    return v0",
		".end method",
	}
	ev := BuildMethodEvidence(body, defaultSecurityMarkers())
	if !ev.HasCFG || !ev.HasDFG {
		t.Fatalf("evidence missing CFG/DFG: %+v", ev)
	}
	if ev.TargetInstruction != 4 {
		t.Errorf("TargetInstruction = %d, want 4 (the if-eqz line)", ev.TargetInstruction)
	}
	if ev.TargetReason == "" {
		t.Error("target selected without reason")
	}
}

// TestEvidenceAmbiguousRefuses — две поддержанные проверки: отказ, не угадайка.
func TestEvidenceAmbiguousRefuses(t *testing.T) {
	body := []string{
		".method public checkBoth()Z",
		"    .registers 3",
		"    invoke-static {}, LA;->checkA()Z",
		"    move-result v0",
		"    if-eqz v0, :no",
		"    invoke-static {}, LB;->checkB()Z",
		"    move-result v1",
		"    if-eqz v1, :no",
		"    const/4 v0, 0x1",
		"    return v0",
		"    :no",
		"    const/4 v0, 0x0",
		"    return v0",
		".end method",
	}
	ev := BuildMethodEvidence(body, defaultSecurityMarkers())
	if ev.TargetInstruction != NoTargetInstruction {
		t.Errorf("ambiguous target must be refused, got line %d", ev.TargetInstruction)
	}
	if !strings.Contains(ev.InsufficientEvidence, "ambiguous") {
		t.Errorf("refusal unexplained: %q", ev.InsufficientEvidence)
	}
}

// TestEvidenceHardcodedNoSupport — проверка локальной константы не имеет
// поддержки данными.
func TestEvidenceHardcodedNoSupport(t *testing.T) {
	body := []string{
		".method public hardcoded()Z",
		"    .registers 2",
		"    const/4 v0, 0x1",
		"    if-eqz v0, :no",
		"    const/4 v0, 0x1",
		"    return v0",
		"    :no",
		"    const/4 v0, 0x0",
		"    return v0",
		".end method",
	}
	ev := BuildMethodEvidence(body, defaultSecurityMarkers())
	if ev.TargetInstruction != NoTargetInstruction {
		t.Errorf("hardcoded check must have no target, got line %d", ev.TargetInstruction)
	}
}

// TestInversionSkipsNullCheck — P1#2: соседняя техническая null-проверка
// сохраняет поведение и фиксируется в SkippedLines.
func TestInversionSkipsNullCheck(t *testing.T) {
	mi := &shared.MethodInfo{
		Name:           "validate",
		ClassName:      "Validator",
		FilePath:       "com/example/Validator.smali",
		ReturnsBoolean: true,
		ReturnType:     "Z",
		IfCheckCount:   2,
		HasDualReturn:  true,
		MethodHeader:   ".method public validate(Ljava/lang/Object;)Z",
		RawBody: []string{
			".method public validate(Ljava/lang/Object;)Z",
			"    .registers 3",
			"    invoke-virtual {p0, p1}, Lcom/example/Validator;->load()Ljava/lang/Object;",
			"    move-result-object v0",
			"    if-eqz v0, :null",
			"    invoke-virtual {p0}, Lcom/example/Validator;->check()Z",
			"    move-result v1",
			"    if-eqz v1, :bad",
			"    const/4 v0, 0x1",
			"    return v0",
			"    :null",
			"    :bad",
			"    const/4 v0, 0x0",
			"    return v0",
			".end method",
		},
	}
	patch, err := NewConditionInversionStrategy().Generate(mi, PatchModeResearch)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// Строка null-проверки (индекс 4) обязана остаться как была.
	origNull := strings.TrimSpace(mi.RawBody[4])
	found := false
	for _, line := range strings.Split(patch.PatchedCode, "\n") {
		if strings.TrimSpace(line) == origNull {
			found = true
		}
	}
	if !found {
		t.Errorf("null check %q was inverted; technical checks must keep behavior", origNull)
	}
	if len(patch.SkippedLines) != 1 || patch.SkippedLines[0] != 4 {
		t.Errorf("SkippedLines = %v, want [4]", patch.SkippedLines)
	}
	if len(patch.ModifiedLines) != 1 || patch.ModifiedLines[0] != 7 {
		t.Errorf("ModifiedLines = %v, want [7]", patch.ModifiedLines)
	}
}

// TestRequiresCFGGate — P1#2: стратегия с RequiresCFG недопустима без
// свидетельства CFG.
func TestRequiresCFGGate(t *testing.T) {
	mi := &shared.MethodInfo{
		Name: "isRooted", ReturnsBoolean: true, ReturnType: "Z",
		HasDualReturn: true, IfCheckCount: 1,
		RawBody: []string{
			".method public isRooted()Z",
			"    invoke-static {}, LA;->c()Z",
			"    move-result v0",
			"    if-eqz v0, :no",
			"    const/4 v0, 0x1",
			"    return v0",
			"    :no",
			"    const/4 v0, 0x0",
			"    return v0",
			".end method",
		},
	}
	req := &ChangeRequest{Method: mi, Mode: PatchModeResearch} // пустое Evidence
	a := assessStrategyWithRequest(NewConditionInversionStrategy(), req)
	if a.Applicable {
		t.Error("condition inversion applicable without CFG evidence")
	}
	found := false
	for _, r := range a.Reasons {
		if r == "requires_cfg_evidence_unavailable" {
			found = true
		}
	}
	if !found {
		t.Errorf("missing gate reason, got %v", a.Reasons)
	}
}

// TestPlannerKeepsAlternatives — P2#6: кандидаты и причины отсева сохраняются.
func TestPlannerKeepsAlternatives(t *testing.T) {
	mi := booleanFixture()
	req, err := BuildChangeRequest(mi, PatchModeResearch, []VulnSignal{rootBypassSignal()})
	if err != nil {
		t.Fatalf("BuildChangeRequest: %v", err)
	}
	planned := NewStrategySelector().PlanPatch(req)
	if planned == nil || planned.Patch == nil {
		t.Fatal("planner returned no patch")
	}
	if len(planned.Candidates) == 0 {
		t.Fatal("planner kept no candidates")
	}
	chosen := 0
	for _, c := range planned.Candidates {
		if c.Strategy == planned.Strategy {
			chosen++
			if c.DropReason != "" {
				t.Errorf("chosen candidate dropped: %s", c.DropReason)
			}
		}
	}
	if chosen != 1 {
		t.Errorf("chosen strategy appears %d times in candidates", chosen)
	}
}

// TestHasDualReturnShapes — P2#8: одинаковые возвраты не доказывают два исхода.
func TestHasDualReturnShapes(t *testing.T) {
	same := []string{
		".method public f()Z",
		"    const/4 v0, 0x1",
		"    return v0",
		"    return v0",
		".end method",
	}
	if hasDualReturnShapes(same) {
		t.Error("two identical returns reported as dual outcome")
	}
	different := []string{
		".method public f()Z",
		"    const/4 v0, 0x1",
		"    return v0",
		"    return-void",
		".end method",
	}
	if !hasDualReturnShapes(different) {
		t.Error("distinct return shapes not reported as dual outcome")
	}
	pg := NewPatchGenerator()
	mi := pg.patchPointToMethodInfo(&PatchPoint{MethodBody: same})
	if mi.HasDualReturn {
		t.Error("patchPointToMethodInfo: identical returns imply dual outcome")
	}
}

// TestUseDefPathsWarning — P2#8: чтение регистра, не определённого на одном
// из входящих путей, выявляется предупреждением.
func TestUseDefPathsWarning(t *testing.T) {
	branchy := strings.Join([]string{
		".method public f(Z)Z",
		"    .registers 3",
		"    if-eqz p1, :other",
		"    const/4 v0, 0x1",
		"    :other",
		"    return v0",
		".end method",
	}, "\n")
	res := preflightBodyStructure(branchy, branchy)
	found := false
	for _, w := range res.Warnings {
		if strings.Contains(w, "possibly undefined on some path") && strings.Contains(w, "v0") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected possibly-undefined warning for v0, got %v", res.Warnings)
	}

	clean := strings.Join([]string{
		".method public f(Z)Z",
		"    .registers 3",
		"    const/4 v0, 0x0",
		"    if-eqz p1, :other",
		"    const/4 v0, 0x1",
		"    :other",
		"    return v0",
		".end method",
	}, "\n")
	resClean := preflightBodyStructure(clean, clean)
	for _, w := range resClean.Warnings {
		if strings.Contains(w, "possibly undefined on some path") {
			t.Errorf("false positive path warning: %s", w)
		}
	}
}

// TestStrategyOutcomeDedup — P2#7: повтор не увеличивает вес; исходы двух
// правок различаются; неизвестное не считается успехом.
func TestStrategyOutcomeDedup(t *testing.T) {
	fc := NewFeedbackCollector()
	mk := func(patch string, goal OutcomeState) *StrategyOutcome {
		return &StrategyOutcome{
			StrategyID: "constant_injection", GeneratorVersion: PlannerVersion,
			SourceHash: hashText("orig"), PatchHash: hashText(patch),
			TargetID: "m()Z", Detection: OutcomeUnverified,
			Build: OutcomePass, Goal: goal, Regressions: OutcomeUnverified,
		}
	}
	if !fc.RecordStrategyOutcome(mk("patched-a", OutcomePass)) {
		t.Fatal("first record rejected")
	}
	if fc.RecordStrategyOutcome(mk("patched-a", OutcomePass)) {
		t.Error("duplicate record accepted, weight would double")
	}
	if !fc.RecordStrategyOutcome(mk("patched-b", OutcomeFail)) {
		t.Fatal("distinct patch rejected")
	}
	st := fc.GetStrategyStats("constant_injection")
	if st.Outcomes != 2 {
		t.Errorf("Outcomes = %d, want 2", st.Outcomes)
	}
	if st.Duplicates != 1 {
		t.Errorf("Duplicates = %d, want 1", st.Duplicates)
	}
	if st.GoalPass != 1 || st.GoalFail != 1 {
		t.Errorf("GoalPass/Fail = %d/%d, want 1/1", st.GoalPass, st.GoalFail)
	}
	if st.BuildPass != 2 {
		t.Errorf("BuildPass = %d, want 2", st.BuildPass)
	}
}
