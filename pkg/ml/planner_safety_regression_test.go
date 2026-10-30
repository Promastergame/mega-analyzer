package ml

import (
	"errors"
	"strings"
	"testing"

	"mega-analyzer/pkg/ml/internal/shared"
)

// Synthetic, local-only fixture: no APKs or external applications are changed.
func plannerSafetyMethod() *shared.MethodInfo {
	return &shared.MethodInfo{
		Name:          "value",
		FullSignature: "Ltest/Fixture;->value()I",
		FilePath:      "test/Fixture.smali",
		ReturnType:    "I",
		ReturnsInt:    true,
		IsStatic:      true,
		MethodHeader:  ".method public static value()I",
		RawBody: []string{
			".method public static value()I",
			"    .locals 1",
			"    const/4 v0, 0x1",
			"    :keep",
			"    return v0",
			".end method",
		},
	}
}

type plannerSafetyStrategy struct {
	id       string
	priority int
	code     string
	decline  bool
	err      error
	calls    int
}

func (s *plannerSafetyStrategy) CanApply(*shared.MethodInfo, PatchMode) bool {
	return !s.decline
}

func (s *plannerSafetyStrategy) Generate(mi *shared.MethodInfo, mode PatchMode) (*GeneratedPatch, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return &GeneratedPatch{
		OriginalCode:      strings.Join(mi.RawBody, "\n"),
		PatchedCode:       s.code,
		PatchType:         PatchConstReplace,
		MethodName:        mi.Name,
		MethodSignature:   mi.FullSignature,
		FilePath:          mi.FilePath,
		Mode:              mode,
		TargetInstruction: NoTargetInstruction,
	}, nil
}

func (s *plannerSafetyStrategy) GetPriority() int {
	return s.priority
}

func (s *plannerSafetyStrategy) PatchType() PatchType {
	return PatchConstReplace
}

func (s *plannerSafetyStrategy) GetDescription() string {
	return s.id
}
func (s *plannerSafetyStrategy) Metadata() StrategyMetadata {
	return StrategyMetadata{ID: s.id, PreservesControlFlow: true}
}

func TestPlannerSafetyConflictsFailClosed(t *testing.T) {
	mi := plannerSafetyMethod()
	signals := []VulnSignal{
		{Kind: VulnRootDetectionBypass},
		{Kind: VulnPremiumFeatureGate},
	}
	for _, reversed := range []bool{false, true} {
		if reversed {
			signals[0], signals[1] = signals[1], signals[0]
		}
		req, err := BuildChangeRequest(mi, PatchModeResearch, signals)
		if err == nil {
			t.Fatal("contradictory request accepted")
		}
		strategy := &plannerSafetyStrategy{id: "must-not-run", code: strings.Join(mi.RawBody, "\n")}
		selector := &StrategySelector{strategies: []PatchStrategy{strategy}}
		plan := selector.PlanPatch(req)
		if plan.Patch != nil || plan.RejectionReason != DropInvalidRequest || strategy.calls != 0 {
			t.Fatalf("conflict reached generation: %+v", plan)
		}
		if len(selector.RankStrategies(mi, PatchModeResearch, signals)) != 0 ||
			selector.SelectStrategyWithSignals(mi, PatchModeResearch, signals) != nil {
			t.Fatal("legacy selector guessed a conflicting intent")
		}
		if _, _, err := selector.GenerateBest(mi, PatchModeResearch, signals); err == nil {
			t.Fatal("GenerateBest discarded request error")
		}
		if _, err := generateWithRequest(strategy, req); err == nil || strategy.calls != 0 {
			t.Fatal("direct request generation bypassed conflict check")
		}
		point := &PatchPoint{
			MethodName: mi.Name, MethodSignature: mi.FullSignature, FilePath: mi.FilePath,
			MethodHeader: mi.MethodHeader, MethodBody: mi.RawBody, ReturnType: mi.ReturnType,
			VulnSignals: &VulnerabilitySignals{Signals: signals},
		}
		generator := NewPatchGenerator()
		if generator.GenerateWithMode(point, PatchModeResearch) != nil || generator.Generate(point) != nil {
			t.Fatal("generator used a legacy fallback after a conflict")
		}
	}
}

func TestPlannerSafetyStructuralFailureTriesNext(t *testing.T) {
	mi := plannerSafetyMethod()
	original := strings.Join(mi.RawBody, "\n")
	bad := &plannerSafetyStrategy{
		id: "removes-label", priority: 100,
		code: strings.ReplaceAll(strings.ReplaceAll(original, "0x1", "0x2"), "    :keep\n", ""),
	}
	good := &plannerSafetyStrategy{id: "keeps-structure", priority: 90, code: strings.ReplaceAll(original, "0x1", "0x3")}
	declined := &plannerSafetyStrategy{id: "declined", priority: 200, decline: true}
	if validation := NewSmaliValidator().ValidateStrict(bad.code); !validation.Valid {
		t.Fatalf("fixture must pass strict syntax before failing structural preflight: %v", validation.Errors)
	}
	req, err := BuildChangeRequest(mi, PatchModeResearch, nil)
	if err != nil {
		t.Fatal(err)
	}
	selector := &StrategySelector{strategies: []PatchStrategy{bad, good, declined}}
	plan := selector.PlanPatch(req)
	if plan.Patch == nil || plan.StrategyID != good.id || plan.Validation == nil || !plan.Validation.Valid {
		t.Fatalf("structurally valid alternative was not selected: %+v", plan)
	}
	if len(plan.Candidates) != 3 {
		t.Fatalf("lost assessment diagnostics: %d candidates", len(plan.Candidates))
	}
	byID := make(map[string]CandidateOutcome)
	for _, c := range plan.Candidates {
		byID[c.StrategyID] = c
	}
	if c := byID[bad.id]; c.DropReason != DropStructInvalid || c.Validation == nil || len(c.Validation.Errors) == 0 {
		t.Fatalf("missing structural rejection details: %+v", c)
	}
	if c := byID[declined.id]; c.DropReason != DropNotApplicable || len(c.Assessment.Reasons) == 0 || declined.calls != 0 {
		t.Fatalf("inapplicable candidate diagnostics lost: %+v", c)
	}
	if ranks := selector.RankStrategiesWithRequest(req); len(ranks) != 2 {
		t.Fatalf("public ranking should exclude inapplicable candidates: %d", len(ranks))
	}
}

func TestPlannerSafetyNoOpDoesNotWin(t *testing.T) {
	mi := plannerSafetyMethod()
	original := strings.Join(mi.RawBody, "\n")
	noop := &plannerSafetyStrategy{id: "noop", priority: 100, code: strings.ReplaceAll(original, "\n", "\r\n") + "\r\n"}
	changed := &plannerSafetyStrategy{id: "changed", priority: 90, code: strings.ReplaceAll(original, "0x1", "0x2")}
	selector := &StrategySelector{strategies: []PatchStrategy{noop, changed}}
	plan := selector.PlanPatch(&ChangeRequest{Method: mi, Mode: PatchModeResearch})
	if plan.Patch == nil || plan.StrategyID != changed.id || plan.Candidates[0].DropReason != DropNoChange {
		t.Fatalf("unchanged body treated as an effective patch: %+v", plan)
	}
}

func TestPlannerSafetyTargetContract(t *testing.T) {
	mi := plannerSafetyMethod()
	req := &ChangeRequest{Method: mi}
	base := GeneratedPatch{
		MethodName: mi.Name, MethodSignature: mi.FullSignature, FilePath: mi.FilePath,
		PatchedCode: strings.Join(mi.RawBody, "\n"),
	}
	cases := []struct {
		name   string
		mutate func(*GeneratedPatch)
	}{
		{"method", func(p *GeneratedPatch) { p.MethodName = "other" }},
		{"overload", func(p *GeneratedPatch) { p.MethodSignature = "value(I)I" }},
		{"file", func(p *GeneratedPatch) { p.FilePath = "other/Fixture.smali" }},
		{"body_name", func(p *GeneratedPatch) { p.PatchedCode = strings.ReplaceAll(p.PatchedCode, "value()", "other()") }},
		{"body_descriptor", func(p *GeneratedPatch) { p.PatchedCode = strings.ReplaceAll(p.PatchedCode, "value()I", "value()Z") }},
		{"empty", func(p *GeneratedPatch) { p.PatchedCode = " \t\n" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			patch := base
			tc.mutate(&patch)
			if err := VerifyPatchAgainstRequest(req, &patch); err == nil {
				t.Fatal("mismatched target accepted")
			}
		})
	}
	if err := VerifyPatchAgainstRequest(req, &base); err != nil {
		t.Fatalf("matching target rejected: %v", err)
	}
}

func TestPlannerSafetyErrorsArePreservedAndNoFallbackEscapes(t *testing.T) {
	mi := plannerSafetyMethod()
	strategy := &plannerSafetyStrategy{id: "broken", err: errors.New("fixture generation failed")}
	selector := &StrategySelector{strategies: []PatchStrategy{strategy}}
	plan := selector.PlanPatch(&ChangeRequest{Method: mi})
	if plan.Patch != nil || plan.RejectionReason != "no_valid_candidate" ||
		len(plan.Candidates) != 1 || plan.Candidates[0].Error != strategy.err.Error() {
		t.Fatalf("generation error was hidden: %+v", plan)
	}
	generator := NewPatchGenerator()
	generator.strategySelector = selector
	point := &PatchPoint{
		MethodName: mi.Name, MethodSignature: mi.FullSignature, FilePath: mi.FilePath,
		MethodHeader: mi.MethodHeader, MethodBody: mi.RawBody, ReturnType: mi.ReturnType,
	}
	if generator.GenerateWithMode(point, PatchModeResearch) != nil {
		t.Fatal("exhausted plan escaped through legacy generator")
	}
}
