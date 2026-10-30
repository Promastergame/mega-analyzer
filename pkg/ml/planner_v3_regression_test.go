package ml

import (
	"encoding/json"
	"strings"
	"testing"

	"mega-analyzer/pkg/ml/internal/shared"
)

func TestPlannerV3NonConcreteAdmission(t *testing.T) {
	for _, flag := range []string{"native", "abstract"} {
		for _, bodyOnly := range []bool{false, true} {
			mi := plannerSafetyMethod()
			header := ".method public static " + flag + " value()I # fixture"
			mi.RawBody = []string{header, ".end method"}
			mi.MethodHeader = header
			if bodyOnly {
				mi.MethodHeader = ""
			}
			s := &plannerSafetyStrategy{id: "must-not-run", code: "return-void"}
			req, err := BuildChangeRequest(mi, PatchModeResearch, nil)
			if err == nil {
				t.Fatalf("%s declaration accepted", flag)
			}
			selector := &StrategySelector{strategies: []PatchStrategy{s}}
			plan := selector.PlanPatch(req)
			if plan.Patch != nil || plan.RejectionReason != DropInvalidRequest || s.calls != 0 {
				t.Fatalf("non-concrete method reached generation: %+v", plan)
			}
			if assessStrategy(s, mi, PatchModeResearch).Applicable {
				t.Fatal("assessment bypassed admission")
			}
			point := &PatchPoint{MethodName: mi.Name, MethodSignature: mi.FullSignature,
				ReturnType: mi.ReturnType, MethodHeader: mi.MethodHeader, MethodBody: mi.RawBody}
			g := NewPatchGenerator()
			if g.Generate(point) != nil || g.GenerateWithMode(point, PatchModeResearch) != nil {
				t.Fatal("generator bypassed non-concrete admission")
			}
		}
	}
	mi := plannerSafetyMethod()
	mi.IsAbstract = true
	if nonConcreteMethodReason(mi) == "" {
		t.Fatal("abstract metadata ignored")
	}
}

func TestPlannerV3AdmissionUsesTokensNotSubstrings(t *testing.T) {
	mi := &shared.MethodInfo{MethodHeader: ".method public nativeValue()I # abstract native",
		RawBody: []string{"const-string v0, \"native abstract\"", "return v0"}}
	if reason := nonConcreteMethodReason(mi); reason != "" {
		t.Fatal(reason)
	}
	mi.MethodHeader = ".method\tpublic\tnative\tvalue()I"
	if nonConcreteMethodReason(mi) == "" {
		t.Fatal("tab-separated native flag ignored")
	}
}

func TestPlannerV3MissingImplementation(t *testing.T) {
	for _, body := range [][]string{nil, {".method public value()I", ".end method"},
		{".annotation runtime Ltest/A;", "value = \"return v0\"", ".end annotation"},
		{".array-data 1", "0x1t", ".end array-data"}} {
		mi := plannerSafetyMethod()
		mi.RawBody = body
		s := &plannerSafetyStrategy{id: "must-not-run"}
		p := (&StrategySelector{strategies: []PatchStrategy{s}}).PlanPatch(&ChangeRequest{Method: mi})
		if p.Patch != nil || p.RejectionReason != "no_concrete_method_body" || s.calls != 0 {
			t.Fatalf("missing implementation accepted: %+v", p)
		}
	}
}

func TestPlannerV3DeclarationFlags(t *testing.T) {
	mi := plannerSafetyMethod()
	original := strings.Join(mi.RawBody, "\n")
	for _, header := range []string{
		".method public value()I", ".method private static value()I",
		".method public static synchronized value()I", ".method public static native value()I",
	} {
		patch := &GeneratedPatch{PatchedCode: strings.Replace(original, mi.MethodHeader, header, 1)}
		if err := VerifyPatchAgainstRequest(&ChangeRequest{Method: mi}, patch); err == nil {
			t.Fatalf("changed access flags accepted: %s", header)
		}
	}
	reordered := strings.Replace(original, mi.MethodHeader, ".method static public value()I # unchanged flags", 1)
	if err := verifyMethodAccessFlags(mi, reordered); err != nil {
		t.Fatal(err)
	}
	if err := verifyMethodAccessFlags(mi, original+"\n"+original); err == nil {
		t.Fatal("multiple method declarations accepted")
	}
}

func TestPlannerV3TypedCoverage(t *testing.T) {
	for _, tc := range []struct {
		coverage *ReturnSiteCoverage
		desc     string
		partial  bool
	}{
		{&ReturnSiteCoverage{Opcode: "return", TotalSites: 2, HandledSites: 1}, "complete", true},
		{&ReturnSiteCoverage{Opcode: "return", TotalSites: 2, HandledSites: 2}, "0 left unforced", false},
		{&ReturnSiteCoverage{Opcode: "return", TotalSites: 2, HandledSites: 3}, "complete", true},
		{nil, "1 left unforced", true},
	} {
		patch := &GeneratedPatch{ReturnCoverage: tc.coverage, Description: tc.desc}
		data, err := json.Marshal(patch)
		if err != nil {
			t.Fatal(err)
		}
		var restored GeneratedPatch
		if err := json.Unmarshal(data, &restored); err != nil {
			t.Fatal(err)
		}
		if got := isPartialForcedPatch(&restored); got != tc.partial {
			t.Fatalf("coverage lost or overridden by prose: %s", data)
		}
	}
}

func TestPlannerV3CoverageValidation(t *testing.T) {
	body := []string{"return v0", "return v1 # second", "const-string v2, \"return v9\"",
		".annotation runtime Ltest/A;", "return v3", ".end annotation"}
	if got := countReturnSites(body, "return"); got != 2 {
		t.Fatalf("count=%d", got)
	}
	for _, c := range []*ReturnSiteCoverage{
		{Opcode: "return", TotalSites: 1, HandledSites: 1},
		{Opcode: "return", TotalSites: 2, HandledSites: 3},
		{Opcode: "return", TotalSites: 2, HandledSites: 0},
		{Opcode: "return", TotalSites: -1, HandledSites: -1},
		{Opcode: "invoke-static", TotalSites: 2, HandledSites: 2},
	} {
		if verifyReturnCoverage(body, c) == nil {
			t.Fatalf("invalid coverage accepted: %+v", c)
		}
	}
	if err := verifyReturnCoverage(body, returnSiteCoverage(body, "return", 1)); err != nil {
		t.Fatal(err)
	}
}

type coverageFixtureStrategy struct {
	plannerSafetyStrategy
	coverage ReturnSiteCoverage
}

func (s *coverageFixtureStrategy) Generate(mi *shared.MethodInfo, mode PatchMode) (*GeneratedPatch, error) {
	p, err := s.plannerSafetyStrategy.Generate(mi, mode)
	if p != nil {
		c := s.coverage
		p.ReturnCoverage = &c
		p.Description = "complete" // Not authoritative.
	}
	return p, err
}

func TestPlannerV3CompleteCandidateBeatsPartial(t *testing.T) {
	mi := plannerSafetyMethod()
	mi.RawBody = []string{mi.MethodHeader, "    .locals 1", "    const/4 v0, 0x1",
		"    if-eqz v0, :second", "    return v0", "    :second", "    const/4 v0, 0x2",
		"    return v0", ".end method"}
	original := strings.Join(mi.RawBody, "\n")
	partial := &coverageFixtureStrategy{plannerSafetyStrategy: plannerSafetyStrategy{
		id: "partial", priority: 100, code: strings.Replace(original, "0x1", "0x3", 1)},
		coverage: ReturnSiteCoverage{Opcode: "return", TotalSites: 2, HandledSites: 1}}
	complete := &coverageFixtureStrategy{plannerSafetyStrategy: plannerSafetyStrategy{
		id: "complete", priority: 90, code: strings.ReplaceAll(strings.ReplaceAll(original, "0x1", "0x3"), "0x2", "0x3")},
		coverage: ReturnSiteCoverage{Opcode: "return", TotalSites: 2, HandledSites: 2}}
	sel := &StrategySelector{strategies: []PatchStrategy{partial, complete}}
	plan := sel.PlanPatch(&ChangeRequest{Method: mi})
	if plan.Patch == nil || plan.StrategyID != "complete" || plan.IsPartial {
		t.Fatalf("complete alternative not selected: %+v", plan)
	}
	sel.strategies = []PatchStrategy{partial}
	plan = sel.PlanPatch(&ChangeRequest{Method: mi})
	if plan.Patch == nil || !plan.IsPartial {
		t.Fatalf("partial candidate not retained for review: %+v", plan)
	}
	point := &PatchPoint{MethodName: mi.Name, MethodSignature: mi.FullSignature, MethodBody: mi.RawBody}
	artifact := buildArtifact(point, plan.Patch, *plan.Validation)
	if artifact.ApplySafety.CanWrite || artifact.ApplySafety.Safe || artifact.ReturnCoverage == nil {
		t.Fatal("partial result allowed automatic writes or lost coverage")
	}
	if err := ApplyArtifactToBase(testTempDir(t), artifact); err == nil || !strings.Contains(err.Error(), "not safe to apply") {
		t.Fatalf("applier did not refuse partial artifact before filesystem access: %v", err)
	}
}

func TestPlannerV3BuiltinCoverage(t *testing.T) {
	mi := booleanFixture()
	p, err := NewConstantInjectionStrategy().Generate(mi, PatchModeResearch)
	if err != nil {
		t.Fatal(err)
	}
	if p.ReturnCoverage == nil || p.ReturnCoverage.TotalSites != 1 || p.ReturnCoverage.HandledSites != 1 {
		t.Fatalf("missing built-in accounting: %+v", p.ReturnCoverage)
	}
	if err := verifyReturnCoverage(mi.RawBody, p.ReturnCoverage); err != nil {
		t.Fatal(err)
	}
}
