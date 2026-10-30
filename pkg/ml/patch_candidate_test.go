package ml

import "testing"

func TestBuildPatchCandidateIsExplainableAndStable(t *testing.T) {
	sm := &ScoredMethod{
		Method: MethodInfo{FilePath: "smali/com/example/Flags.smali", FullSignature: "isEnabled()Z", Name: "isEnabled", ReturnType: "Z", IsAppCode: true, InstructionCount: 4, RawBody: []string{"const/4 v0, 0x1", "return v0"}},
		Score:  ScoreResult{SuggestedPatch: PatchReturnTrue, PatchCategory: PatchCatLicense, FinalScore: 81, Confidence: 1.2, RiskLevel: RiskClassLow, MatchedParts: []string{"method:isEnabled"}},
	}
	first := BuildPatchCandidate(sm)
	second := BuildPatchCandidate(sm)
	if first == nil || first.ID != second.ID || first.SourceHash == "" {
		t.Fatal("candidate identity/source hash is not stable")
	}
	if first.Confidence != 1 || len(first.Evidence) != 1 {
		t.Fatalf("candidate normalization failed: confidence=%v evidence=%v", first.Confidence, first.Evidence)
	}
}

func TestPreflightPatchCandidateRejectsIncompatibleReturnType(t *testing.T) {
	sm := &ScoredMethod{Method: MethodInfo{IsAppCode: true, ReturnType: "V", InstructionCount: 2}, Score: ScoreResult{SuggestedPatch: PatchReturnTrue, RiskLevel: RiskClassLow}}
	status, reason := PreflightPatchCandidate(sm)
	if status != CandidateBlocked || reason != "boolean_patch_on_non_boolean_return" {
		t.Fatalf("status=%q reason=%q", status, reason)
	}
}

func TestPreflightPatchCandidateAllowsMatchingReturnType(t *testing.T) {
	sm := &ScoredMethod{Method: MethodInfo{IsAppCode: true, ReturnType: "Z", InstructionCount: 2}, Score: ScoreResult{SuggestedPatch: PatchReturnFalse, RiskLevel: RiskClassLow}}
	status, reason := PreflightPatchCandidate(sm)
	if status != CandidateReview || reason != "" {
		t.Fatalf("status=%q reason=%q", status, reason)
	}
}
