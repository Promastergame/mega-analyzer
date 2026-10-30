package ml

import (
	"strings"
	"testing"

	"mega-analyzer/pkg/ml/ensemble"
)

func TestBoostScoredMethods_ReordersByBlend(t *testing.T) {
	in := []ScoredMethod{
		{
			Method: MethodInfo{
				Name:             "isLicensed",
				FullSignature:    "Lcom/example/security/LicenseChecker;->isLicensed()Z",
				ReturnType:       "Z",
				ReturnsBoolean:   true,
				InstructionCount: 30,
				IfCheckCount:     4,
				IsAppCode:        true,
				StringConsts:     []string{"VGhpcyBpcyBhIHNlY3JldA=="},
				Calls: []CallInfo{
					{FullCall: "Landroid/content/Intent;->getStringExtra"},
					{FullCall: "Ljava/lang/Runtime;->exec"},
				},
				RawBody: []string{
					"invoke-virtual {p0}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;",
					"if-eqz v1, :cond_0",
					"invoke-static {v1}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;",
				},
			},
			Score: ScoreResult{FinalScore: 50},
		},
		{
			Method: MethodInfo{
				Name:             "getName",
				FullSignature:    "Lcom/example/util/Helper;->getName()Ljava/lang/String;",
				ReturnType:       "Ljava/lang/String;",
				InstructionCount: 5,
				IsAppCode:        true,
				RawBody:          []string{"const-string v0, \"hello\"", "return-object v0"},
			},
			Score: ScoreResult{FinalScore: 60}, // higher legacy score, but lower true risk
		},
	}

	mix := DefaultBoostMix()
	out := BoostScoredMethods(in, mix, 2)
	if len(out) != 2 {
		t.Fatalf("expected 2 results, got %d", len(out))
	}
	if out[0].Method.Name != "isLicensed" {
		t.Fatalf("expected isLicensed to top the boosted list, got %q", out[0].Method.Name)
	}
	if out[0].BoostScore <= 0 {
		t.Fatalf("expected positive boost score, got %f", out[0].BoostScore)
	}
	if out[0].Explanation == "" {
		t.Fatal("expected non-empty explanation")
	}
}

func TestBoostScoredMethods_EmptyInput(t *testing.T) {
	if got := BoostScoredMethods(nil, DefaultBoostMix(), 0); got != nil {
		t.Fatalf("expected nil for empty input, got %v", got)
	}
}

func TestApplyEnsembleBoost_MutatesInPlaceAndChangesFinalScore(t *testing.T) {
	in := []ScoredMethod{
		{
			Method: MethodInfo{
				Name:             "isLicensed",
				FullSignature:    "Lcom/example/security/LicenseChecker;->isLicensed()Z",
				ReturnType:       "Z",
				ReturnsBoolean:   true,
				InstructionCount: 30,
				IfCheckCount:     4,
				IsAppCode:        true,
				StringConsts:     []string{"VGhpcyBpcyBhIHNlY3JldA=="},
				Calls: []CallInfo{
					{FullCall: "Landroid/content/Intent;->getStringExtra"},
					{FullCall: "Ljava/lang/Runtime;->exec"},
				},
				RawBody: []string{
					"invoke-virtual {p0}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;",
					"if-eqz v1, :cond_0",
					"invoke-static {v1}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;",
				},
			},
			Score: ScoreResult{FinalScore: 50},
		},
	}

	legacyBefore := in[0].Score.FinalScore
	out := ApplyEnsembleBoost(in, DefaultBoostMix(), 0, nil)

	// Same underlying array — mutated in place, not a copy.
	if &out[0] != &in[0] {
		t.Fatal("expected ApplyEnsembleBoost to mutate and return the same slice")
	}
	if out[0].Ensemble == nil {
		t.Fatal("expected Ensemble field to be populated")
	}
	if out[0].Score.FinalScore == legacyBefore {
		t.Fatalf("expected FinalScore to change from blending, still %f", legacyBefore)
	}
	if len(out[0].Score.Reasons) == 0 {
		t.Fatal("expected a blend explanation appended to Reasons")
	}
	last := out[0].Score.Reasons[len(out[0].Score.Reasons)-1]
	if !strings.Contains(last, "blend") {
		t.Fatalf("expected explanation to mention the blend, got %q", last)
	}
}

func TestApplyEnsembleBoost_EmptyInput(t *testing.T) {
	if got := ApplyEnsembleBoost(nil, DefaultBoostMix(), 0, nil); got != nil {
		t.Fatalf("expected nil for empty input, got %v", got)
	}
}

type fakeTrainedRiskScorer struct {
	loaded bool
	prob   float64
}

func (f fakeTrainedRiskScorer) IsLoaded() bool { return f.loaded }
func (f fakeTrainedRiskScorer) Score(ensemble.Features) (float64, bool) {
	return f.prob, true
}

func TestApplyEnsembleBoost_UnloadedTrainedScorerIsNoOp(t *testing.T) {
	in := []ScoredMethod{
		{Method: MethodInfo{Name: "a", RawBody: []string{"return-void"}}, Score: ScoreResult{FinalScore: 10}},
	}
	inCopy := []ScoredMethod{
		{Method: MethodInfo{Name: "a", RawBody: []string{"return-void"}}, Score: ScoreResult{FinalScore: 10}},
	}

	got := ApplyEnsembleBoost(in, DefaultBoostMix(), 0, fakeTrainedRiskScorer{loaded: false})
	want := ApplyEnsembleBoost(inCopy, DefaultBoostMix(), 0, nil)

	if got[0].Score.FinalScore != want[0].Score.FinalScore {
		t.Fatalf("unloaded trained scorer should be a no-op: got %f want %f", got[0].Score.FinalScore, want[0].Score.FinalScore)
	}
}

func TestApplyEnsembleBoost_LoadedTrainedScorerShiftsScore(t *testing.T) {
	base := ScoredMethod{Method: MethodInfo{Name: "a", RawBody: []string{"return-void"}}, Score: ScoreResult{FinalScore: 10}}

	withoutModel := ApplyEnsembleBoost([]ScoredMethod{base}, DefaultBoostMix(), 0, fakeTrainedRiskScorer{loaded: false})
	withModel := ApplyEnsembleBoost([]ScoredMethod{base}, DefaultBoostMix(), 0, fakeTrainedRiskScorer{loaded: true, prob: 1.0})

	if withoutModel[0].Score.FinalScore == withModel[0].Score.FinalScore {
		t.Fatal("expected a loaded trained scorer predicting max risk to shift the blended score")
	}
}

func TestBoostScoredMethods_RespectsMinConfidence(t *testing.T) {
	in := []ScoredMethod{
		{
			Method: MethodInfo{
				Name:    "a",
				RawBody: []string{"return-void"},
			},
			Score: ScoreResult{FinalScore: 1},
		},
	}
	// Set min-confidence ridiculously high so the entry is dropped.
	mix := DefaultBoostMix()
	mix.MinConfidence = 0.99
	out := BoostScoredMethods(in, mix, 0)
	if len(out) != 0 {
		t.Fatalf("expected entry to be dropped, got %d", len(out))
	}
}
