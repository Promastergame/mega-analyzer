package ml

import (
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func TestCrackPointIndex_LookupAndBoost(t *testing.T) {
	points := []types.CrackPoint{
		{
			Location: types.SourceLocation{
				File:   "/tmp/apk/smali/com/app/Billing.smali",
				Method: "isPremium",
			},
			ClassName:  "Lcom/app/Billing;",
			Method:     "isPremium",
			Category:   "premium",
			Confidence: 0.92,
		},
	}
	idx := BuildCrackPointIndex(points)

	scored := []ScoredMethod{{
		Method: MethodInfo{
			Name:      "isPremium",
			ClassName: "Lcom/app/Billing;",
		},
		ClassPath: "/tmp/apk/smali/com/app/Billing.smali",
		Score:     ScoreResult{FinalScore: 40},
	}}

	before := scored[0].Score.FinalScore
	boosted := ApplyCrackPointBoost(scored, idx)
	if boosted[0].Score.FinalScore <= before {
		t.Fatalf("expected score boost, before=%.1f after=%.1f", before, boosted[0].Score.FinalScore)
	}
	if _, ok := idx.Lookup(&scored[0]); !ok {
		t.Fatal("expected lookup hit")
	}
}

func TestCrackPointIndex_NoMatch(t *testing.T) {
	idx := BuildCrackPointIndex([]types.CrackPoint{
		{Method: "other", Location: types.SourceLocation{File: "a.smali"}},
	})
	sm := ScoredMethod{Method: MethodInfo{Name: "isPremium"}, ClassPath: "b.smali"}
	if _, ok := idx.Lookup(&sm); ok {
		t.Fatal("expected no match")
	}
}
