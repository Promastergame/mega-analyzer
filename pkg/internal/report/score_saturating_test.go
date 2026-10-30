package report

import (
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func TestSaturatingScoreEmptyIsZeroAndClean(t *testing.T) {
	bd := SaturatingScore(types.NewAnalysisResult("/tmp/target"))
	if bd.Score != 0 {
		t.Fatalf("empty score = %d, want 0", bd.Score)
	}
	if bd.Status != "clean" {
		t.Fatalf("empty status = %q, want clean", bd.Status)
	}
	if bd.Neutralized {
		t.Fatal("empty result must not be flagged neutralized")
	}
}

func TestSaturatingScoreDampensDuplicates(t *testing.T) {
	one := types.NewAnalysisResult("/tmp/target")
	one.MatchesByCategory = map[types.Category]int{types.CategoryPiracySite: 1}

	ten := types.NewAnalysisResult("/tmp/target")
	ten.MatchesByCategory = map[types.Category]int{types.CategoryPiracySite: 10}

	hundred := types.NewAnalysisResult("/tmp/target")
	hundred.MatchesByCategory = map[types.Category]int{types.CategoryPiracySite: 100}

	s1 := SaturatingScore(one).Score
	s10 := SaturatingScore(ten).Score
	s100 := SaturatingScore(hundred).Score

	if !(s1 <= s10 && s10 <= s100) {
		t.Fatalf("monotonicity broken: 1=%d 10=%d 100=%d", s1, s10, s100)
	}
	// 10x the findings must not be anywhere near 10x the score, and going from
	// 10 to 100 duplicates must add very little (log dampening).
	if s10 > 4*s1 {
		t.Errorf("10 dup links scored %d vs 1 link %d; dampening too weak", s10, s1)
	}
	if s100-s10 > s10 {
		t.Errorf("100 vs 10 dup links added %d (from %d); should saturate", s100-s10, s10)
	}
}

func TestSaturatingScoreNeutralizerFloorsAndRelabels(t *testing.T) {
	r := types.NewAnalysisResult("/tmp/target")
	r.Files = map[string]*types.FileAnalysis{
		"Lfky/pq/Sztx.smali": {
			Path: "Lfky/pq/Sztx.smali",
			Matches: []types.Match{
				{Text: "const-string v0, \"assets/SignatureKiller/origin.apk\""},
			},
		},
	}
	bd := SaturatingScore(r)
	if !bd.Neutralized {
		t.Fatal("signature killer evidence must set Neutralized")
	}
	if bd.Score < neutralizerFloor {
		t.Fatalf("neutralized score = %d, want >= %d", bd.Score, neutralizerFloor)
	}
	if bd.Status != "neutralized" {
		t.Fatalf("status = %q, want neutralized", bd.Status)
	}
	if got := SecurityStatusLabel(r, true); got != "Neutralized" {
		t.Fatalf("security badge = %q, want Neutralized (B4 fix)", got)
	}
}

func TestSecurityStatusLabelHonoursDetectionWhenClean(t *testing.T) {
	r := types.NewAnalysisResult("/tmp/target")
	if got := SecurityStatusLabel(r, true); got != "Protected" {
		t.Fatalf("badge = %q, want Protected", got)
	}
	if got := SecurityStatusLabel(r, false); got != "None" {
		t.Fatalf("badge = %q, want None", got)
	}
}
