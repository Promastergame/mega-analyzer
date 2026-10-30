package report

import (
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func suspicionResult(total, critical, piracySites int) *types.AnalysisResult {
	r := types.NewAnalysisResult("/tmp/target")
	r.Stats.TotalMatches = total
	r.Stats.CriticalMatches = critical
	r.MatchesByCategory = map[types.Category]int{
		types.CategoryPiracySite: piracySites,
	}
	return r
}

func TestSuspicionScoreEmptyResultIsZero(t *testing.T) {
	if bd := SuspicionScore(types.NewAnalysisResult("/tmp/target")); bd.Score != 0 {
		t.Fatalf("empty result score = %d, want 0", bd.Score)
	}
}

func TestSuspicionScoreIsTheSumOfItsBuckets(t *testing.T) {
	for _, r := range []*types.AnalysisResult{
		suspicionResult(1072, 867, 782),
		suspicionResult(10, 5, 0),
		suspicionResult(3, 0, 3),
	} {
		bd := SuspicionScore(r)
		want := bd.PatternMatches + bd.CriticalFindings + bd.PiracyIndicators + bd.ConfidenceBoost
		if want > 100 {
			want = 100
		}
		if bd.Score != want {
			t.Errorf("score = %d, want bucket sum %d", bd.Score, want)
		}
	}
}

func TestSuspicionScoreMatchesRawFormulaWithoutPiracySites(t *testing.T) {
	bd := SuspicionScore(suspicionResult(10, 5, 0))
	if want := computeSuspicionScore(10, 5, 0, 0); bd.Score != want {
		t.Fatalf("score = %d, want %d (raw formula, no piracy sites)", bd.Score, want)
	}
}

func TestSuspicionScoreDiscountsPiracySiteLinks(t *testing.T) {
	// 10 inert pirate URLs must score far below 10 behavioral matches.
	linksOnly := SuspicionScore(suspicionResult(10, 10, 10))
	behavior := SuspicionScore(suspicionResult(10, 10, 0))
	if linksOnly.Score >= behavior.Score {
		t.Fatalf("links-only score %d >= behavioral score %d; discount not applied",
			linksOnly.Score, behavior.Score)
	}
	// 10 links fold into ceil(10/10) = 1 kept signal -> 1*2 pattern points.
	if linksOnly.PatternMatches != 2 {
		t.Errorf("links-only pattern bucket = %d, want 2", linksOnly.PatternMatches)
	}
}

func TestSuspicionScoreNeverGoesNegative(t *testing.T) {
	// Inconsistent stats (more piracy sites than counted matches) must clamp.
	bd := SuspicionScore(suspicionResult(0, 0, 50))
	if bd.Score != 0 {
		t.Fatalf("score = %d, want 0", bd.Score)
	}
}

func TestSuspicionScorePiracyBucketRespectsDetectorConfidence(t *testing.T) {
	// Repack case: hundreds of inert piracy-site links, but the dedicated
	// piracy scorer is only 10% confident. The composition bucket must not
	// report 25/25 while the "Piracy Detection" block reports LOW.
	r := suspicionResult(0, 0, 0)
	r.Piracy = &types.PiracyAnalysis{
		Findings:   make([]types.PiracyFinding, 886),
		Confidence: 0.10,
	}
	bd := SuspicionScore(r)
	if bd.PiracyIndicators > 3 {
		t.Fatalf("piracy bucket = %d, want <= 3 with detector confidence 10%%", bd.PiracyIndicators)
	}

	// High detector confidence keeps the old ceiling.
	r.Piracy.Confidence = 1.0
	if bd = SuspicionScore(r); bd.PiracyIndicators != 25 {
		t.Fatalf("piracy bucket = %d, want 25 with detector confidence 100%%", bd.PiracyIndicators)
	}
}

func artifactResult(sevs ...types.Severity) *types.AnalysisResult {
	r := types.NewAnalysisResult("/tmp/target")
	r.MatchesByCategory = map[types.Category]int{}
	for _, s := range sevs {
		r.ArtifactFindings = append(r.ArtifactFindings, types.ArtifactFinding{
			Path: "app.jar", Severity: s, Reason: "test",
		})
	}
	return r
}

func TestSuspicionScoreCountsArtifactFindings(t *testing.T) {
	// A stealer whose only signals are sidecar rows must not score zero:
	// one HIGH (OS exec) + one MEDIUM must lift the score off the floor.
	bd := SuspicionScore(artifactResult(types.SeverityHigh, types.SeverityMedium))
	if bd.Score == 0 {
		t.Fatal("artifact-only result scored 0; sidecar findings must feed the score")
	}
	if bd.Score < 10 {
		t.Errorf("HIGH+MEDIUM artifact score = %d, want >= 10", bd.Score)
	}
	// Inventory alone (INFO rows) must never raise the score.
	if bd := SuspicionScore(artifactResult(types.SeverityInfo, types.SeverityInfo)); bd.Score != 0 {
		t.Errorf("info-only artifact score = %d, want 0", bd.Score)
	}
}

func TestSuspicionScorePeakFloor(t *testing.T) {
	// Peak severity guarantees minimum attention: Critical->25, High->15.
	if bd := SuspicionScore(artifactResult(types.SeverityCritical)); bd.Score < 25 {
		t.Errorf("critical artifact score = %d, want >= 25", bd.Score)
	}
	if bd := SuspicionScore(artifactResult(types.SeverityHigh)); bd.Score < 15 {
		t.Errorf("high artifact score = %d, want >= 15", bd.Score)
	}
	// Buckets still cap the total at 100 with heavy artifact load.
	many := make([]types.Severity, 0, 60)
	for i := 0; i < 60; i++ {
		many = append(many, types.SeverityHigh)
	}
	if bd := SuspicionScore(artifactResult(many...)); bd.Score > 100 {
		t.Errorf("heavy artifact score = %d, want capped at 100", bd.Score)
	} else if bd.Score != 30 {
		t.Errorf("60 HIGH artifacts score = %d, want 30 (pattern bucket cap)", bd.Score)
	}
}
