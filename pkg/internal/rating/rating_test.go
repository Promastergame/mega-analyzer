package rating

import (
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func TestComputeProfile_SeparatedRatings(t *testing.T) {
	findings := []types.ClassifiedFinding{
		{
			Verdict:    types.VerdictConfirmedAppRisk,
			FinalScore: 8.0,
			Original: &types.Match{
				Categorized:    types.Categorized{Category: types.Category("PIRACY")},
				SourceLocation: types.SourceLocation{File: "classes.dex::La0/a;", Line: 129},
				Pattern:        "androeed.ru",
			},
		},
		{
			Verdict:    types.VerdictConfirmedAppRisk,
			FinalScore: 8.0,
			Original: &types.Match{
				Categorized:    types.Categorized{Category: types.Category("PIRACY")},
				SourceLocation: types.SourceLocation{File: "classes.dex::La0/b;", Line: 11},
				Pattern:        "androeed.ru",
			},
		},
		{
			Verdict:    types.VerdictGenericNoiseSuppressed,
			FinalScore: 7.0,
			Original: &types.Match{
				Categorized:    types.Categorized{Category: types.Category("malware")},
				SourceLocation: types.SourceLocation{File: "res/icon.png", Line: 1},
				Pattern:        "HighEntropy",
			},
		},
	}

	prof := ComputeProfile(findings)

	if prof.Categories[CatPiracy].Score < 1 {
		t.Errorf("Expected Piracy score > 0, got %d", prof.Categories[CatPiracy].Score)
	}

	// Suppressed media noise should not inflate Malware category score
	if prof.Categories[CatMalware].Score != 0 {
		t.Errorf("Expected Malware score 0 due to suppressed PNG noise, got %d", prof.Categories[CatMalware].Score)
	}
}
