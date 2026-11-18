package rating

import (
	"testing"

	"mega-analyzer/pkg/internal/types"
)

// corroborationFinding builds one classified finding for a category.
func corroborationFinding(category types.Category, pattern string, score float64) types.ClassifiedFinding {
	return types.ClassifiedFinding{
		Verdict:    types.VerdictConfirmedAppRisk,
		FinalScore: score,
		Original: &types.Match{
			Categorized:    types.Categorized{Category: category},
			SourceLocation: types.SourceLocation{File: "classes.dex::Lapp/A;->x", Line: 10},
			Pattern:        pattern,
		},
	}
}

// TestComputeProfile_CriticalNeedsCriticalEvidence locks the corroboration
// gate: a pile of HIGH findings must cap its category at HIGH (8), because
// volume must not synthesize a critical verdict. Measured motivation: the
// clean markor baseline scored SECURITY 10/10 (overall CRITICAL 100) from 93
// HIGH data-flow hygiene findings with zero critical evidence, while real
// malware keeps its verdict through its own critical findings.
func TestComputeProfile_CriticalNeedsCriticalEvidence(t *testing.T) {
	manyHigh := make([]types.ClassifiedFinding, 0, 16)
	for i := 0; i < 16; i++ {
		manyHigh = append(manyHigh,
			corroborationFinding(types.Category("SECURITY"), "dataflow.path_traversal", 70))
	}
	prof := ComputeProfile(manyHigh)
	if got := prof.Categories[CatSecurity].Score; got > 8 {
		t.Errorf("16 HIGH findings produced SECURITY score %d; want <= 8 (corroboration gate)", got)
	}
	if prof.OverallScore > 80 {
		t.Errorf("overall %d without critical evidence; want <= 80", prof.OverallScore)
	}
	if prof.OverallLevel == "CRITICAL" {
		t.Errorf("overall level CRITICAL without critical evidence")
	}

	// One critical finding lifts the category past the gate unchanged.
	withCritical := append(manyHigh, corroborationFinding(types.Category("MALWARE"), "rat_reverse_connection", 90))
	prof = ComputeProfile(withCritical)
	if got := prof.Categories[CatMalware].Score; got < 9 {
		t.Errorf("critical evidence produced MALWARE score %d; want >= 9", got)
	}
	if prof.OverallLevel != "CRITICAL" {
		t.Errorf("overall level %s with critical evidence; want CRITICAL", prof.OverallLevel)
	}

	// A single HIGH finding must not dominate a category either.
	single := []types.ClassifiedFinding{corroborationFinding(types.Category("SECURITY"), "dataflow.path_traversal", 70)}
	if got := ComputeProfile(single).Categories[CatSecurity].Score; got > 8 {
		t.Errorf("single HIGH finding produced SECURITY score %d; want <= 8", got)
	}
}
