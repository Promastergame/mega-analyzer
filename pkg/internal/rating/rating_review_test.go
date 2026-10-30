package rating

import (
	"testing"

	"mega-analyzer/pkg/internal/types"
)

// Review round: license/mod findings in their own buckets, and zero-risk
// findings staying at 0/SAFE instead of being floored to 1/LOW.

func TestReviewMapCategory(t *testing.T) {
	cases := []struct {
		in   types.Category
		want string
	}{
		{"license_check", CatCrackPoint},
		{"LICENSE_STORAGE", CatCrackPoint},
		{"LICENSE_CALLBACK", CatCrackPoint},
		{"GOOGLE_LVL", CatCrackPoint},
		{"MOD_DETECTION", CatPiracy},
		{"mod_menu_injection", CatPiracy},
		{"CRACK_TOOL", CatCrackPoint},
		{"BANKING_THREAT", CatMalware},
		{"malware", CatMalware},
		{"SUBSCRIPTION", CatBilling},
		{"PURCHASE_VERIFY", CatBilling},
		{"PERMISSION_RULE", CatPrivacy},
		{"WEAK_CRYPTO", CatSecurity},
		{"TAMPER_DETECTION", CatSecurity},
		{"SOMETHING_UNKNOWN_XYZ", CatSecurity}, // default bucket
	}
	for _, tc := range cases {
		if got := MapCategory(tc.in); got != tc.want {
			t.Errorf("MapCategory(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func reviewFinding(category string, score float64, file, pattern string) types.ClassifiedFinding {
	return types.ClassifiedFinding{
		Verdict:    types.VerdictConfirmedAppRisk,
		FinalScore: score,
		Original: &types.Match{
			Categorized:    types.Categorized{Category: types.Category(category)},
			SourceLocation: types.SourceLocation{File: file, Line: 1},
			Pattern:        pattern,
		},
	}
}

func TestReviewLicenseAndModBuckets(t *testing.T) {
	prof := ComputeProfile([]types.ClassifiedFinding{
		reviewFinding("LICENSE_STORAGE", 80, "a.smali", "checkAccess"),
		reviewFinding("MOD_DETECTION", 70, "b.smali", "modmenu"),
	})
	if prof.Categories[CatCrackPoint].Score == 0 {
		t.Error("license finding should score in CRACK_POINT")
	}
	if prof.Categories[CatPiracy].Score == 0 {
		t.Error("mod finding should score in PIRACY")
	}
	if prof.Categories[CatSecurity].Score != 0 {
		t.Errorf("nothing should land in SECURITY, got %+v", prof.Categories[CatSecurity])
	}
	if prof.PrimaryRisk != "Crack-Points" {
		t.Errorf("PrimaryRisk = %q, want Crack-Points", prof.PrimaryRisk)
	}
}

func TestReviewZeroScoreStaysSafe(t *testing.T) {
	prof := ComputeProfile([]types.ClassifiedFinding{
		reviewFinding("WEAK_CRYPTO", 0, "a.smali", "nop"),
	})
	if got := prof.Categories[CatSecurity]; got.Score != 0 || got.Level != "SAFE" {
		t.Errorf("zero-risk category = %d/%s, want 0/SAFE", got.Score, got.Level)
	}
	if prof.OverallScore != 0 || prof.OverallLevel != "SAFE" || prof.PrimaryRisk != "SAFE" {
		t.Errorf("overall = %d/%s primary = %q, want 0/SAFE/SAFE",
			prof.OverallScore, prof.OverallLevel, prof.PrimaryRisk)
	}
}
