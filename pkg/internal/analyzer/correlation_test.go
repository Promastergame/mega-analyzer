package analyzer

import (
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func TestNewCorrelationFinder_Empty(t *testing.T) {
	cf := NewCorrelationFinder(nil)
	if cf == nil {
		t.Fatal("expected non-nil CorrelationFinder")
	}
	correlations := cf.FindAll()
	if len(correlations) != 0 {
		t.Fatalf("expected 0 correlations for nil files, got %d", len(correlations))
	}
}

func TestNewCorrelationFinder_EmptyMap(t *testing.T) {
	cf := NewCorrelationFinder(map[string]*types.FileAnalysis{})
	correlations := cf.FindAll()
	if len(correlations) != 0 {
		t.Fatalf("expected 0 correlations for empty map, got %d", len(correlations))
	}
}

func TestNewCorrelationFinder_NonAppCode(t *testing.T) {
	files := map[string]*types.FileAnalysis{
		"lib/support.smali": {
			Path:      "lib/support.smali",
			IsAppCode: false,
			Matches:   []types.Match{{Categorized: types.Categorized{Category: types.CategoryLicenseCheck}}},
		},
	}
	cf := NewCorrelationFinder(files)
	correlations := cf.FindAll()
	// Non-app code should be excluded from correlation
	if len(correlations) != 0 {
		t.Fatalf("expected 0 correlations for non-app code, got %d", len(correlations))
	}
}

func TestCorrelationFinder_CategoryCorrelation_Extended(t *testing.T) {
	files := map[string]*types.FileAnalysis{
		"com/app/LicenseChecker.smali": {
			Path:      "com/app/LicenseChecker.smali",
			IsAppCode: true,
			Matches: []types.Match{
				{Categorized: types.Categorized{Category: types.CategoryLicenseCheck}},
			},
		},
		"com/app/LicenseValidator.smali": {
			Path:      "com/app/LicenseValidator.smali",
			IsAppCode: true,
			Matches: []types.Match{
				{Categorized: types.Categorized{Category: types.CategoryLicenseCheck}},
			},
		},
	}
	cf := NewCorrelationFinder(files)
	correlations := cf.FindAll()
	if len(correlations) == 0 {
		t.Fatal("expected at least one correlation for files sharing a category")
	}

	// Should find a correlation linking both files via license_check
	found := false
	for _, c := range correlations {
		if c.Category == types.CategoryLicenseCheck && len(c.Files) >= 2 {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected category correlation for license_check")
	}
}

func TestCorrelationFinder_SimilarNames(t *testing.T) {
	files := map[string]*types.FileAnalysis{
		"com/app/license/LicenseManager.smali": {
			Path:      "com/app/license/LicenseManager.smali",
			IsAppCode: true,
			Matches:   []types.Match{{Categorized: types.Categorized{Category: types.CategoryLicenseCheck}}},
		},
		"com/app/billing/LicenseHelper.smali": {
			Path:      "com/app/billing/LicenseHelper.smali",
			IsAppCode: true,
			Matches:   []types.Match{{Categorized: types.Categorized{Category: types.CategoryBillingClient}}},
		},
	}
	cf := NewCorrelationFinder(files)
	correlations := cf.FindAll()
	// Both files contain "license" keyword, should be correlated
	if len(correlations) == 0 {
		t.Fatal("expected correlations for files with similar names (license keyword)")
	}
}

func TestCorrelationFinder_PackageClusters(t *testing.T) {
	files := map[string]*types.FileAnalysis{
		"com/app/security/Check1.smali": {
			Path:      "com/app/security/Check1.smali",
			IsAppCode: true,
			Matches:   []types.Match{{Categorized: types.Categorized{Category: types.CategoryLicenseCheck}}},
		},
		"com/app/security/Check2.smali": {
			Path:      "com/app/security/Check2.smali",
			IsAppCode: true,
			Matches:   []types.Match{{Categorized: types.Categorized{Category: types.CategoryTamperDetection}}},
		},
		"com/app/security/Check3.smali": {
			Path:      "com/app/security/Check3.smali",
			IsAppCode: true,
			Matches:   []types.Match{{Categorized: types.Categorized{Category: types.CategorySignatureCheck}}},
		},
	}
	cf := NewCorrelationFinder(files)
	correlations := cf.FindAll()
	// 3 files in same package with findings should create a cluster
	if len(correlations) == 0 {
		t.Fatal("expected package cluster correlation")
	}
}

func TestCorrelationFinder_MultiCategoryFiles(t *testing.T) {
	files := map[string]*types.FileAnalysis{
		"com/app/Guard.smali": {
			Path:      "com/app/Guard.smali",
			IsAppCode: true,
			Matches: []types.Match{
				{Categorized: types.Categorized{Category: types.CategoryLicenseCheck}},
				{Categorized: types.Categorized{Category: types.CategoryTamperDetection}},
				{Categorized: types.Categorized{Category: types.CategoryRootDetection}},
			},
		},
		"com/app/Security.smali": {
			Path:      "com/app/Security.smali",
			IsAppCode: true,
			Matches: []types.Match{
				{Categorized: types.Categorized{Category: types.CategoryLicenseCheck}},
				{Categorized: types.Categorized{Category: types.CategorySignatureCheck}},
			},
		},
	}
	cf := NewCorrelationFinder(files)
	correlations := cf.FindAll()
	if len(correlations) == 0 {
		t.Fatal("expected correlations for multi-category files")
	}
}

func TestCorrelationFinder_MaxCorrelations(t *testing.T) {
	// Create many files to test the cap
	files := make(map[string]*types.FileAnalysis)
	for i := 0; i < 200; i++ {
		path := "com/app/pkg" + string(rune('A'+i%26)) + "/File" + string(rune('0'+i%10)) + ".smali"
		cat := types.CategoryLicenseCheck
		if i%3 == 0 {
			cat = types.CategoryPremiumCheck
		}
		if i%5 == 0 {
			cat = types.CategoryTamperDetection
		}
		files[path] = &types.FileAnalysis{
			Path:      path,
			IsAppCode: true,
			Matches:   []types.Match{{Categorized: types.Categorized{Category: cat}}},
		}
	}
	cf := NewCorrelationFinder(files)
	correlations := cf.FindAll()
	if len(correlations) > 150 {
		t.Fatalf("correlations should be capped at 150, got %d", len(correlations))
	}
}

func TestCorrelationFinder_ScoresSorted(t *testing.T) {
	files := map[string]*types.FileAnalysis{
		"com/app/License1.smali": {
			Path: "com/app/License1.smali", IsAppCode: true,
			Matches: []types.Match{{Categorized: types.Categorized{Category: types.CategoryLicenseCheck}}},
		},
		"com/app/License2.smali": {
			Path: "com/app/License2.smali", IsAppCode: true,
			Matches: []types.Match{{Categorized: types.Categorized{Category: types.CategoryLicenseCheck}}},
		},
		"com/app/Premium1.smali": {
			Path: "com/app/Premium1.smali", IsAppCode: true,
			Matches: []types.Match{{Categorized: types.Categorized{Category: types.CategoryPremiumCheck}}},
		},
		"com/app/Premium2.smali": {
			Path: "com/app/Premium2.smali", IsAppCode: true,
			Matches: []types.Match{{Categorized: types.Categorized{Category: types.CategoryPremiumCheck}}},
		},
	}
	cf := NewCorrelationFinder(files)
	correlations := cf.FindAll()
	// Verify sorted by score descending
	for i := 1; i < len(correlations); i++ {
		if correlations[i].Score > correlations[i-1].Score {
			t.Fatalf("correlations not sorted by score: [%d]=%f > [%d]=%f",
				i, correlations[i].Score, i-1, correlations[i-1].Score)
		}
	}
}

func TestExtractPackage(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"com/app/security/Check.smali", "com/app/security"},
		{"com/app/Check.smali", "com/app"},
		{"Check.smali", "."},
	}
	for _, tt := range tests {
		got := extractPackage(tt.path)
		if got != tt.want {
			t.Errorf("extractPackage(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestExtractClassName_Correlation(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"com/app/security/Check.smali", "Check"},
		{"com/app/LicenseManager.smali", "LicenseManager"},
	}
	for _, tt := range tests {
		got := extractClassName(tt.path)
		if got == "" {
			t.Errorf("extractClassName(%q) returned empty", tt.path)
		}
		if got != tt.want {
			t.Errorf("extractClassName(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}
