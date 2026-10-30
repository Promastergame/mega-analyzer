package fpfilter

import (
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func TestIsHeuristicLibrary(t *testing.T) {
	yes := []string{
		"smali/com/example/BuildConfig.smali",
		"src/BuildConfig.java",
		"smali/com/app/R.smali",
		"smali/com/app/R$id.smali",
		"smali/com/app/R$layout.smali",
	}
	for _, p := range yes {
		if !isHeuristicLibrary(p) {
			t.Errorf("isHeuristicLibrary(%q) = false, want true", p)
		}
	}
	no := []string{
		"smali/com/example/MainActivity.smali",
		"src/Main.java",
		"smali/com/app/Utils.smali",
	}
	for _, p := range no {
		if isHeuristicLibrary(p) {
			t.Errorf("isHeuristicLibrary(%q) = true, want false", p)
		}
	}
}

func TestExtractSDKName(t *testing.T) {
	if got := extractSDKName("smali/com/google/firebase/Analytics.smali"); got != "com.google" {
		t.Errorf("got %q, want com.google", got)
	}
	if got := extractSDKName("smali/androidx"); got != "androidx" {
		t.Errorf("single-segment: got %q", got)
	}
}

func TestIsAppCodePath(t *testing.T) {
	if isAppCodePath("") {
		t.Error("empty path should not be app code")
	}
	// SDK paths should not be app code
	if isAppCodePath("smali/com/google/ads/AdMob.smali") {
		t.Error("google SDK path should not be app code")
	}
	if isAppCodePath("smali/androidx/fragment/Fragment.smali") {
		t.Error("androidx path should not be app code")
	}
	// App code path
	if !isAppCodePath("smali/com/myapp/MainActivity.smali") {
		t.Error("app smali path should be app code")
	}
}

func TestIsSecurityChainCategory(t *testing.T) {
	yes := []types.Category{
		types.CategoryRootDetection,
		types.CategorySSLPinning,
		types.CategoryAntiHook,
		types.CategoryBankingThreat,
		types.CategoryMalwareCombo,
	}
	for _, c := range yes {
		if !isSecurityChainCategory(c) {
			t.Errorf("isSecurityChainCategory(%q) = false, want true", c)
		}
	}
	if isSecurityChainCategory(types.CategoryDonation) {
		t.Error("donation should not be a security chain category")
	}
}

func TestNewBoilerplateDetector(t *testing.T) {
	bd := NewBoilerplateDetector()
	if bd == nil {
		t.Fatal("expected non-nil BoilerplateDetector")
	}
}

func TestNewVerdictRefiner(t *testing.T) {
	vr := NewVerdictRefiner()
	if vr == nil {
		t.Fatal("expected non-nil VerdictRefiner")
	}
	// Empty input should return empty
	result := vr.Refine(nil)
	if len(result) != 0 {
		t.Errorf("expected nil/empty for nil input, got %v", result)
	}
}
