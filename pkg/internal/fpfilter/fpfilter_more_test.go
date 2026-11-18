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

func TestProtectionCategoriesAreObservations(t *testing.T) {
	yes := []types.Category{
		types.CategoryRootDetection,
		types.CategorySSLPinning,
		types.CategoryAntiHook,
		types.CategorySignatureCheck,
	}
	for _, c := range yes {
		if !isObservation(&types.Match{Categorized: types.Categorized{Category: c}}) {
			t.Errorf("protection %q was treated as a risk", c)
		}
	}
	if isObservation(nil) || isObservation(&types.Match{Categorized: types.Categorized{Category: types.CategoryMalwareCombo}}) {
		t.Error("nil or an unclassified malware finding was treated as an observation")
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
