package analyzer

import (
	"mega-analyzer/pkg/internal/types"
	"testing"
)

func TestSynergyNative_FeatureMask(t *testing.T) {
	analysis := &types.MethodAnalysis{
		FeatureMap: map[string]bool{
			"uses_encryption": true,
			"reads_file":      true,
		},
	}

	// Build and Cache
	BuildAndCacheFeatureMask(analysis)
	if !analysis.FeatureMaskValid {
		t.Error("FeatureMask should be valid")
	}

	// Cached should return the same
	mask := GetCachedFeatureMask(analysis)
	if mask == 0 {
		t.Error("Mask should not be 0")
	}

	// Rebuild and Cache (already valid, should immediately return)
	BuildAndCacheFeatureMask(analysis)

	// Invalidate
	InvalidateFeatureMask(analysis)
	if analysis.FeatureMaskValid {
		t.Error("FeatureMask should be invalid after Invalidate")
	}

	// Fallback GetCached
	mask2 := GetCachedFeatureMask(analysis)
	if mask2 != mask {
		t.Errorf("GetCachedFeatureMask fallback failed")
	}
}

func TestSynergyNative_Calculations(t *testing.T) {
	analysis := &types.MethodAnalysis{
		FeatureMap: map[string]bool{
			"uses_encryption":       true,
			"reads_file":            true,
			"calls_native_method":   true,
			"name_contains_license": true,
		},
	}
	// Test normal calculation
	bonus, matched := CalculateSynergyNative(analysis)
	if bonus < 0 {
		t.Error("Should have synergy bonus >= 0")
	}

	// Test threshold logic
	bonus2, matched2 := CalculateSynergyNativeWithThreshold(analysis, -0.01) // easily hit threshold early
	_ = bonus2
	if len(matched2) == 0 && len(matched) > 0 { // matched could be 0 if no rule triggers
		t.Error("Should evaluate")
	}

	analyzer := NewDefaultMethodAnalyzer()
	bonus3, matchedLegacy := analyzer.CalculateSynergyNativeLegacy(analysis)
	if bonus3 != bonus {
		t.Errorf("Legacy wrapper mismatch score: expected %v, got %v", bonus, bonus3)
	}
	if len(matchedLegacy) != len(matched) {
		t.Errorf("Legacy wrapper mismatch length: expected %d, got %d", len(matched), len(matchedLegacy))
	}
}

func TestSynergyNative_FeatureUpdate(t *testing.T) {
	analysis := &types.MethodAnalysis{
		FeatureMap: make(map[string]bool),
	}

	_ = GetCachedFeatureMask(analysis)

	initialMask := analysis.FeatureMaskCached

	feat := types.Feature{ID: "calls_reflection"}
	AddFeatureWithMask(analysis, feat)

	if !analysis.FeatureMap["calls_reflection"] {
		t.Error("Map not updated")
	}
	if analysis.FeatureMaskCached == initialMask {
		t.Error("Mask not updated")
	}

	// Test UpdateFeatureMask manually clearing
	UpdateFeatureMask(analysis, "calls_reflection", false)
	if analysis.FeatureMaskCached != initialMask {
		t.Error("Mask not cleared properly")
	}

	InvalidateFeatureMask(analysis)
	UpdateFeatureMask(analysis, "calls_reflection", true)
	if analysis.FeatureMaskValid {
		t.Error("Should not become valid on update after invalidate")
	}
}
