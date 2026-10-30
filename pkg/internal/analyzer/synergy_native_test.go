package analyzer

import (
	"mega-analyzer/pkg/internal/types"
	"testing"
)

func TestSynergyNative(t *testing.T) {
	analysis := &types.MethodAnalysis{
		FeatureMap: map[string]bool{
			"feature_1": true,
			"feature_2": true,
		},
	}

	// Test BuildAndCacheFeatureMask
	BuildAndCacheFeatureMask(analysis)
	if !analysis.FeatureMaskValid {
		t.Error("FeatureMaskValid should be true after BuildAndCacheFeatureMask")
	}

	// Test GetCachedFeatureMask
	mask := GetCachedFeatureMask(analysis)
	_ = mask

	// Test CalculateSynergyNative
	bonus, matched := CalculateSynergyNative(analysis)
	_ = bonus
	_ = matched

	// Test CalculateSynergyNativeWithThreshold
	bonus2, matched2 := CalculateSynergyNativeWithThreshold(analysis, 1.0)
	_ = bonus2
	_ = matched2

	// Test InvalidateFeatureMask
	InvalidateFeatureMask(analysis)
	if analysis.FeatureMaskValid {
		t.Error("FeatureMaskValid should be false after InvalidateFeatureMask")
	}

	// Test UpdateFeatureMask
	analysis.FeatureMaskValid = true
	UpdateFeatureMask(analysis, "feature_1", true)
	UpdateFeatureMask(analysis, "feature_1", false)
	UpdateFeatureMask(analysis, "unknown_feature", true)

	// Test AddFeatureWithMask
	AddFeatureWithMask(analysis, types.Feature{ID: "feature_1"})
}

func TestSynergyBatch(t *testing.T) {
	analyses := []*types.MethodAnalysis{
		{FeatureMap: map[string]bool{"f1": true}},
		{FeatureMap: map[string]bool{"f2": true}},
	}

	results := CalculateSynergyBatch(analyses)
	if len(results) != 2 {
		t.Errorf("Expected 2 results, got %d", len(results))
	}

	// Parallel batch
	resultsParallel := CalculateSynergyBatchParallel(analyses)
	if len(resultsParallel) != 2 {
		t.Errorf("Expected 2 results, got %d", len(resultsParallel))
	}

	// Large batch for parallel
	largeAnalyses := make([]*types.MethodAnalysis, 150)
	for i := range largeAnalyses {
		largeAnalyses[i] = &types.MethodAnalysis{FeatureMap: map[string]bool{"f1": true}}
	}
	resultsLarge := CalculateSynergyBatchParallel(largeAnalyses)
	if len(resultsLarge) != 150 {
		t.Errorf("Expected 150 results, got %d", len(resultsLarge))
	}
}

func TestSynergyStats(t *testing.T) {
	ResetSynergyStats()
	stats := GetSynergyStats()
	if stats.TotalCalculations != 0 {
		t.Error("Stats should be reset")
	}
}

func TestSynergyNativeLegacy(t *testing.T) {
	analyzer := &MethodAnalyzer{}
	analysis := &types.MethodAnalysis{
		FeatureMap: map[string]bool{"f1": true},
	}

	bonus, matched := analyzer.CalculateSynergyNativeLegacy(analysis)
	_ = bonus
	_ = matched
}
