package analyzer

import (
	"mega-analyzer/pkg/internal/types"
	"testing"
)

func TestSynergyBitmask(t *testing.T) {
	featureMap := map[string]bool{
		"returns_boolean":       true,
		"name_contains_license": true,
		"has_conditions":        true,
		"unknown_feature":       true,
	}

	// Test BuildFeatureMask
	mask := BuildFeatureMask(featureMap)
	if mask == 0 {
		t.Error("Mask should not be zero")
	}

	// Test BuildFeatureMaskFromAnalysis
	analysis := &types.MethodAnalysis{FeatureMap: featureMap}
	mask2 := BuildFeatureMaskFromAnalysis(analysis)
	if mask2 != mask {
		t.Error("Masks should be equal")
	}

	// Test CalculateSynergyBitmask
	bonus, matched := CalculateSynergyBitmask(mask)
	if bonus < 8.0 {
		t.Errorf("Expected bonus >= 8.0, got %f", bonus)
	}
	if len(matched) == 0 {
		t.Error("Expected matched rules")
	}

	// Test CalculateSynergyBitmaskWithThreshold
	bonusT, matchedT := CalculateSynergyBitmaskWithThreshold(mask, 5.0)
	_ = matchedT
	if bonusT < 5.0 {
		t.Errorf("Expected bonus >= 5.0, got %f", bonusT)
	}

	// Test Matches
	rule := bitmaskSynergyRules[0]
	if !rule.Matches(mask) {
		t.Error("Rule should match")
	}

	// Test ConvertToLegacySynergyRule
	legacy := ConvertToLegacySynergyRule(rule)
	if legacy.name == "" {
		t.Error("Legacy rule should have a name")
	}

	// Test CalculateSynergyOptimized
	analyzer := &MethodAnalyzer{}
	bonusOpt, matchedLegacy := analyzer.CalculateSynergyOptimized(analysis)
	if bonusOpt != bonus {
		t.Error("Optimized bonus should match bitmask bonus")
	}
	if len(matchedLegacy) != len(matched) {
		t.Error("Optimized matched length should match bitmask matched length")
	}
}

func TestBitmaskHelpers(t *testing.T) {
	var mask FeatureBit
	SetFeature(&mask, "returns_int")
	if !HasFeature(mask, "returns_int") {
		t.Error("Feature should be set")
	}
	if HasFeature(mask, "unknown") {
		t.Error("Unknown feature should not be found")
	}

	ClearFeature(&mask, "returns_int")
	if HasFeature(mask, "returns_int") {
		t.Error("Feature should be cleared")
	}

	stats := GetFeatureMaskStats(BitReturnsBoolean | BitReturnsInt)
	if stats.SetBits != 2 {
		t.Errorf("Expected 2 set bits, got %d", stats.SetBits)
	}
}
