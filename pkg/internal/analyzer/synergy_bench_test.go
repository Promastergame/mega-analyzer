package analyzer

import (
	"mega-analyzer/pkg/internal/types"
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// SYNERGY OPTIMIZATION BENCHMARKS (Task 8)
// ═══════════════════════════════════════════════════════════════════════════════
//
// These benchmarks verify the synergy rule optimizations from Task 8:
//   - Bitmask-based feature tracking (O(1) vs O(N))
//   - Short-circuit evaluation
//   - Priority-based rule evaluation

// BenchmarkSynergyCalculation_MapBased measures old map-based approach
func BenchmarkSynergyCalculation_MapBased(b *testing.B) {
	analyzer := NewDefaultMethodAnalyzer()

	analysis := &types.MethodAnalysis{
		FeatureMap: map[string]bool{
			"returns_boolean":       true,
			"name_contains_license": true,
			"has_conditions":        true,
			"calls_license_api":     true,
			"has_try_catch":         true,
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = analyzer.calculateSynergy(analysis)
	}
}

// BenchmarkSynergyCalculation_Bitmask measures new bitmask approach
func BenchmarkSynergyCalculation_Bitmask(b *testing.B) {
	analyzer := NewDefaultMethodAnalyzer()

	analysis := &types.MethodAnalysis{
		FeatureMap: map[string]bool{
			"returns_boolean":       true,
			"name_contains_license": true,
			"has_conditions":        true,
			"calls_license_api":     true,
			"has_try_catch":         true,
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = analyzer.CalculateSynergyOptimized(analysis)
	}
}

// BenchmarkFeatureMaskBuild measures mask building performance
func BenchmarkFeatureMaskBuild(b *testing.B) {
	featureMap := map[string]bool{
		"returns_boolean":          true,
		"name_contains_license":    true,
		"has_conditions":           true,
		"calls_license_api":        true,
		"has_try_catch":            true,
		"has_early_return":         true,
		"calls_billing_api":        true,
		"reads_shared_preferences": true,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = BuildFeatureMask(featureMap)
	}
}

// BenchmarkBitmaskMatch measures single rule matching
func BenchmarkBitmaskMatch(b *testing.B) {
	rule := BitmaskSynergyRule{
		RequiredMask: BitReturnsBoolean | BitNameContainsLicense | BitHasConditions,
		Bonus:        8.0,
		Name:         "License check method",
	}

	featureMask := BitReturnsBoolean | BitNameContainsLicense | BitHasConditions | BitCallsLicenseAPI

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = rule.Matches(featureMask)
	}
}

// BenchmarkMapLookup measures map-based feature checking
func BenchmarkMapLookup(b *testing.B) {
	featureMap := map[string]bool{
		"returns_boolean":       true,
		"name_contains_license": true,
		"has_conditions":        true,
	}

	required := []string{"returns_boolean", "name_contains_license", "has_conditions"}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		allPresent := true
		for _, req := range required {
			if !featureMap[req] {
				allPresent = false
				break
			}
		}
		_ = allPresent
	}
}

// BenchmarkSynergyWithThreshold measures early exit optimization
func BenchmarkSynergyWithThreshold(b *testing.B) {
	featureMask := BitReturnsBoolean | BitNameContainsLicense | BitHasConditions |
		BitCallsLicenseAPI | BitHasTryCatch

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = CalculateSynergyBitmaskWithThreshold(featureMask, 10.0)
	}
}

// BenchmarkSynergyWithoutThreshold measures full evaluation
func BenchmarkSynergyWithoutThreshold(b *testing.B) {
	featureMask := BitReturnsBoolean | BitNameContainsLicense | BitHasConditions |
		BitCallsLicenseAPI | BitHasTryCatch

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = CalculateSynergyBitmask(featureMask)
	}
}

// BenchmarkFeatureCheck_Bitmask measures bitmask feature checking
func BenchmarkFeatureCheck_Bitmask(b *testing.B) {
	mask := BitReturnsBoolean | BitNameContainsLicense | BitHasConditions

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = HasFeature(mask, "returns_boolean")
		_ = HasFeature(mask, "name_contains_license")
		_ = HasFeature(mask, "has_conditions")
	}
}

// BenchmarkFeatureCheck_Map measures map-based feature checking
func BenchmarkFeatureCheck_Map(b *testing.B) {
	featureMap := map[string]bool{
		"returns_boolean":       true,
		"name_contains_license": true,
		"has_conditions":        true,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = featureMap["returns_boolean"]
		_ = featureMap["name_contains_license"]
		_ = featureMap["has_conditions"]
	}
}

// BenchmarkSynergyScenarios tests different feature combinations
func BenchmarkSynergyScenarios(b *testing.B) {
	b.Run("NoMatches", func(b *testing.B) {
		mask := BitReturnsVoid | BitShortMethod
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_, _ = CalculateSynergyBitmask(mask)
		}
	})

	b.Run("OneMatch", func(b *testing.B) {
		mask := BitReturnsBoolean | BitNameContainsPremium
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_, _ = CalculateSynergyBitmask(mask)
		}
	})

	b.Run("MultipleMatches", func(b *testing.B) {
		mask := BitReturnsBoolean | BitNameContainsLicense | BitHasConditions |
			BitCallsLicenseAPI | BitHasTryCatch | BitHasEarlyReturn
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_, _ = CalculateSynergyBitmask(mask)
		}
	})

	b.Run("AllFeatures", func(b *testing.B) {
		// Set all bits
		mask := FeatureBit(^uint64(0))
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_, _ = CalculateSynergyBitmask(mask)
		}
	})
}

// BenchmarkFullAnalysisWithSynergy measures complete analysis with synergy
func BenchmarkFullAnalysisWithSynergy(b *testing.B) {
	b.Run("MapBased", func(b *testing.B) {
		analyzer := NewDefaultMethodAnalyzer()

		analysis := &types.MethodAnalysis{
			Features: []types.Feature{
				{ID: "returns_boolean", Weight: 2.0, Confidence: 1.0},
				{ID: "name_contains_license", Weight: 3.0, Confidence: 1.0},
				{ID: "has_conditions", Weight: 1.5, Confidence: 1.0},
			},
			FeatureMap: map[string]bool{
				"returns_boolean":       true,
				"name_contains_license": true,
				"has_conditions":        true,
			},
		}

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			baseScore := analyzer.calculateScore(analysis)
			synergyBonus, _ := analyzer.calculateSynergy(analysis)
			_ = baseScore + synergyBonus
		}
	})

	b.Run("Bitmask", func(b *testing.B) {
		analyzer := NewDefaultMethodAnalyzer()

		analysis := &types.MethodAnalysis{
			Features: []types.Feature{
				{ID: "returns_boolean", Weight: 2.0, Confidence: 1.0},
				{ID: "name_contains_license", Weight: 3.0, Confidence: 1.0},
				{ID: "has_conditions", Weight: 1.5, Confidence: 1.0},
			},
			FeatureMap: map[string]bool{
				"returns_boolean":       true,
				"name_contains_license": true,
				"has_conditions":        true,
			},
		}

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			baseScore := analyzer.calculateScore(analysis)
			synergyBonus, _ := analyzer.CalculateSynergyOptimized(analysis)
			_ = baseScore + synergyBonus
		}
	})
}

// BenchmarkBitwiseOperations measures raw bitwise performance
func BenchmarkBitwiseOperations(b *testing.B) {
	b.Run("BitwiseAND", func(b *testing.B) {
		mask := FeatureBit(0x12345678)
		required := FeatureBit(0x12340000)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = (mask & required) == required
		}
	})

	b.Run("BitwiseOR", func(b *testing.B) {
		mask := FeatureBit(0x12345678)
		bit := FeatureBit(0x00001000)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = mask | bit
		}
	})

	b.Run("BitwiseXOR", func(b *testing.B) {
		mask := FeatureBit(0x12345678)
		bit := FeatureBit(0x00001000)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = mask ^ bit
		}
	})
}

// BenchmarkShortCircuit measures short-circuit evaluation benefit
func BenchmarkShortCircuit(b *testing.B) {
	b.Run("EarlyExit_FirstBitMissing", func(b *testing.B) {
		// First required bit is missing - should exit immediately
		mask := BitNameContainsLicense | BitHasConditions
		rule := BitmaskSynergyRule{
			RequiredMask: BitReturnsBoolean | BitNameContainsLicense | BitHasConditions,
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = rule.Matches(mask)
		}
	})

	b.Run("EarlyExit_LastBitMissing", func(b *testing.B) {
		// Last required bit is missing - still single operation
		mask := BitReturnsBoolean | BitNameContainsLicense
		rule := BitmaskSynergyRule{
			RequiredMask: BitReturnsBoolean | BitNameContainsLicense | BitHasConditions,
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = rule.Matches(mask)
		}
	})

	b.Run("AllBitsPresent", func(b *testing.B) {
		// All bits present - full match
		mask := BitReturnsBoolean | BitNameContainsLicense | BitHasConditions
		rule := BitmaskSynergyRule{
			RequiredMask: BitReturnsBoolean | BitNameContainsLicense | BitHasConditions,
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = rule.Matches(mask)
		}
	})
}

// BenchmarkConcurrentSynergy measures concurrent synergy calculation
func BenchmarkConcurrentSynergy(b *testing.B) {
	mask := BitReturnsBoolean | BitNameContainsLicense | BitHasConditions |
		BitCallsLicenseAPI | BitHasTryCatch

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = CalculateSynergyBitmask(mask)
		}
	})
}
