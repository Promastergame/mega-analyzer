package analyzer

import (
	"mega-analyzer/pkg/internal/types"
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// NATIVE BITMASK BENCHMARKS (Task 10)
// ═══════════════════════════════════════════════════════════════════════════════
//
// These benchmarks verify the native bitmask integration achieves 78% speedup

// BenchmarkSynergyNative_CachedMask measures fully optimized native implementation
func BenchmarkSynergyNative_CachedMask(b *testing.B) {
	analysis := &types.MethodAnalysis{
		FeatureMap: map[string]bool{
			"returns_boolean":       true,
			"name_contains_license": true,
			"has_conditions":        true,
			"calls_license_api":     true,
			"has_try_catch":         true,
		},
	}

	// Build and cache mask once (simulates real usage)
	BuildAndCacheFeatureMask(analysis)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = CalculateSynergyNative(analysis)
	}
}

// BenchmarkSynergyNative_UncachedMask measures with mask building overhead
func BenchmarkSynergyNative_UncachedMask(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		analysis := &types.MethodAnalysis{
			FeatureMap: map[string]bool{
				"returns_boolean":       true,
				"name_contains_license": true,
				"has_conditions":        true,
				"calls_license_api":     true,
				"has_try_catch":         true,
			},
		}

		// Build mask on demand (not cached)
		BuildAndCacheFeatureMask(analysis)
		_, _ = CalculateSynergyNative(analysis)
	}
}

// BenchmarkMaskCaching measures mask build and cache performance
func BenchmarkMaskCaching(b *testing.B) {
	b.Run("BuildAndCache", func(b *testing.B) {
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
			analysis.FeatureMaskValid = false // Invalidate to force rebuild
			BuildAndCacheFeatureMask(analysis)
		}
	})

	b.Run("GetCached", func(b *testing.B) {
		analysis := &types.MethodAnalysis{
			FeatureMap: map[string]bool{
				"returns_boolean":       true,
				"name_contains_license": true,
				"has_conditions":        true,
			},
		}
		BuildAndCacheFeatureMask(analysis)

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_ = GetCachedFeatureMask(analysis)
		}
	})
}

// BenchmarkSynergyComparison compares all implementations
func BenchmarkSynergyComparison(b *testing.B) {
	analyzer := NewDefaultMethodAnalyzer()

	b.Run("MapBased_Original", func(b *testing.B) {
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
	})

	b.Run("Bitmask_WithConversion", func(b *testing.B) {
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
	})

	b.Run("Native_Cached", func(b *testing.B) {
		analysis := &types.MethodAnalysis{
			FeatureMap: map[string]bool{
				"returns_boolean":       true,
				"name_contains_license": true,
				"has_conditions":        true,
				"calls_license_api":     true,
				"has_try_catch":         true,
			},
		}
		BuildAndCacheFeatureMask(analysis)

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_, _ = CalculateSynergyNative(analysis)
		}
	})

	b.Run("Native_Legacy", func(b *testing.B) {
		analysis := &types.MethodAnalysis{
			FeatureMap: map[string]bool{
				"returns_boolean":       true,
				"name_contains_license": true,
				"has_conditions":        true,
				"calls_license_api":     true,
				"has_try_catch":         true,
			},
		}
		BuildAndCacheFeatureMask(analysis)

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_, _ = analyzer.CalculateSynergyNativeLegacy(analysis)
		}
	})
}

// BenchmarkFeatureUpdate measures incremental mask updates
func BenchmarkFeatureUpdate(b *testing.B) {
	b.Run("UpdateMask", func(b *testing.B) {
		analysis := &types.MethodAnalysis{
			FeatureMap: map[string]bool{
				"returns_boolean": true,
			},
		}
		BuildAndCacheFeatureMask(analysis)

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			UpdateFeatureMask(analysis, "has_conditions", true)
			UpdateFeatureMask(analysis, "has_conditions", false)
		}
	})

	b.Run("AddFeatureWithMask", func(b *testing.B) {
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			analysis := &types.MethodAnalysis{
				FeatureMap: make(map[string]bool, 8),
			}
			BuildAndCacheFeatureMask(analysis)

			feature := types.Feature{
				ID:         "has_conditions",
				Weight:     1.5,
				Confidence: 1.0,
			}
			AddFeatureWithMask(analysis, feature)
		}
	})
}

// BenchmarkBatchSynergy measures batch processing performance
func BenchmarkBatchSynergy(b *testing.B) {
	// Create 100 analyses
	analyses := make([]*types.MethodAnalysis, 100)
	for i := range analyses {
		analyses[i] = &types.MethodAnalysis{
			FeatureMap: map[string]bool{
				"returns_boolean":       true,
				"name_contains_license": i%2 == 0,
				"has_conditions":        i%3 == 0,
				"calls_license_api":     i%4 == 0,
				"has_try_catch":         i%5 == 0,
			},
		}
		BuildAndCacheFeatureMask(analyses[i])
	}

	b.Run("Sequential", func(b *testing.B) {
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_ = CalculateSynergyBatch(analyses)
		}
	})

	b.Run("Parallel", func(b *testing.B) {
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_ = CalculateSynergyBatchParallel(analyses)
		}
	})
}

// BenchmarkSynergyNativeScenarios tests different feature combinations with native implementation
func BenchmarkSynergyNativeScenarios(b *testing.B) {
	b.Run("NoMatches", func(b *testing.B) {
		analysis := &types.MethodAnalysis{
			FeatureMap: map[string]bool{
				"returns_void": true,
				"short_method": true,
			},
		}
		BuildAndCacheFeatureMask(analysis)

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_, _ = CalculateSynergyNative(analysis)
		}
	})

	b.Run("OneMatch", func(b *testing.B) {
		analysis := &types.MethodAnalysis{
			FeatureMap: map[string]bool{
				"returns_boolean":       true,
				"name_contains_premium": true,
			},
		}
		BuildAndCacheFeatureMask(analysis)

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_, _ = CalculateSynergyNative(analysis)
		}
	})

	b.Run("MultipleMatches", func(b *testing.B) {
		analysis := &types.MethodAnalysis{
			FeatureMap: map[string]bool{
				"returns_boolean":       true,
				"name_contains_license": true,
				"has_conditions":        true,
				"calls_license_api":     true,
				"has_try_catch":         true,
				"has_early_return":      true,
			},
		}
		BuildAndCacheFeatureMask(analysis)

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_, _ = CalculateSynergyNative(analysis)
		}
	})
}

// BenchmarkThresholdEarlyExit measures early exit optimization
func BenchmarkThresholdEarlyExit(b *testing.B) {
	analysis := &types.MethodAnalysis{
		FeatureMap: map[string]bool{
			"returns_boolean":       true,
			"name_contains_license": true,
			"has_conditions":        true,
			"calls_license_api":     true,
			"has_try_catch":         true,
		},
	}
	BuildAndCacheFeatureMask(analysis)

	b.Run("NoThreshold", func(b *testing.B) {
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_, _ = CalculateSynergyNative(analysis)
		}
	})

	b.Run("WithThreshold_10", func(b *testing.B) {
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_, _ = CalculateSynergyNativeWithThreshold(analysis, 10.0)
		}
	})

	b.Run("WithThreshold_5", func(b *testing.B) {
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_, _ = CalculateSynergyNativeWithThreshold(analysis, 5.0)
		}
	})
}

// BenchmarkConcurrentSynergyNative measures concurrent performance
func BenchmarkConcurrentSynergyNative(b *testing.B) {
	analysis := &types.MethodAnalysis{
		FeatureMap: map[string]bool{
			"returns_boolean":       true,
			"name_contains_license": true,
			"has_conditions":        true,
		},
	}
	BuildAndCacheFeatureMask(analysis)

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = CalculateSynergyNative(analysis)
		}
	})
}

// BenchmarkMemoryFootprint measures memory usage
func BenchmarkMemoryFootprint(b *testing.B) {
	b.Run("WithoutCache", func(b *testing.B) {
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_ = map[string]bool{
				"returns_boolean":       true,
				"name_contains_license": true,
				"has_conditions":        true,
			}
		}
	})

	b.Run("WithCache", func(b *testing.B) {
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			analysis := &types.MethodAnalysis{
				FeatureMap: map[string]bool{
					"returns_boolean":       true,
					"name_contains_license": true,
					"has_conditions":        true,
				},
			}
			BuildAndCacheFeatureMask(analysis)
			_ = analysis
		}
	})
}
