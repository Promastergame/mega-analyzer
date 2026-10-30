package filter

import (
	"testing"
)

var resultSink any

// ═══════════════════════════════════════════════════════════════════════════════
// BENCHMARK SUITE: Filter Performance Baseline
//
// Establishes baseline metrics for:
// - Path classification performance
// - Fast-path vs full classification
// - Cache hit/miss performance
// - Path normalization overhead
// - Prefix matching performance
// - Critical keyword detection
//
// Run with: go test -bench=. -benchmem -cpuprofile=cpu.prof -memprofile=mem.prof
// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
// BASELINE: Core Classification
// ═══════════════════════════════════════════════════════════════════════════════

func BenchmarkIsAppCode(b *testing.B) {
	f := NewFilter()

	paths := []string{
		"smali/com/myapp/MainActivity.smali",
		"smali/com/google/android/gms/ads/AdView.smali",
		"smali/androidx/appcompat/app/AppCompatActivity.smali",
		"smali/com/myapp/security/LicenseChecker.smali",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		for _, path := range paths {
			_ = f.IsAppCode(path)
		}
	}
}

func BenchmarkGetImportance(b *testing.B) {
	f := NewFilter()

	paths := []string{
		"smali/com/myapp/MainActivity.smali",
		"smali/com/myapp/security/LicenseChecker.smali",
		"smali/com/myapp/billing/PurchaseVerifier.smali",
		"smali/com/google/android/gms/ads/AdView.smali",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		for _, path := range paths {
			_ = f.GetImportance(path)
		}
	}
}

func BenchmarkClassify(b *testing.B) {
	f := NewFilter()
	path := "smali/com/myapp/security/LicenseChecker.smali"

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = f.Classify(path)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// BASELINE: Fast-Path Performance
// ═══════════════════════════════════════════════════════════════════════════════

func BenchmarkTryFastPath_Hit(b *testing.B) {
	f := NewFilter()
	// Known library path (should hit fast-path)
	path := "smali/com/google/android/gms/ads/AdView.smali"

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = f.tryFastPath(path)
	}
}

func BenchmarkTryFastPath_Miss(b *testing.B) {
	f := NewFilter()
	// App code path (should miss fast-path)
	path := "smali/com/myapp/MainActivity.smali"

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = f.tryFastPath(path)
	}
}

func BenchmarkTryFastPath_CriticalKeyword(b *testing.B) {
	f := NewFilter()
	// Library path with critical keyword (should miss fast-path)
	path := "smali/com/android/billingclient/api/Purchase.smali"

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = f.tryFastPath(path)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// BASELINE: Path Normalization
// ═══════════════════════════════════════════════════════════════════════════════

func BenchmarkPathNormalization_Unix(b *testing.B) {
	path := "smali/com/myapp/security/LicenseChecker.smali"

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		normalized := path
		if len(normalized) > 0 {
			_ = toLowerFast(normalized)
		}
	}
}

func BenchmarkPathNormalization_Windows(b *testing.B) {
	path := "smali\\com\\myapp\\security\\LicenseChecker.smali"

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		normalized := path
		// Simulate normalization
		for j := 0; j < len(normalized); j++ {
			if normalized[j] == '\\' {
				// Would need to allocate new string
				break
			}
		}
		_ = toLowerFast(normalized)
	}
}

func BenchmarkToLowerFast(b *testing.B) {
	paths := []string{
		"smali/com/myapp/MainActivity.smali",
		"SMALI/COM/MYAPP/MAINACTIVITY.SMALI",
		"smali/com/myapp/mainactivity.smali", // already lowercase
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		for _, path := range paths {
			_ = toLowerFast(path)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// BASELINE: Critical Keyword Detection
// ═══════════════════════════════════════════════════════════════════════════════

func BenchmarkContainsCriticalKeyword_NoMatch(b *testing.B) {
	path := "smali/com/google/android/gms/ads/adview.smali"

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = containsCriticalKeywordBoundary(path)
	}
}

func BenchmarkContainsCriticalKeyword_Match(b *testing.B) {
	path := "smali/com/myapp/billing/purchaseverifier.smali"

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = containsCriticalKeywordBoundary(path)
	}
}

func BenchmarkIsAtWordBoundary(b *testing.B) {
	s := "smali/com/myapp/billing/purchase.smali"
	idx := 21 // "billing"
	length := 7

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = isAtWordBoundary(s, idx, length)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// BASELINE: Prefix Index Lookup
// ═══════════════════════════════════════════════════════════════════════════════

func BenchmarkExtractIndexKeyFromPath(b *testing.B) {
	paths := []string{
		"smali/com/google/android/gms/ads/AdView.smali",
		"smali/androidx/appcompat/app/AppCompatActivity.smali",
		"smali/kotlin/collections/List.smali",
		"smali/com/myapp/MainActivity.smali",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		for _, path := range paths {
			_, _ = extractIndexKeyFromPath(path)
		}
	}
}

func BenchmarkPrefixIndexLookup(b *testing.B) {
	paths := []string{
		"smali/com/google/android/gms/ads/adview.smali",
		"smali/androidx/appcompat/app/appcompatactivity.smali",
		"smali/kotlin/collections/list.smali",
		"smali/com/myapp/mainactivity.smali",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		for _, path := range paths {
			_ = prefixIdx.lookup(path)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// BASELINE: Optimized API
// ═══════════════════════════════════════════════════════════════════════════════

func BenchmarkClassifyForPipeline(b *testing.B) {
	f := NewFilter()

	paths := []string{
		"smali/com/myapp/MainActivity.smali",
		"smali/com/myapp/security/LicenseChecker.smali",
		"smali/com/google/android/gms/ads/AdView.smali",
		"smali/androidx/appcompat/app/AppCompatActivity.smali",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		for _, path := range paths {
			_ = f.ClassifyForPipeline(path)
		}
	}
}

// Compare: old way (2 calls) vs new way (1 call)
func BenchmarkClassify_TwoCalls(b *testing.B) {
	f := NewFilter()
	path := "smali/com/myapp/security/LicenseChecker.smali"

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = f.IsAppCode(path)
		_ = f.GetImportance(path)
	}
}

func BenchmarkClassify_OneCall(b *testing.B) {
	f := NewFilter()
	path := "smali/com/myapp/security/LicenseChecker.smali"

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = f.ClassifyForPipeline(path)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// BASELINE: Batch Classification
// ═══════════════════════════════════════════════════════════════════════════════

func BenchmarkClassifyBatch(b *testing.B) {
	f := NewFilter()

	paths := make([]string, 100)
	for i := range paths {
		switch i % 4 {
		case 0:
			paths[i] = "smali/com/myapp/MainActivity.smali"
		case 1:
			paths[i] = "smali/com/myapp/security/LicenseChecker.smali"
		case 2:
			paths[i] = "smali/com/google/android/gms/ads/AdView.smali"
		default:
			paths[i] = "smali/androidx/appcompat/app/AppCompatActivity.smali"
		}
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = f.ClassifyBatch(paths)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// BASELINE: High-Value Detection
// ═══════════════════════════════════════════════════════════════════════════════

func BenchmarkIsHighValue(b *testing.B) {
	f := NewFilter()

	paths := []string{
		"smali/com/myapp/security/LicenseChecker.smali",
		"smali/com/myapp/billing/PurchaseVerifier.smali",
		"smali/com/myapp/premium/PremiumChecker.smali",
		"smali/com/myapp/MainActivity.smali",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		for _, path := range paths {
			_ = f.IsHighValue(path)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// BASELINE: Category Results
// ═══════════════════════════════════════════════════════════════════════════════

func BenchmarkGetCategoryResult(b *testing.B) {
	categories := []string{
		"sdk",
		"kotlin",
		"google",
		"network",
		"common",
		"ads_sdk",
		"billing_lib",
		"crypto",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		for _, cat := range categories {
			_ = getCategoryResult(cat)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// BASELINE: Concurrent Classification
// ═══════════════════════════════════════════════════════════════════════════════

func BenchmarkConcurrentClassify(b *testing.B) {
	f := NewFilter()

	paths := []string{
		"smali/com/myapp/MainActivity.smali",
		"smali/com/myapp/security/LicenseChecker.smali",
		"smali/com/google/android/gms/ads/AdView.smali",
		"smali/androidx/appcompat/app/AppCompatActivity.smali",
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			_ = f.Classify(paths[i%len(paths)])
			i++
		}
	})
}

// ═══════════════════════════════════════════════════════════════════════════════
// MEMORY ALLOCATION BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

func BenchmarkFileClassificationAllocation(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = FileClassification{
			IsAppCode:  true,
			Importance: 8,
		}
	}
}

func BenchmarkClassificationResultAllocation(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		resultSink = &ClassificationResult{
			IsAppCode:         true,
			IsLibrary:         false,
			Importance:        8,
			RawImportance:     8,
			Confidence:        0.85,
			RawStrength:       SignalStrong,
			EffectiveStrength: SignalStrong,
			TotalDampening:    1.0,
			Categories:        []string{"app", "security"},
		}
	}
}
