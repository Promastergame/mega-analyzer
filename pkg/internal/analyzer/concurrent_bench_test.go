package analyzer

import (
	"mega-analyzer/pkg/internal/types"
	"runtime"
	"sync"
	"testing"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// CONCURRENCY BENCHMARKS (Task 12)
// ═══════════════════════════════════════════════════════════════════════════════
//
// These benchmarks verify concurrent processing achieves near-linear scaling

// BenchmarkShardedCache measures sharded cache performance
func BenchmarkShardedCache(b *testing.B) {
	b.Run("Get_SingleThread", func(b *testing.B) {
		cache := NewShardedCache(16)
		cache.Set("key1", "value1")
		cache.Set("key2", "value2")
		cache.Set("key3", "value3")

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_, _ = cache.Get("key1")
			_, _ = cache.Get("key2")
			_, _ = cache.Get("key3")
		}
	})

	b.Run("Get_Concurrent", func(b *testing.B) {
		cache := NewShardedCache(16)
		cache.Set("key1", "value1")
		cache.Set("key2", "value2")
		cache.Set("key3", "value3")

		b.ResetTimer()
		b.ReportAllocs()

		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_, _ = cache.Get("key1")
				_, _ = cache.Get("key2")
				_, _ = cache.Get("key3")
			}
		})
	})

	b.Run("Set_SingleThread", func(b *testing.B) {
		cache := NewShardedCache(16)

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			cache.Set("key1", i)
			cache.Set("key2", i)
			cache.Set("key3", i)
		}
	})

	b.Run("Set_Concurrent", func(b *testing.B) {
		cache := NewShardedCache(16)

		b.ResetTimer()
		b.ReportAllocs()

		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				cache.Set("key1", i)
				cache.Set("key2", i)
				cache.Set("key3", i)
				i++
			}
		})
	})
}

// BenchmarkShardedCache_Contention measures lock contention
func BenchmarkShardedCache_Contention(b *testing.B) {
	b.Run("1Shard", func(b *testing.B) {
		cache := NewShardedCache(1)
		for i := 0; i < 100; i++ {
			cache.Set(string(rune(i)), i)
		}

		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_, _ = cache.Get("key1")
			}
		})
	})

	b.Run("4Shards", func(b *testing.B) {
		cache := NewShardedCache(4)
		for i := 0; i < 100; i++ {
			cache.Set(string(rune(i)), i)
		}

		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_, _ = cache.Get("key1")
			}
		})
	})

	b.Run("16Shards", func(b *testing.B) {
		cache := NewShardedCache(16)
		for i := 0; i < 100; i++ {
			cache.Set(string(rune(i)), i)
		}

		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_, _ = cache.Get("key1")
			}
		})
	})

	b.Run("64Shards", func(b *testing.B) {
		cache := NewShardedCache(64)
		for i := 0; i < 100; i++ {
			cache.Set(string(rune(i)), i)
		}

		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_, _ = cache.Get("key1")
			}
		})
	})
}

// BenchmarkParallelSynergy measures parallel synergy calculation
func BenchmarkParallelSynergy(b *testing.B) {
	// Create 1000 analyses
	analyses := make([]*types.MethodAnalysis, 1000)
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
			for _, analysis := range analyses {
				_, _ = CalculateSynergyNative(analysis)
			}
		}
	})

	b.Run("Parallel_1Worker", func(b *testing.B) {
		calc := NewParallelSynergyCalculator(1)
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_ = calc.Calculate(analyses)
		}
	})

	b.Run("Parallel_2Workers", func(b *testing.B) {
		calc := NewParallelSynergyCalculator(2)
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_ = calc.Calculate(analyses)
		}
	})

	b.Run("Parallel_4Workers", func(b *testing.B) {
		calc := NewParallelSynergyCalculator(4)
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_ = calc.Calculate(analyses)
		}
	})

	b.Run("Parallel_8Workers", func(b *testing.B) {
		calc := NewParallelSynergyCalculator(8)
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_ = calc.Calculate(analyses)
		}
	})
}

// BenchmarkWorkerPool measures worker pool performance
func BenchmarkWorkerPool(b *testing.B) {
	analyzer := NewDefaultMethodAnalyzer()

	// Create test data
	method := &types.SmaliMethod{
		Name:       "isLicensed",
		ReturnType: "Z",
	}
	class := &types.SmaliClass{
		Name: "Lcom/app/LicenseChecker;",
	}

	b.Run("1Worker", func(b *testing.B) {
		pool := NewWorkerPool(analyzer, 1)
		pool.Start()

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			pool.Submit(&AnalysisJob{Method: method, Class: class, ID: i})
			<-pool.Results()
		}

		pool.Stop()
	})

	b.Run("2Workers", func(b *testing.B) {
		pool := NewWorkerPool(analyzer, 2)
		pool.Start()

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			pool.Submit(&AnalysisJob{Method: method, Class: class, ID: i})
			<-pool.Results()
		}

		pool.Stop()
	})

	b.Run("4Workers", func(b *testing.B) {
		pool := NewWorkerPool(analyzer, 4)
		pool.Start()

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			pool.Submit(&AnalysisJob{Method: method, Class: class, ID: i})
			<-pool.Results()
		}

		pool.Stop()
	})
}

// BenchmarkScaling measures scaling efficiency
func BenchmarkScaling(b *testing.B) {
	// Create 10000 analyses
	analyses := make([]*types.MethodAnalysis, 10000)
	for i := range analyses {
		analyses[i] = &types.MethodAnalysis{
			FeatureMap: map[string]bool{
				"returns_boolean":       true,
				"name_contains_license": i%2 == 0,
				"has_conditions":        i%3 == 0,
			},
		}
		BuildAndCacheFeatureMask(analyses[i])
	}

	numCPU := runtime.NumCPU()

	for workers := 1; workers <= numCPU; workers *= 2 {
		b.Run(string(rune('0'+workers))+"Workers", func(b *testing.B) {
			calc := NewParallelSynergyCalculator(workers)

			b.ResetTimer()
			start := time.Now()

			for i := 0; i < b.N; i++ {
				_ = calc.Calculate(analyses)
			}

			elapsed := time.Since(start)
			opsPerSec := float64(b.N*len(analyses)) / elapsed.Seconds()
			b.ReportMetric(opsPerSec/1e6, "Mops/s")
		})
	}
}

// BenchmarkLockFreeAggregation measures lock-free result aggregation
func BenchmarkLockFreeAggregation(b *testing.B) {
	numWorkers := 4
	totalJobs := 1000

	b.Run("LockFree", func(b *testing.B) {
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			agg := NewResultAggregator(numWorkers, totalJobs)

			// Simulate workers adding results
			for w := 0; w < numWorkers; w++ {
				result := &AnalysisResult{ID: w}
				agg.Add(w, result)
			}

			_ = agg.Collect()
		}
	})

	b.Run("WithMutex", func(b *testing.B) {
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			var mu sync.Mutex
			results := make([]*AnalysisResult, 0, totalJobs)

			// Simulate workers adding results
			for w := 0; w < numWorkers; w++ {
				result := &AnalysisResult{ID: w}
				mu.Lock()
				results = append(results, result)
				mu.Unlock()
			}

			_ = results
		}
	})
}

// BenchmarkCacheHitRate measures cache hit rate impact
func BenchmarkCacheHitRate(b *testing.B) {
	cache := NewShardedCache(16)

	// Pre-populate cache
	for i := 0; i < 1000; i++ {
		cache.Set(string(rune(i)), i)
	}

	b.Run("100%_HitRate", func(b *testing.B) {
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_, _ = cache.Get("0")
		}
	})

	b.Run("50%_HitRate", func(b *testing.B) {
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			if i%2 == 0 {
				_, _ = cache.Get("0")
			} else {
				_, _ = cache.Get("nonexistent")
			}
		}
	})

	b.Run("0%_HitRate", func(b *testing.B) {
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_, _ = cache.Get("nonexistent")
		}
	})
}

// BenchmarkHashFunction measures hash function performance
func BenchmarkHashFunction(b *testing.B) {
	keys := []string{
		"short",
		"medium_length_key",
		"very_long_key_with_many_characters_to_hash",
	}

	b.Run("FNV1a", func(b *testing.B) {
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			for _, key := range keys {
				_ = fnv1aHash(key)
			}
		}
	})
}

// BenchmarkConcurrentSynergyThroughput measures maximum throughput
func BenchmarkConcurrentSynergyThroughput(b *testing.B) {
	// Create large batch
	analyses := make([]*types.MethodAnalysis, 100000)
	for i := range analyses {
		analyses[i] = &types.MethodAnalysis{
			FeatureMap: map[string]bool{
				"returns_boolean": true,
				"has_conditions":  i%2 == 0,
			},
		}
		BuildAndCacheFeatureMask(analyses[i])
	}

	calc := NewParallelSynergyCalculator(runtime.NumCPU())

	b.ResetTimer()
	start := time.Now()

	for i := 0; i < b.N; i++ {
		_ = calc.Calculate(analyses)
	}

	elapsed := time.Since(start)
	opsPerSec := float64(b.N*len(analyses)) / elapsed.Seconds()
	b.ReportMetric(opsPerSec/1e6, "Mops/s")
}
