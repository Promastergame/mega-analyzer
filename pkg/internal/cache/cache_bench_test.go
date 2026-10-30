package cache

import (
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// BENCHMARK TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func BenchmarkShardedCache_Get(b *testing.B) {
	cache := NewShardedCache[int, int](10000)

	// Pre-populate
	for i := 0; i < 1000; i++ {
		cache.Put(i, i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Get(i % 1000)
	}
}

func BenchmarkShardedCache_Put(b *testing.B) {
	cache := NewShardedCache[int, int](10000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Put(i, i)
	}
}

func BenchmarkShardedCache_PutGet(b *testing.B) {
	cache := NewShardedCache[int, int](10000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if i%2 == 0 {
			cache.Put(i, i)
		} else {
			cache.Get(i)
		}
	}
}

func BenchmarkShardedCache_Concurrent(b *testing.B) {
	cache := NewShardedCache[int, int](10000)

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			if i%2 == 0 {
				cache.Put(i, i)
			} else {
				cache.Get(i)
			}
			i++
		}
	})
}

func BenchmarkShardedCache_StringKeys(b *testing.B) {
	cache := NewShardedCache[string, int](10000)

	keys := make([]string, 1000)
	for i := 0; i < 1000; i++ {
		keys[i] = string(rune('a' + (i % 26)))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if i%2 == 0 {
			cache.Put(keys[i%1000], i)
		} else {
			cache.Get(keys[i%1000])
		}
	}
}
