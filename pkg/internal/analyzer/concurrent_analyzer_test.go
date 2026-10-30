package analyzer

import (
	"sync"
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// ShardedCache tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestNewShardedCache_Default(t *testing.T) {
	cache := NewShardedCache(0)
	if cache == nil {
		t.Fatal("expected non-nil")
	}
	if cache.numShards != 16 {
		t.Fatalf("numShards = %d, want 16 (default)", cache.numShards)
	}
}

func TestNewShardedCache_PowerOf2(t *testing.T) {
	cache := NewShardedCache(10)
	if cache.numShards != 16 { // next power of 2 after 10
		t.Fatalf("numShards = %d, want 16", cache.numShards)
	}
}

func TestNewShardedCache_ExactPowerOf2(t *testing.T) {
	cache := NewShardedCache(8)
	if cache.numShards != 8 {
		t.Fatalf("numShards = %d, want 8", cache.numShards)
	}
}

func TestShardedCache_SetAndGet(t *testing.T) {
	cache := NewShardedCache(4)
	cache.Set("key1", "value1")
	cache.Set("key2", 42)

	v1, ok := cache.Get("key1")
	if !ok || v1 != "value1" {
		t.Fatalf("Get(key1) = %v, %v", v1, ok)
	}

	v2, ok := cache.Get("key2")
	if !ok || v2 != 42 {
		t.Fatalf("Get(key2) = %v, %v", v2, ok)
	}
}

func TestShardedCache_Get_Miss(t *testing.T) {
	cache := NewShardedCache(4)
	_, ok := cache.Get("nonexistent")
	if ok {
		t.Fatal("expected miss")
	}
}

func TestShardedCache_Delete(t *testing.T) {
	cache := NewShardedCache(4)
	cache.Set("key", "value")
	cache.Delete("key")

	_, ok := cache.Get("key")
	if ok {
		t.Fatal("expected miss after delete")
	}
}

func TestShardedCache_Clear(t *testing.T) {
	cache := NewShardedCache(4)
	cache.Set("a", 1)
	cache.Set("b", 2)
	cache.Set("c", 3)

	cache.Clear()

	_, ok := cache.Get("a")
	if ok {
		t.Fatal("expected miss after clear")
	}
}

func TestShardedCache_Stats(t *testing.T) {
	cache := NewShardedCache(4)
	cache.Set("key", "value")
	cache.Get("key")         // hit
	cache.Get("nonexistent") // miss

	hits, misses := cache.Stats()
	if hits != 1 {
		t.Fatalf("hits = %d, want 1", hits)
	}
	if misses != 1 {
		t.Fatalf("misses = %d, want 1", misses)
	}
}

func TestShardedCache_Concurrent(t *testing.T) {
	cache := NewShardedCache(16)
	var wg sync.WaitGroup

	// Concurrent writes
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := "key" + string(rune('A'+i%26))
			cache.Set(key, i)
			cache.Get(key)
		}(i)
	}
	wg.Wait()

	// Should not panic or deadlock
	hits, misses := cache.Stats()
	if hits+misses == 0 {
		t.Fatal("expected some operations")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// ResultAggregator tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestNewResultAggregator(t *testing.T) {
	ra := NewResultAggregator(4, 100)
	if ra == nil {
		t.Fatal("expected non-nil")
	}
	if ra.numSlots != 4 {
		t.Fatalf("numSlots = %d, want 4", ra.numSlots)
	}
}

func TestResultAggregator_AddAndCollect(t *testing.T) {
	ra := NewResultAggregator(3, 10)

	r1 := &AnalysisResult{ID: 1}
	r2 := &AnalysisResult{ID: 2}

	ra.Add(0, r1)
	ra.Add(1, r2)

	collected := ra.Collect()
	if len(collected) != 2 {
		t.Fatalf("expected 2 results, got %d", len(collected))
	}
}

func TestResultAggregator_Collect_Empty(t *testing.T) {
	ra := NewResultAggregator(4, 10)
	collected := ra.Collect()
	if len(collected) != 0 {
		t.Fatalf("expected 0 results, got %d", len(collected))
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Utility function tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestNextPowerOf2(t *testing.T) {
	tests := []struct {
		input int
		want  int
	}{
		{0, 1},
		{1, 1},
		{2, 2},
		{3, 4},
		{4, 4},
		{5, 8},
		{7, 8},
		{8, 8},
		{9, 16},
		{15, 16},
		{16, 16},
		{17, 32},
	}
	for _, tt := range tests {
		got := nextPowerOf2(tt.input)
		if got != tt.want {
			t.Errorf("nextPowerOf2(%d) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestFnv1aHash(t *testing.T) {
	// Same input should produce same hash
	h1 := fnv1aHash("test")
	h2 := fnv1aHash("test")
	if h1 != h2 {
		t.Fatal("same input should produce same hash")
	}

	// Different input should produce different hash
	h3 := fnv1aHash("other")
	if h1 == h3 {
		t.Fatal("different input should produce different hash")
	}

	// Empty string should not panic
	_ = fnv1aHash("")
}

func TestNewWorkerPool_DefaultWorkers(t *testing.T) {
	wp := NewWorkerPool(nil, 0)
	if wp.numWorkers <= 0 {
		t.Fatalf("numWorkers should be positive, got %d", wp.numWorkers)
	}
}

func TestNewWorkerPool_CustomWorkers(t *testing.T) {
	wp := NewWorkerPool(nil, 8)
	if wp.numWorkers != 8 {
		t.Fatalf("numWorkers = %d, want 8", wp.numWorkers)
	}
}

func TestWorkerPool_Stats_Initial(t *testing.T) {
	wp := NewWorkerPool(nil, 4)
	processed, failed := wp.Stats()
	if processed != 0 || failed != 0 {
		t.Fatalf("initial stats should be 0, got processed=%d, failed=%d", processed, failed)
	}
}

func TestNewParallelSynergyCalculator(t *testing.T) {
	psc := NewParallelSynergyCalculator(0)
	if psc.numWorkers <= 0 {
		t.Fatal("should default to positive workers")
	}

	psc2 := NewParallelSynergyCalculator(4)
	if psc2.numWorkers != 4 {
		t.Fatalf("numWorkers = %d, want 4", psc2.numWorkers)
	}
}

func TestGetConcurrencyStats(t *testing.T) {
	wp := NewWorkerPool(nil, 4)
	cache := NewShardedCache(8)

	cache.Set("x", 1)
	cache.Get("x")
	cache.Get("y")

	stats := GetConcurrencyStats(wp, cache)
	if stats.WorkersActive != 4 {
		t.Fatalf("WorkersActive = %d, want 4", stats.WorkersActive)
	}
	if stats.CacheHits != 1 {
		t.Fatalf("CacheHits = %d, want 1", stats.CacheHits)
	}
	if stats.CacheMisses != 1 {
		t.Fatalf("CacheMisses = %d, want 1", stats.CacheMisses)
	}
	if stats.CacheHitRate != 0.5 {
		t.Fatalf("CacheHitRate = %f, want 0.5", stats.CacheHitRate)
	}
}
