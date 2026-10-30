package cache

import (
	"testing"
	"time"
)

// ─── anyToBytes ────────────────────────────────────────────────────────────────

func TestAnyToBytes_String(t *testing.T) {
	result := anyToBytes("hello")
	if len(result) == 0 {
		t.Error("expected non-empty bytes from string")
	}
	if string(result) != "hello" {
		t.Errorf("expected 'hello', got %q", string(result))
	}
}

func TestAnyToBytes_ByteSlice(t *testing.T) {
	data := []byte("test")
	result := anyToBytes(data)
	if string(result) != "[116 101 115 116]" {
		t.Errorf("expected '[116 101 115 116]', got %q", string(result))
	}
}

func TestAnyToBytes_Int(t *testing.T) {
	result := anyToBytes(42)
	if len(result) == 0 {
		t.Error("expected bytes from int")
	}
}

// ─── anyToString ──────────────────────────────────────────────────────────────

func TestAnyToString_String(t *testing.T) {
	result := anyToString("hello")
	if result != "hello" {
		t.Errorf("expected 'hello', got %q", result)
	}
}

func TestAnyToString_ByteSlice(t *testing.T) {
	result := anyToString([]byte("world"))
	if result != "[119 111 114 108 100]" {
		t.Errorf("expected '[119 111 114 108 100]', got %q", result)
	}
}

func TestAnyToString_Int(t *testing.T) {
	result := anyToString(100)
	if result == "" {
		t.Error("expected non-empty string from int")
	}
}

// ─── estimateMemorySize ───────────────────────────────────────────────────────

func TestEstimateMemorySize_String(t *testing.T) {
	size := estimateMemorySize("hello")
	if size == 0 {
		t.Error("expected non-zero size for string")
	}
}

func TestEstimateMemorySize_ByteSlice(t *testing.T) {
	size := estimateMemorySize([]byte("data"))
	if size == 0 {
		t.Error("expected non-zero size for byte slice")
	}
}

func TestEstimateMemorySize_Int(t *testing.T) {
	size := estimateMemorySize(int64(1000))
	if size == 0 {
		t.Error("expected non-zero size for int64")
	}
}

// ─── hashValue ────────────────────────────────────────────────────────────────

func TestHashValue_String(t *testing.T) {
	hc := NewHashCombiner()
	hashValue(hc, "key")
	h := hc.Sum()
	if h == 0 {
		t.Error("expected non-zero hash")
	}
}

func TestHashValue_Consistency(t *testing.T) {
	hc1 := NewHashCombiner()
	hashValue(hc1, "same")
	h1 := hc1.Sum()

	hc2 := NewHashCombiner()
	hashValue(hc2, "same")
	h2 := hc2.Sum()

	if h1 != h2 {
		t.Error("expected consistent hash for same input")
	}
}

func TestHashValue_Different(t *testing.T) {
	hc1 := NewHashCombiner()
	hashValue(hc1, "key1")
	h1 := hc1.Sum()

	hc2 := NewHashCombiner()
	hashValue(hc2, "key2")
	h2 := hc2.Sum()

	if h1 == h2 {
		t.Error("expected different hashes for different inputs")
	}
}

// ─── CacheManager operations ──────────────────────────────────────────────────

func TestCacheManager_ClearMore(t *testing.T) {
	mgr := NewCacheManager(t.TempDir())
	_ = mgr.Clear()
}

func TestCacheManager_PruneMore(t *testing.T) {
	mgr := NewCacheManager(t.TempDir())
	_, _ = mgr.Prune(1)
}

func TestCacheManager_GetStatsMore(t *testing.T) {
	mgr := NewCacheManager(t.TempDir())
	stats, err := mgr.GetStats()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stats == nil {
		t.Error("expected non-nil stats")
	}
}

// ─── ShardedCache Get/Put/Delete ─────────────────────────────────────────────

func TestShardedCache_GetPut_String(t *testing.T) {
	cache := NewShardedCache[string, string](100)
	cache.Put("key1", "value1")
	val, found := cache.Get("key1")
	if !found {
		t.Error("expected to find key1")
	}
	if val != "value1" {
		t.Errorf("expected 'value1', got %v", val)
	}
}

func TestShardedCache_GetPut_NotFound(t *testing.T) {
	cache := NewShardedCache[string, string](100)
	_, found := cache.Get("nonexistent")
	if found {
		t.Error("expected key not found")
	}
}

func TestShardedCache_Delete(t *testing.T) {
	cache := NewShardedCache[string, string](100)
	cache.Put("key", "value")
	cache.Delete("key")
	_, found := cache.Get("key")
	if found {
		t.Error("expected key to be removed")
	}
}

// ─── ShardedCache with TTL ────────────────────────────────────────────────────

func TestShardedCache_TTLMore(t *testing.T) {
	cfg := CacheConfig[string]{
		Capacity: 10,
		TTL:      50 * time.Millisecond,
	}
	cache := NewShardedCacheWithConfig[string, string](cfg)
	cache.Put("key", "value")

	val, found := cache.Get("key")
	if !found || val != "value" {
		t.Error("expected key to be found initially")
	}

	time.Sleep(100 * time.Millisecond)

	_, found = cache.Get("key")
	if found {
		t.Error("expected key to be expired and not found")
	}
}

// ─── ShardedCache.Size & Capacity & Resize ────────────────────────────────────

func TestShardedCache_SizeAndCapacity(t *testing.T) {
	cache := NewShardedCache[string, string](100)
	cache.Put("k1", "v1")
	cache.Put("k2", "v2")
	if size := cache.Size(); size != 2 {
		t.Errorf("expected size 2, got %d", size)
	}
	if cap := cache.Capacity(); cap != 100 {
		t.Errorf("expected capacity 100, got %d", cap)
	}

	cache.Resize(50)
	if cap := cache.Capacity(); cap != 50 {
		t.Errorf("expected capacity 50 after resize, got %d", cap)
	}
}

// ─── ShardedCache.Clear ──────────────────────────────────────────────────────

func TestShardedCache_ClearMore(t *testing.T) {
	cache := NewShardedCache[string, string](100)
	cache.Put("key", "value")
	cache.Clear()
	if cache.Size() != 0 {
		t.Error("expected cache to be cleared")
	}
}

// ─── ShardedCache.Stats ───────────────────────────────────────────────────────

func TestShardedCache_StatsMore(t *testing.T) {
	cache := NewShardedCache[string, string](10)
	cache.Put("k1", "v1")
	_, _ = cache.Get("k1") // hit
	_, _ = cache.Get("k2") // miss

	stats := cache.Stats()
	if stats.Hits != 1 {
		t.Errorf("expected 1 hit, got %d", stats.Hits)
	}
	if stats.Misses != 1 {
		t.Errorf("expected 1 miss, got %d", stats.Misses)
	}
	if stats.Size != 1 {
		t.Errorf("expected size 1, got %d", stats.Size)
	}
}
