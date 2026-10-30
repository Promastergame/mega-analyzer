package cache

import (
	"sync"
	"testing"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// BASIC OPERATIONS TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestShardedCache_BasicOperations(t *testing.T) {
	cache := NewShardedCache[string, int](100)

	// Put and Get
	cache.Put("key1", 42)
	val, ok := cache.Get("key1")
	if !ok {
		t.Fatal("Expected key1 to exist")
	}
	if val != 42 {
		t.Errorf("Expected 42, got %d", val)
	}

	// Miss
	_, ok = cache.Get("nonexistent")
	if ok {
		t.Error("Expected miss for nonexistent key")
	}

	// Update
	cache.Put("key1", 100)
	val, ok = cache.Get("key1")
	if !ok {
		t.Fatal("Expected key1 to exist after update")
	}
	if val != 100 {
		t.Errorf("Expected 100, got %d", val)
	}

	// Delete
	cache.Delete("key1")
	_, ok = cache.Get("key1")
	if ok {
		t.Error("Expected key1 to be deleted")
	}
}

func TestShardedCache_Clear(t *testing.T) {
	cache := NewShardedCache[string, string](100)

	cache.Put("key1", "value1")
	cache.Put("key2", "value2")
	cache.Put("key3", "value3")

	if cache.Size() != 3 {
		t.Errorf("Expected size 3, got %d", cache.Size())
	}

	cache.Clear()

	if cache.Size() != 0 {
		t.Errorf("Expected size 0 after clear, got %d", cache.Size())
	}

	_, ok := cache.Get("key1")
	if ok {
		t.Error("Expected all keys to be cleared")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// LRU EVICTION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestShardedCache_LRUEviction(t *testing.T) {
	// Use capacity of 16 so each shard gets exactly 1 slot
	cache := NewShardedCache[int, string](16)

	// Fill all shards
	for i := 0; i < 20; i++ {
		cache.Put(i, "value")
	}

	// Check that evictions happened
	stats := cache.Stats()
	if stats.Evictions == 0 {
		t.Error("Expected at least one eviction")
	}

	// Size should be at most capacity
	if cache.Size() > cache.Capacity() {
		t.Errorf("Expected size <= %d, got %d", cache.Capacity(), cache.Size())
	}
}

func TestShardedCache_LRUAccess(t *testing.T) {
	cache := NewShardedCache[int, string](3)

	cache.Put(1, "one")
	cache.Put(2, "two")
	cache.Put(3, "three")

	// Access key 1 to make it recently used
	cache.Get(1)

	// Add key 4, which should evict key 2 (least recently used)
	cache.Put(4, "four")

	// Key 1 should still exist
	_, ok := cache.Get(1)
	if !ok {
		t.Error("Expected key 1 to still exist after being accessed")
	}

	// Key 4 should exist
	_, ok = cache.Get(4)
	if !ok {
		t.Error("Expected key 4 to exist")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// TTL TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestShardedCache_TTL(t *testing.T) {
	config := CacheConfig[string]{
		Capacity: 100,
		TTL:      100 * time.Millisecond,
	}
	cache := NewShardedCacheWithConfig[string, int](config)

	cache.Put("key", 42)

	// Should exist immediately
	_, ok := cache.Get("key")
	if !ok {
		t.Error("Expected key to exist immediately")
	}

	// Should expire after TTL
	time.Sleep(150 * time.Millisecond)
	_, ok = cache.Get("key")
	if ok {
		t.Error("Expected key to be expired after TTL")
	}
}

func TestShardedCache_EvictExpired(t *testing.T) {
	config := CacheConfig[string]{
		Capacity: 100,
		TTL:      50 * time.Millisecond,
	}
	cache := NewShardedCacheWithConfig[string, int](config)

	cache.Put("key1", 1)
	cache.Put("key2", 2)
	cache.Put("key3", 3)

	// Wait for expiration
	time.Sleep(100 * time.Millisecond)

	// Manually evict expired entries
	evicted := cache.EvictExpired()

	if evicted != 3 {
		t.Errorf("Expected 3 evictions, got %d", evicted)
	}

	if cache.Size() != 0 {
		t.Errorf("Expected size 0 after evicting expired, got %d", cache.Size())
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONCURRENCY TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestShardedCache_Concurrent(t *testing.T) {
	cache := NewShardedCache[int, int](1000)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				cache.Put(id*100+j, j)
				cache.Get(id*100 + j)
			}
		}(i)
	}
	wg.Wait()

	stats := cache.Stats()
	if stats.Hits == 0 {
		t.Error("Expected some cache hits")
	}
}

func TestShardedCache_ConcurrentReadWrite(t *testing.T) {
	cache := NewShardedCache[string, int](100)

	// Pre-populate
	for i := 0; i < 50; i++ {
		cache.Put(string(rune('a'+i)), i)
	}

	var wg sync.WaitGroup

	// Readers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				cache.Get(string(rune('a' + (j % 50))))
			}
		}()
	}

	// Writers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				cache.Put(string(rune('a'+(j%50))), id*100+j)
			}
		}(i)
	}

	wg.Wait()

	// Should complete without deadlock or race
	if cache.Size() == 0 {
		t.Error("Expected cache to have entries")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// STATISTICS TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestShardedCache_Stats(t *testing.T) {
	cache := NewShardedCache[string, int](100)

	// Initial stats
	stats := cache.Stats()
	if stats.Hits != 0 || stats.Misses != 0 {
		t.Error("Expected zero stats initially")
	}

	// Put and hit
	cache.Put("key1", 42)
	cache.Get("key1")

	stats = cache.Stats()
	if stats.Hits != 1 {
		t.Errorf("Expected 1 hit, got %d", stats.Hits)
	}

	// Miss
	cache.Get("nonexistent")
	stats = cache.Stats()
	if stats.Misses != 1 {
		t.Errorf("Expected 1 miss, got %d", stats.Misses)
	}

	// Hit rate
	if stats.HitRate != 0.5 {
		t.Errorf("Expected hit rate 0.5, got %f", stats.HitRate)
	}
}

func TestShardedCache_StatsEvictions(t *testing.T) {
	// Use capacity of 16 so each shard gets exactly 1 slot
	cache := NewShardedCache[int, int](16)

	// Fill beyond capacity to trigger evictions
	for i := 0; i < 20; i++ {
		cache.Put(i, i)
	}

	stats := cache.Stats()
	if stats.Evictions == 0 {
		t.Error("Expected evictions to be tracked")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// RESIZE TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestShardedCache_Resize(t *testing.T) {
	// Start with capacity that gives reasonable per-shard capacity
	cache := NewShardedCache[int, int](160) // 160/16 = 10 per shard

	// Fill cache
	for i := 0; i < 100; i++ {
		cache.Put(i, i)
	}

	initialSize := cache.Size()
	if initialSize == 0 {
		t.Error("Expected cache to have entries")
	}

	// Resize down to 80 (5 per shard)
	cache.Resize(80)

	if cache.Capacity() != 80 {
		t.Errorf("Expected capacity 80, got %d", cache.Capacity())
	}

	if cache.Size() > 80 {
		t.Errorf("Expected size <= 80 after resize, got %d", cache.Size())
	}

	// Resize up
	cache.Resize(320)

	if cache.Capacity() != 320 {
		t.Errorf("Expected capacity 320, got %d", cache.Capacity())
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// TYPE TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestShardedCache_StringKeys(t *testing.T) {
	cache := NewShardedCache[string, string](10)

	cache.Put("hello", "world")
	val, ok := cache.Get("hello")
	if !ok || val != "world" {
		t.Error("String key/value failed")
	}
}

func TestShardedCache_IntKeys(t *testing.T) {
	cache := NewShardedCache[int, string](10)

	cache.Put(42, "answer")
	val, ok := cache.Get(42)
	if !ok || val != "answer" {
		t.Error("Int key failed")
	}
}

func TestShardedCache_StructValues(t *testing.T) {
	type TestStruct struct {
		Name  string
		Value int
	}

	cache := NewShardedCache[string, TestStruct](10)

	cache.Put("test", TestStruct{Name: "foo", Value: 42})
	val, ok := cache.Get("test")
	if !ok || val.Name != "foo" || val.Value != 42 {
		t.Error("Struct value failed")
	}
}

func TestShardedCache_PointerValues(t *testing.T) {
	type TestStruct struct {
		Name string
	}

	cache := NewShardedCache[string, *TestStruct](10)

	obj := &TestStruct{Name: "test"}
	cache.Put("key", obj)
	val, ok := cache.Get("key")
	if !ok || val.Name != "test" {
		t.Error("Pointer value failed")
	}
}
