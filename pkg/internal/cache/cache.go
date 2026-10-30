package cache

import (
	"container/list"
	"fmt"
	"hash/fnv"
	"sync"
	"sync/atomic"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// SHARDED CACHE — Generic LRU with TTL, Memory Tracking, Thread-Safe
// ═══════════════════════════════════════════════════════════════════════════════
//
// Features:
//   • Generic implementation using Go generics [K comparable, V any]
//   • FNV-1a hashing for fast key distribution
//   • 16 shards for reduced lock contention
//   • LRU eviction policy per shard using doubly-linked list
//   • TTL support with automatic expiration checking
//   • sync.RWMutex per shard for concurrent access
//   • Atomic counters for statistics (hits, misses, evictions)
//   • Memory tracking with approximate size estimation
// ═══════════════════════════════════════════════════════════════════════════════

const numShards = 16

// ShardedCache is a generic sharded LRU cache with TTL support
type ShardedCache[K comparable, V any] struct {
	shards      [numShards]*cacheShard[K, V]
	capacity    atomic.Int64 // atomic for thread-safe access
	ttl         time.Duration
	hasher      Hasher[K]
	memoryLimit int64 // memory limit in bytes, 0 = unlimited

	// Atomic statistics (no lock needed for reads)
	hits      atomic.Int64
	misses    atomic.Int64
	evictions atomic.Int64
}

// cacheShard represents a single shard with its own lock
type cacheShard[K comparable, V any] struct {
	mu          sync.RWMutex
	cache       map[K]*list.Element
	lru         *list.List
	capacity    int
	memoryBytes atomic.Int64 // per-shard memory tracking
}

// cacheEntry represents a single cache entry
type cacheEntry[K comparable, V any] struct {
	key       K
	value     V
	createdAt time.Time
	memSize   int // estimated memory in bytes
}

// Hasher defines the interface for hashing keys
type Hasher[K comparable] interface {
	Hash(key K) uint64
}

// DefaultCacheConfig returns sensible defaults
func DefaultCacheConfig[K comparable]() CacheConfig[K] {
	return CacheConfig[K]{
		Capacity: 2048,
		TTL:      10 * time.Minute,
		Hasher:   nil, // will use default FNV-1a hasher
	}
}

// NewShardedCache creates a cache with default settings
func NewShardedCache[K comparable, V any](capacity int) *ShardedCache[K, V] {
	return NewShardedCacheWithConfig[K, V](CacheConfig[K]{Capacity: capacity})
}

// NewShardedCacheWithConfig creates a cache with full configuration
func NewShardedCacheWithConfig[K comparable, V any](cfg CacheConfig[K]) *ShardedCache[K, V] {
	if cfg.Capacity <= 0 {
		cfg.Capacity = 1000
	}

	hasher := cfg.Hasher
	if hasher == nil {
		hasher = &defaultHasher[K]{}
	}

	c := &ShardedCache[K, V]{
		ttl:         cfg.TTL,
		hasher:      hasher,
		memoryLimit: cfg.MemoryLimit,
	}
	c.capacity.Store(int64(cfg.Capacity))

	numActiveShards := activeShardCount(cfg.Capacity)

	for i := range c.shards {
		shardCapacity := shardCapacityForIndex(cfg.Capacity, numActiveShards, i)
		c.shards[i] = &cacheShard[K, V]{
			cache:    make(map[K]*list.Element, shardCapacity),
			lru:      list.New(),
			capacity: shardCapacity,
		}
	}

	return c
}

// ═══════════════════════════════════════════════════════════════════════════════
// CORE OPERATIONS
// ═══════════════════════════════════════════════════════════════════════════════

// Get retrieves a value from the cache
func (c *ShardedCache[K, V]) Get(key K) (V, bool) {
	hash := c.hasher.Hash(key)
	shard := c.getShard(hash)

	shard.mu.RLock()

	if elem, ok := shard.cache[key]; ok {
		entry := elem.Value.(*cacheEntry[K, V])

		// Check TTL
		if c.ttl > 0 && time.Since(entry.createdAt) > c.ttl {
			// Expired — need write lock to remove
			shard.mu.RUnlock()
			shard.mu.Lock()
			// Double-check after acquiring write lock
			if elem, ok := shard.cache[key]; ok {
				entry := elem.Value.(*cacheEntry[K, V])
				if time.Since(entry.createdAt) > c.ttl {
					shard.removeElement(elem)
					c.evictions.Add(1)
				}
			}
			shard.mu.Unlock()

			c.misses.Add(1)
			var zero V
			return zero, false
		}

		// Move to front (need write lock)
		shard.mu.RUnlock()
		shard.mu.Lock()
		// Double-check entry still exists
		if elem, ok := shard.cache[key]; ok {
			entry := elem.Value.(*cacheEntry[K, V])
			if c.ttl == 0 || time.Since(entry.createdAt) <= c.ttl {
				shard.lru.MoveToFront(elem)
				value := entry.value
				shard.mu.Unlock()
				c.hits.Add(1)
				return value, true
			}
		}
		shard.mu.Unlock()

		c.misses.Add(1)
		var zero V
		return zero, false
	}

	shard.mu.RUnlock()
	c.misses.Add(1)
	var zero V
	return zero, false
}

// Put stores a value in the cache
func (c *ShardedCache[K, V]) Put(key K, value V) {
	hash := c.hasher.Hash(key)
	shard := c.getShard(hash)

	shard.mu.Lock()
	defer shard.mu.Unlock()

	// Handle shards with 0 capacity (inactive shards)
	if shard.capacity == 0 {
		// Shard is inactive, cannot store entries
		return
	}

	// Check if entry already exists
	if elem, ok := shard.cache[key]; ok {
		// Update existing entry
		entry := elem.Value.(*cacheEntry[K, V])
		oldSize := entry.memSize
		newSize := estimateMemorySize(value)

		entry.value = value
		entry.createdAt = time.Now()
		entry.memSize = newSize

		// Update shard memory tracking
		shard.memoryBytes.Add(int64(newSize - oldSize))

		shard.lru.MoveToFront(elem)
		return
	}

	// Calculate new entry size
	newSize := estimateMemorySize(value)

	// Enforce memory limit with aggressive eviction if set
	if c.memoryLimit > 0 {
		totalMemory := c.getTotalMemory()
		// Evict aggressively if we're over the limit or would exceed it
		for totalMemory+int64(newSize) > c.memoryLimit && shard.lru.Len() > 0 {
			shard.evictOldest()
			c.evictions.Add(1)
			totalMemory = c.getTotalMemory()
		}

		// If still can't fit, the pressure may come from OTHER shards: the
		// old code drained the current shard and then rejected the insert
		// anyway. Sample a global victim (the largest shard's LRU tail)
		// until the entry fits or nothing is evictable.
		for totalMemory+int64(newSize) > c.memoryLimit {
			if !c.evictGlobalVictim(shard) {
				return
			}
			c.evictions.Add(1)
			totalMemory = c.getTotalMemory()
		}
	}

	// Evict if needed based on capacity
	for shard.lru.Len() >= shard.capacity {
		shard.evictOldest()
		c.evictions.Add(1)
	}

	// Insert new entry
	entry := &cacheEntry[K, V]{
		key:       key,
		value:     value,
		createdAt: time.Now(),
		memSize:   newSize,
	}
	elem := shard.lru.PushFront(entry)
	shard.cache[key] = elem

	// Update shard memory tracking
	shard.memoryBytes.Add(int64(newSize))
}

// Delete removes a value from the cache
func (c *ShardedCache[K, V]) Delete(key K) {
	hash := c.hasher.Hash(key)
	shard := c.getShard(hash)

	shard.mu.Lock()
	defer shard.mu.Unlock()

	if elem, ok := shard.cache[key]; ok {
		shard.removeElement(elem)
	}
}

// evictGlobalVictim removes the LRU tail of the shard currently holding the
// most memory. Called from Put while holding `skip` (the inserting shard)'s
// mutex; other shards are locked one at a time and never the other way
// around, so no lock-order cycle exists.
func (c *ShardedCache[K, V]) evictGlobalVictim(skip *cacheShard[K, V]) bool {
	var victim *cacheShard[K, V]
	var best int64
	for _, s := range c.shards {
		if n := s.memoryBytes.Load(); n > best {
			best = n
			victim = s
		}
	}
	if victim == nil {
		return false
	}
	if victim == skip {
		if skip.lru.Len() == 0 {
			return false
		}
		skip.evictOldest()
		return true
	}
	victim.mu.Lock()
	defer victim.mu.Unlock()
	if victim.lru.Len() == 0 {
		return false
	}
	victim.evictOldest()
	return true
}

// Clear empties the entire cache
func (c *ShardedCache[K, V]) Clear() {
	for _, shard := range c.shards {
		shard.mu.Lock()
		shard.cache = make(map[K]*list.Element)
		shard.lru = list.New()
		shard.memoryBytes.Store(0)
		shard.mu.Unlock()
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CACHE MANAGEMENT
// ═══════════════════════════════════════════════════════════════════════════════

// EvictExpired removes all expired entries
func (c *ShardedCache[K, V]) EvictExpired() int {
	if c.ttl == 0 {
		return 0
	}

	evicted := 0
	now := time.Now()

	for _, shard := range c.shards {
		shard.mu.Lock()

		// Walk from back (oldest)
		for elem := shard.lru.Back(); elem != nil; {
			entry := elem.Value.(*cacheEntry[K, V])
			prev := elem.Prev()

			if now.Sub(entry.createdAt) > c.ttl {
				shard.removeElement(elem)
				evicted++
			}
			elem = prev
		}

		shard.mu.Unlock()
	}

	c.evictions.Add(int64(evicted))
	return evicted
}

// Resize changes the cache capacity
func (c *ShardedCache[K, V]) Resize(newCapacity int) {
	if newCapacity <= 0 {
		newCapacity = 1
	}

	c.capacity.Store(int64(newCapacity))

	numActiveShards := activeShardCount(newCapacity)

	for i, shard := range c.shards {
		shard.mu.Lock()
		shard.capacity = shardCapacityForIndex(newCapacity, numActiveShards, i)
		if shard.capacity == 0 {
			shard.capacity = 0
			// Evict all entries from inactive shards
			for shard.lru.Len() > 0 {
				shard.evictOldest()
				c.evictions.Add(1)
			}
		}
		// Evict if current size exceeds new capacity
		for shard.lru.Len() > shard.capacity {
			shard.evictOldest()
			c.evictions.Add(1)
		}
		shard.mu.Unlock()
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// STATISTICS
// ═══════════════════════════════════════════════════════════════════════════════

// Stats returns comprehensive cache statistics
func (c *ShardedCache[K, V]) Stats() CacheStats {
	hits := c.hits.Load()
	misses := c.misses.Load()

	total := hits + misses
	var hitRate float64
	if total > 0 {
		hitRate = float64(hits) / float64(total)
	}

	size := 0
	memBytes := int64(0)
	shardStats := make([]ShardStats, 0, numShards)

	for i, shard := range c.shards {
		shard.mu.RLock()
		shardSize := shard.lru.Len()
		shardMem := shard.memoryBytes.Load()
		size += shardSize
		memBytes += shardMem

		if shardSize > 0 {
			shardStats = append(shardStats, ShardStats{
				ShardID:     i,
				Size:        shardSize,
				MemoryBytes: shardMem,
			})
		}
		shard.mu.RUnlock()
	}

	return CacheStats{
		Hits:        hits,
		Misses:      misses,
		Evictions:   c.evictions.Load(),
		Size:        size,
		Capacity:    int(c.capacity.Load()),
		HitRate:     hitRate,
		MemoryBytes: memBytes,
		MemoryMB:    float64(memBytes) / (1024 * 1024),
		ShardStats:  shardStats,
	}
}

// getTotalMemory returns the total memory usage across all shards
func (c *ShardedCache[K, V]) getTotalMemory() int64 {
	total := int64(0)
	for _, shard := range c.shards {
		total += shard.memoryBytes.Load()
	}
	return total
}

// Size returns the current number of entries in the cache
func (c *ShardedCache[K, V]) Size() int {
	size := 0
	for _, shard := range c.shards {
		shard.mu.RLock()
		size += shard.lru.Len()
		shard.mu.RUnlock()
	}
	return size
}

// Capacity returns the maximum number of entries the cache can hold
func (c *ShardedCache[K, V]) Capacity() int {
	return int(c.capacity.Load())
}

// ═══════════════════════════════════════════════════════════════════════════════
// SHARD OPERATIONS
// ═══════════════════════════════════════════════════════════════════════════════

// getShard returns the shard for a given hash
// When capacity < numShards, we only use the first 'capacity' shards
func (c *ShardedCache[K, V]) getShard(hash uint64) *cacheShard[K, V] {
	capacity := int(c.capacity.Load())
	active := activeShardCount(capacity)
	return c.shards[hash%uint64(active)]
}

func activeShardCount(capacity int) int {
	if capacity <= 1 {
		return 1
	}
	if capacity < numShards {
		// Small caches keep a single shard so LRU semantics stay intuitive.
		return 1
	}
	return numShards
}

func shardCapacityForIndex(totalCapacity, activeShards, index int) int {
	if index >= activeShards {
		return 0
	}
	base := totalCapacity / activeShards
	remainder := totalCapacity % activeShards
	if index < remainder {
		return base + 1
	}
	return base
}

func (s *cacheShard[K, V]) removeElement(elem *list.Element) {
	entry := elem.Value.(*cacheEntry[K, V])
	delete(s.cache, entry.key)
	s.lru.Remove(elem)
	// Update memory tracking
	s.memoryBytes.Add(-int64(entry.memSize))
}

func (s *cacheShard[K, V]) evictOldest() {
	elem := s.lru.Back()
	if elem != nil {
		s.removeElement(elem)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// HASHING — FNV-1a (fast and good distribution)
// ═══════════════════════════════════════════════════════════════════════════════

// defaultHasher implements FNV-1a hashing for any comparable type
type defaultHasher[K comparable] struct{}

func (h *defaultHasher[K]) Hash(key K) uint64 {
	hasher := fnv.New64a()

	// Use fmt.Sprint to convert any comparable type to string
	// This is a simple approach that works for all comparable types
	keyStr := anyToBytes(key)
	hasher.Write(keyStr)

	return hasher.Sum64()
}

// anyToBytes converts any comparable value to bytes for hashing
func anyToBytes(v interface{}) []byte {
	switch val := v.(type) {
	case string:
		return []byte(val)
	case int:
		return int64ToBytes(int64(val))
	case int64:
		return int64ToBytes(val)
	case int32:
		return int64ToBytes(int64(val))
	case uint:
		return uint64ToBytes(uint64(val))
	case uint64:
		return uint64ToBytes(val)
	case uint32:
		return uint64ToBytes(uint64(val))
	default:
		// Fallback: use fmt.Sprint
		return []byte(anyToString(v))
	}
}

// Note: int64ToBytes and uint64ToBytes are now in hash.go

// anyToString converts any value to string (fallback)
func anyToString(v interface{}) string {
	// Simple string conversion
	switch val := v.(type) {
	case string:
		return val
	default:
		return fmt.Sprintf("%v", v)
	}
}

// estimateMemorySize returns approximate memory usage in bytes
func estimateMemorySize(v interface{}) int {
	// Base estimate: 64 bytes for overhead (struct, pointers, etc.)
	mem := 64

	switch val := v.(type) {
	case string:
		// String header (16 bytes) + actual string data
		mem += 16 + len(val)
	case []byte:
		// Slice header (24 bytes) + actual data
		mem += 24 + len(val)
	case []string:
		// Slice header + each string
		mem += 24
		for _, s := range val {
			mem += 16 + len(s)
		}
	case map[string]string:
		// Map overhead + entries
		mem += 48
		for k, v := range val {
			mem += 16 + len(k) + 16 + len(v)
		}
	case map[string]interface{}:
		// Map overhead + entries
		mem += 48
		for k, v := range val {
			mem += 16 + len(k) + estimateMemorySize(v)
		}
	case int, int32, uint32, float32:
		mem += 4
	case int64, uint64, float64:
		mem += 8
	case bool:
		mem += 1
	default:
		// For complex types, use a conservative estimate
		// This includes structs, pointers, interfaces, etc.
		mem += 256
	}

	return mem
}
