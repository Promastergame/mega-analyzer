package llmkeys

import (
	"container/list"
	"sync"
)

// The classifier is pure — Classify(v) always returns the same Verdict for the
// same v — so its results are perfectly cacheable. In practice the loaders call
// Classify over every printable string in a binary, and large binaries repeat
// the same string constants across many objects (shared runtime symbols, format
// strings, framework selectors). Memoizing turns those repeats into O(1) map
// hits and keeps the expensive regex/entropy path off the hot loop.
//
// The cache is a bounded LRU: bounded so a pathological input (millions of
// distinct strings) cannot exhaust memory, LRU so the working set of a scan
// stays resident. It is safe for concurrent use.

const defaultCacheCapacity = 8192

type cacheEntry struct {
	key     string
	verdict Verdict
}

type verdictCache struct {
	mu       sync.Mutex
	capacity int
	ll       *list.List               // front = most recently used
	items    map[string]*list.Element // key -> element holding *cacheEntry
	hits     uint64
	misses   uint64
}

func newVerdictCache(capacity int) *verdictCache {
	if capacity <= 0 {
		capacity = defaultCacheCapacity
	}
	return &verdictCache{
		capacity: capacity,
		ll:       list.New(),
		items:    make(map[string]*list.Element, capacity),
	}
}

func (c *verdictCache) get(key string) (Verdict, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		c.ll.MoveToFront(el)
		c.hits++
		return el.Value.(*cacheEntry).verdict, true
	}
	c.misses++
	return Verdict{}, false
}

func (c *verdictCache) put(key string, v Verdict) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		c.ll.MoveToFront(el)
		el.Value.(*cacheEntry).verdict = v
		return
	}
	el := c.ll.PushFront(&cacheEntry{key: key, verdict: v})
	c.items[key] = el
	if c.ll.Len() > c.capacity {
		c.evictOldest()
	}
}

// evictOldest removes the least-recently-used entry. Caller must hold c.mu.
func (c *verdictCache) evictOldest() {
	el := c.ll.Back()
	if el == nil {
		return
	}
	c.ll.Remove(el)
	delete(c.items, el.Value.(*cacheEntry).key)
}

func (c *verdictCache) stats() (hits, misses uint64, size int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hits, c.misses, c.ll.Len()
}

func (c *verdictCache) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ll.Init()
	c.items = make(map[string]*list.Element, c.capacity)
	c.hits, c.misses = 0, 0
}

var globalCache = newVerdictCache(defaultCacheCapacity)

// ClassifyCached is a memoized Classify. It returns byte-for-byte the same
// Verdict as Classify(value) but serves repeated values from a bounded LRU
// cache, which is a large win on real binaries where the same string constant
// recurs many times. Safe for concurrent use.
func ClassifyCached(value string) Verdict {
	if v, ok := globalCache.get(value); ok {
		return v
	}
	v := Classify(value)
	globalCache.put(value, v)
	return v
}

// CacheStats reports the global classification cache's hit/miss counts and
// current occupancy. Useful for tuning and for the insights layer.
func CacheStats() (hits, misses uint64, size int) {
	return globalCache.stats()
}

// ResetCache clears the global classification cache. Intended for tests and for
// long-lived processes that want to release the working set between scans.
func ResetCache() {
	globalCache.reset()
}
