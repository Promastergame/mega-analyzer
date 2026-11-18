package s1

// CacheUsage reports retained entries and their accounted memory. Bytes includes
// payloads and an allowance for bookkeeping, not the whole process or Go heap.
type CacheUsage struct {
	Entries    int   `json:"entries"`
	Bytes      int64 `json:"bytes"`
	LimitBytes int64 `json:"limit_bytes"`
}

// weightedCache is an LRU with a byte budget. Its owner provides synchronization
// and includes keys, values and bookkeeping in each entry's cost.
type weightedCache[K comparable, V any] struct {
	items          map[K]*cacheEntry[K, V]
	newest, oldest *cacheEntry[K, V]
	bytes, limit   int64
}

type cacheEntry[K comparable, V any] struct {
	key        K
	value      V
	bytes      int64
	prev, next *cacheEntry[K, V]
}

func (c *weightedCache[K, V]) get(key K) (V, bool) {
	if entry, ok := c.items[key]; ok {
		c.unlink(entry)
		c.push(entry)
		return entry.value, true
	}
	var zero V
	return zero, false
}

func (c *weightedCache[K, V]) put(key K, value V, bytes int64) bool {
	// A single oversized entry must not evict the useful working set.
	if bytes <= 0 || bytes > c.limit {
		return false
	}
	if entry, ok := c.items[key]; ok {
		c.remove(entry)
	}
	for c.bytes > c.limit-bytes {
		c.remove(c.oldest)
	}
	if c.items == nil {
		c.items = make(map[K]*cacheEntry[K, V])
	}
	entry := &cacheEntry[K, V]{key: key, value: value, bytes: bytes}
	c.items[key] = entry
	c.bytes += bytes
	c.push(entry)
	return true
}

func (c *weightedCache[K, V]) resize(limit int64) {
	c.limit = max(0, limit)
	for c.bytes > c.limit {
		c.remove(c.oldest)
	}
	// Rebuild on explicit reconfiguration to release oversized map buckets too.
	items := make(map[K]*cacheEntry[K, V], len(c.items))
	for key, entry := range c.items {
		items[key] = entry
	}
	c.items = items
}

func (c *weightedCache[K, V]) usage() CacheUsage {
	return CacheUsage{Entries: len(c.items), Bytes: c.bytes, LimitBytes: c.limit}
}

func (c *weightedCache[K, V]) remove(entry *cacheEntry[K, V]) {
	c.unlink(entry)
	delete(c.items, entry.key)
	c.bytes -= entry.bytes
}

func (c *weightedCache[K, V]) unlink(entry *cacheEntry[K, V]) {
	if entry.prev != nil {
		entry.prev.next = entry.next
	} else {
		c.newest = entry.next
	}
	if entry.next != nil {
		entry.next.prev = entry.prev
	} else {
		c.oldest = entry.prev
	}
}

func (c *weightedCache[K, V]) push(entry *cacheEntry[K, V]) {
	entry.prev, entry.next = nil, c.newest
	if c.newest != nil {
		c.newest.prev = entry
	} else {
		c.oldest = entry
	}
	c.newest = entry
}
