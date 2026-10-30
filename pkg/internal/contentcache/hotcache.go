// Hot cache: sharded, per-namespace LRU with entry and byte budgets.
//
// Rationale: the previous implementation was a single
// map[Namespace]map[ContentKey][]byte guarded by one RWMutex, with an
// "evictOldest" that deleted a random map entry and a promotion path that
// silently stopped promoting once the map was full. That is neither LRU nor
// FIFO, it froze after warm-up, and it had no byte ceiling at all
// (4096 entries x 64 MiB max entry size).
//
// This file replaces it with hotShardCount independent shards keyed by the
// first content-key byte. Each shard keeps one LRU list per namespace, so a
// hot GNN namespace cannot be flushed by churn in "metrics". Budgets are
// divided across shards; SHA-256 keys distribute uniformly, so per-shard
// budgets are a close approximation of the global ones.
package contentcache

import (
	"container/list"
	"sync"
)

// hotShardCount must be a power of two so the shard index is a cheap mask.
const hotShardCount = 32

// hotEntry is one cached payload inside a namespace LRU list.
type hotEntry struct {
	key  ContentKey
	data []byte
}

// nsLRU is the LRU list for a single (shard, namespace) pair.
type nsLRU struct {
	ll    *list.List
	items map[ContentKey]*list.Element
	bytes int64
}

func newNSLRU() *nsLRU {
	return &nsLRU{ll: list.New(), items: make(map[ContentKey]*list.Element, 32)}
}

type hotShard struct {
	mu sync.Mutex
	ns map[Namespace]*nsLRU
}

func newHotShard() *hotShard {
	return &hotShard{ns: make(map[Namespace]*nsLRU, len(AllNamespaces()))}
}

func (h *hotShard) lru(ns Namespace) *nsLRU {
	l, ok := h.ns[ns]
	if !ok {
		l = newNSLRU()
		h.ns[ns] = l
	}
	return l
}

// hotCache is the sharded hot cache owned by a Store.
type hotCache struct {
	shards [hotShardCount]*hotShard

	// Per-(shard, namespace) budgets, derived from the Store config.
	maxEntries int
	maxBytes   int64
}

func newHotCache(maxEntriesPerNS int, maxBytesPerNS int64) *hotCache {
	c := &hotCache{}
	for i := range c.shards {
		c.shards[i] = newHotShard()
	}
	// Divide the global budget across shards, never below 1 entry so a small
	// configured limit still caches something in every shard.
	c.maxEntries = maxEntriesPerNS / hotShardCount
	if c.maxEntries < 1 {
		c.maxEntries = 1
	}
	c.maxBytes = maxBytesPerNS / hotShardCount
	if c.maxBytes < 1 {
		c.maxBytes = 1
	}
	return c
}

func (c *hotCache) shardFor(key ContentKey) *hotShard {
	return c.shards[int(key[0])%hotShardCount]
}

// get returns a copy of the cached payload and moves it to the front of its
// namespace LRU list.
func (c *hotCache) get(ns Namespace, key ContentKey) ([]byte, bool) {
	sh := c.shardFor(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	l, ok := sh.ns[ns]
	if !ok {
		return nil, false
	}
	el, ok := l.items[key]
	if !ok {
		return nil, false
	}
	l.ll.MoveToFront(el)
	data := el.Value.(*hotEntry).data
	return append([]byte(nil), data...), true
}

func (c *hotCache) has(ns Namespace, key ContentKey) bool {
	sh := c.shardFor(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	l, ok := sh.ns[ns]
	if !ok {
		return false
	}
	_, ok = l.items[key]
	return ok
}

// put inserts or refreshes an entry and returns how many entries were evicted
// to make room. Entries larger than half the per-shard byte budget are
// refused: a single blob must not be able to flush an entire namespace.
func (c *hotCache) put(ns Namespace, key ContentKey, data []byte) int64 {
	size := int64(len(data))
	if size*2 > c.maxBytes {
		// Too large to be worth caching in RAM; it stays on disk only.
		// Drop any older copy so hot and disk cannot disagree.
		c.delete(ns, key)
		return 0
	}

	sh := c.shardFor(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	l := sh.lru(ns)

	if el, ok := l.items[key]; ok {
		entry := el.Value.(*hotEntry)
		l.bytes += size - int64(len(entry.data))
		entry.data = append([]byte(nil), data...)
		l.ll.MoveToFront(el)
		return c.evictLocked(l)
	}

	el := l.ll.PushFront(&hotEntry{key: key, data: append([]byte(nil), data...)})
	l.items[key] = el
	l.bytes += size
	return c.evictLocked(l)
}

// evictLocked drops entries from the back until both budgets are satisfied.
// The caller must hold the shard lock.
func (c *hotCache) evictLocked(l *nsLRU) int64 {
	var evicted int64
	for l.ll.Len() > c.maxEntries || (l.bytes > c.maxBytes && l.ll.Len() > 0) {
		back := l.ll.Back()
		if back == nil {
			break
		}
		entry := back.Value.(*hotEntry)
		l.ll.Remove(back)
		delete(l.items, entry.key)
		l.bytes -= int64(len(entry.data))
		evicted++
	}
	if l.bytes < 0 {
		l.bytes = 0
	}
	return evicted
}

// delete removes a single entry. Disk is the source of truth, so every disk
// removal (Delete, eviction, corruption rejection) must call this.
func (c *hotCache) delete(ns Namespace, key ContentKey) {
	sh := c.shardFor(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	l, ok := sh.ns[ns]
	if !ok {
		return
	}
	el, ok := l.items[key]
	if !ok {
		return
	}
	l.bytes -= int64(len(el.Value.(*hotEntry).data))
	if l.bytes < 0 {
		l.bytes = 0
	}
	l.ll.Remove(el)
	delete(l.items, key)
}

// clearNamespace drops every entry of one namespace across all shards.
func (c *hotCache) clearNamespace(ns Namespace) {
	for _, sh := range c.shards {
		sh.mu.Lock()
		delete(sh.ns, ns)
		sh.mu.Unlock()
	}
}

// clear drops everything.
func (c *hotCache) clear() {
	for _, sh := range c.shards {
		sh.mu.Lock()
		sh.ns = make(map[Namespace]*nsLRU, len(AllNamespaces()))
		sh.mu.Unlock()
	}
}

// stats reports the aggregate entry count and resident bytes.
func (c *hotCache) stats() (entries int, bytes int64) {
	for _, sh := range c.shards {
		sh.mu.Lock()
		for _, l := range sh.ns {
			entries += l.ll.Len()
			bytes += l.bytes
		}
		sh.mu.Unlock()
	}
	return entries, bytes
}

// keysForNamespace returns the resident keys of a namespace. Test-facing
// helper used to assert the hot/disk consistency invariant.
func (c *hotCache) keysForNamespace(ns Namespace) []ContentKey {
	var out []ContentKey
	for _, sh := range c.shards {
		sh.mu.Lock()
		if l, ok := sh.ns[ns]; ok {
			for k := range l.items {
				out = append(out, k)
			}
		}
		sh.mu.Unlock()
	}
	return out
}

// orderedKeys returns the keys of one (shard, namespace) LRU from most to
// least recently used. Test-facing helper for exact eviction-order assertions.
func (c *hotCache) orderedKeys(ns Namespace, shard int) []ContentKey {
	sh := c.shards[shard]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	l, ok := sh.ns[ns]
	if !ok {
		return nil
	}
	out := make([]ContentKey, 0, l.ll.Len())
	for el := l.ll.Front(); el != nil; el = el.Next() {
		out = append(out, el.Value.(*hotEntry).key)
	}
	return out
}
