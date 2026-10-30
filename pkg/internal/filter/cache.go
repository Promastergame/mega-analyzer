package filter

import (
	"container/list"
	"sync"
)

// ═══════════════════════════════════════════════════════════════════
// GENERIC LRU CACHE
// ═══════════════════════════════════════════════════════════════════

type LRUCache[K comparable, V any] struct {
	capacity int
	cache    map[K]*list.Element
	list     *list.List
	mu       sync.RWMutex

	// Статистика
	hits   int64
	misses int64
}

type cacheEntry[K comparable, V any] struct {
	key   K
	value V
}

func NewLRUCache[K comparable, V any](capacity int) *LRUCache[K, V] {
	return &LRUCache[K, V]{
		capacity: capacity,
		cache:    make(map[K]*list.Element),
		list:     list.New(),
	}
}

func (c *LRUCache[K, V]) Get(key K) (V, bool) {
	c.mu.RLock()
	elem, ok := c.cache[key]
	c.mu.RUnlock()

	if !ok {
		c.mu.Lock()
		c.misses++
		c.mu.Unlock()
		var zero V
		return zero, false
	}

	c.mu.Lock()
	c.list.MoveToFront(elem)
	c.hits++
	c.mu.Unlock()

	return elem.Value.(*cacheEntry[K, V]).value, true
}

func (c *LRUCache[K, V]) Put(key K, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Уже есть
	if elem, ok := c.cache[key]; ok {
		c.list.MoveToFront(elem)
		elem.Value.(*cacheEntry[K, V]).value = value
		return
	}

	// Новый элемент
	entry := &cacheEntry[K, V]{key: key, value: value}
	elem := c.list.PushFront(entry)
	c.cache[key] = elem

	// Eviction
	if c.list.Len() > c.capacity {
		c.evict()
	}
}

func (c *LRUCache[K, V]) evict() {
	elem := c.list.Back()
	if elem != nil {
		entry := elem.Value.(*cacheEntry[K, V])
		delete(c.cache, entry.key)
		c.list.Remove(elem)
	}
}

func (c *LRUCache[K, V]) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache = make(map[K]*list.Element)
	c.list = list.New()
}

func (c *LRUCache[K, V]) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.list.Len()
}

func (c *LRUCache[K, V]) Stats() (hits, misses int64, hitRate float64) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	hits = c.hits
	misses = c.misses
	total := hits + misses
	if total > 0 {
		hitRate = float64(hits) / float64(total)
	}
	return
}
