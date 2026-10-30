// pkg/internal/syncx/singleflight.go
// Zero-dependency singleflight
package syncx

import "sync"

type call struct {
	wg  sync.WaitGroup
	val any
	err error
}

// SingleFlight подавляет дублирующиеся вызовы.
type SingleFlight struct {
	mu sync.Mutex
	m  map[string]*call
}

// Do выполняет fn только один раз для данного ключа.
// Остальные вызовы с тем же ключом ждут и получают тот же результат.
func (sf *SingleFlight) Do(key string, fn func() (any, error)) (any, error, bool) {
	sf.mu.Lock()
	if sf.m == nil {
		sf.m = make(map[string]*call)
	}
	if c, ok := sf.m[key]; ok {
		sf.mu.Unlock()
		c.wg.Wait()
		return c.val, c.err, true // shared
	}
	c := new(call)
	c.wg.Add(1)
	sf.m[key] = c
	sf.mu.Unlock()

	defer c.wg.Done()

	c.val, c.err = fn()

	sf.mu.Lock()
	delete(sf.m, key)
	sf.mu.Unlock()

	return c.val, c.err, false // owner
}

// Forget удаляет ключ — следующий вызов Do выполнит fn заново.
func (sf *SingleFlight) Forget(key string) {
	sf.mu.Lock()
	delete(sf.m, key)
	sf.mu.Unlock()
}
