package ncer

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestFileLock_MutualExclusion(t *testing.T) {
	dir := t.TempDir()
	lock := newBaselineLock(dir)
	var inside int32
	var maxSeen int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := lock.acquire(); err != nil {
				t.Errorf("acquire: %v", err)
				return
			}
			n := atomic.AddInt32(&inside, 1)
			for {
				m := atomic.LoadInt32(&maxSeen)
				if n <= m || atomic.CompareAndSwapInt32(&maxSeen, m, n) {
					break
				}
			}
			atomic.AddInt32(&inside, -1)
			lock.release()
		}()
	}
	wg.Wait()
	if maxSeen > 1 {
		t.Fatalf("mutual exclusion violated: %d goroutines held the lock at once", maxSeen)
	}
}
