package matcher

import (
	"runtime"
	"sync"
)

// cpuGovernor bounds the number of concurrent CPU-bound matching goroutines
// across the ENTIRE process.
//
// Why this exists: the analysis pipeline already runs one file-worker per CPU
// (file-level parallelism keeps every core busy when there are many files).
// Historically each of those file-workers could ALSO fan a single large file
// out to runtime.NumCPU() chunk workers. With P = NumCPU that produced up to
// P*P CPU-bound goroutines (e.g. 64 on an 8-core box): the scheduler and CPU
// caches thrash, the machine pegs at 100% CPU, and total throughput actually
// drops.
//
// The governor hands out a fixed budget of tokens (GOMAXPROCS). Each file holds
// exactly one token while it is scanned; a large file may borrow extra tokens
// for additional chunk workers, but only as many as are currently free. When no
// tokens are free the file is scanned sequentially. The set of matches produced
// is identical either way — only scheduling changes.
type cpuGovernor struct {
	tokens chan struct{}
}

var (
	globalCPUGovernor     *cpuGovernor
	globalCPUGovernorOnce sync.Once
)

// newCPUGovernor builds a governor pre-filled with n tokens (min 1).
func newCPUGovernor(n int) *cpuGovernor {
	if n < 1 {
		n = 1
	}
	g := &cpuGovernor{tokens: make(chan struct{}, n)}
	for i := 0; i < n; i++ {
		g.tokens <- struct{}{}
	}
	return g
}

// cpuBudget returns the process-wide governor, sized to GOMAXPROCS.
func cpuBudget() *cpuGovernor {
	globalCPUGovernorOnce.Do(func() {
		globalCPUGovernor = newCPUGovernor(runtime.GOMAXPROCS(0))
	})
	return globalCPUGovernor
}

// acquire blocks until one token is available. Callers MUST call releaseOne.
func (g *cpuGovernor) acquire() {
	<-g.tokens
}

// releaseOne returns a single token to the pool. It never blocks and never
// pushes the pool above its capacity.
func (g *cpuGovernor) releaseOne() {
	select {
	case g.tokens <- struct{}{}:
	default:
	}
}

// tryAcquire grabs up to max tokens WITHOUT blocking and returns how many were
// actually obtained (0..max). Callers MUST release exactly that many.
func (g *cpuGovernor) tryAcquire(max int) int {
	if max <= 0 {
		return 0
	}
	got := 0
	for got < max {
		select {
		case <-g.tokens:
			got++
		default:
			return got
		}
	}
	return got
}

// release returns n tokens to the pool, never exceeding capacity (defensive
// against accounting bugs).
func (g *cpuGovernor) release(n int) {
	for i := 0; i < n; i++ {
		select {
		case g.tokens <- struct{}{}:
		default:
			return
		}
	}
}
