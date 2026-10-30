package deobfuscation

import (
	"context"
	"runtime"
	"sync"

	"mega-analyzer/pkg/internal/cfg"
)

// ═══════════════════════════════════════════════════════════════════════════════
// BATCH / PARALLEL ANALYSIS
// ═══════════════════════════════════════════════════════════════════════════════
//
// Engine.Analyze is read-only with respect to the CFG it inspects, so a large
// corpus of methods can be analysed concurrently with no shared mutable state.
// AnalyzeAll fans the work out across a bounded worker pool and returns the
// results in the same order as the input, honouring context cancellation.

// AnalyzeAll runs Analyze over every graph concurrently and returns the results
// positionally (result[i] corresponds to graphs[i]). Nil graphs yield an empty,
// non-nil result. If ctx is cancelled, remaining slots are left as empty
// results and the function returns promptly.
func (e *Engine) AnalyzeAll(ctx context.Context, graphs []*cfg.ControlFlowGraph) []*DeobfuscationResult {
	results := make([]*DeobfuscationResult, len(graphs))
	if len(graphs) == 0 {
		return results
	}

	workers := e.workerCount(len(graphs))

	// Small inputs are cheaper to process inline than to hand off to goroutines.
	if workers <= 1 {
		for i, g := range graphs {
			if ctx != nil && ctx.Err() != nil {
				break
			}
			results[i] = e.analyzeOrEmpty(g)
		}
		fillEmpty(results)
		return results
	}

	indices := make(chan int, workers)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range indices {
				if ctx != nil && ctx.Err() != nil {
					return
				}
				results[i] = e.analyzeOrEmpty(graphs[i])
			}
		}()
	}

	for i := range graphs {
		if ctx != nil && ctx.Err() != nil {
			break
		}
		indices <- i
	}
	close(indices)
	wg.Wait()

	fillEmpty(results)
	return results
}

// analyzeOrEmpty guarantees a non-nil result even for a nil graph.
func (e *Engine) analyzeOrEmpty(g *cfg.ControlFlowGraph) *DeobfuscationResult {
	if g == nil {
		return &DeobfuscationResult{}
	}
	return e.Analyze(g)
}

// workerCount picks a sensible degree of parallelism bounded by the workload.
func (e *Engine) workerCount(n int) int {
	w := runtime.GOMAXPROCS(0)
	if w < 1 {
		w = 1
	}
	if w > n {
		w = n
	}
	return w
}

// fillEmpty replaces any nil slots (e.g. left by early cancellation) with empty
// results so callers never have to nil-check the slice.
func fillEmpty(results []*DeobfuscationResult) {
	for i := range results {
		if results[i] == nil {
			results[i] = &DeobfuscationResult{}
		}
	}
}
