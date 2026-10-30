// Package panicnote records panics that parsers deliberately recover from.
//
// Parsers of untrusted input use recover() so one malformed file cannot crash
// a scan. Swallowing the panic silently, however, hides real parser bugs: the
// file just produces an empty result. Note keeps the "never crash" guarantee
// but makes every recovered panic visible (stderr + per-stage counter).
package panicnote

import (
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"sort"
	"sync"
	"sync/atomic"
)

// maxStacksPerStage limits how many full stack traces are printed per stage,
// so a corpus full of broken files does not flood the log.
const maxStacksPerStage = 3

var (
	counts sync.Map // stage -> *atomic.Int64
	outMu  sync.Mutex
	// Output is where notes are written. Tests may replace it.
	Output io.Writer = os.Stderr
)

// Note records a recovered panic value. Call it as
//
//	defer func() { panicnote.Note("pkg.stage", recover()) }()
//
// A nil value (no panic) is ignored.
func Note(stage string, r any) {
	if r == nil {
		return
	}
	v, _ := counts.LoadOrStore(stage, new(atomic.Int64))
	n := v.(*atomic.Int64).Add(1)
	outMu.Lock()
	defer outMu.Unlock()
	if n <= maxStacksPerStage {
		fmt.Fprintf(Output, "[panic recovered] %s: %v\n%s\n", stage, r, debug.Stack())
	} else {
		fmt.Fprintf(Output, "[panic recovered] %s: %v (#%d, stack suppressed)\n", stage, r, n)
	}
}

// Snapshot returns the number of recovered panics per stage.
func Snapshot() map[string]int64 {
	out := map[string]int64{}
	counts.Range(func(k, v any) bool {
		out[k.(string)] = v.(*atomic.Int64).Load()
		return true
	})
	return out
}

// Stages returns the stages that recovered at least one panic, sorted.
func Stages() []string {
	s := Snapshot()
	keys := make([]string, 0, len(s))
	for k := range s {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
