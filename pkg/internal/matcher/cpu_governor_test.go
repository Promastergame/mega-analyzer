package matcher

import (
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"mega-analyzer/pkg/internal/config"
	"mega-analyzer/pkg/internal/types"
)

func TestCPUGovernorTryAcquireBounded(t *testing.T) {
	const capN = 4
	g := newCPUGovernor(capN)

	got := g.tryAcquire(capN + 10)
	if got != capN {
		t.Fatalf("tryAcquire handed out %d tokens, want cap %d", got, capN)
	}
	if extra := g.tryAcquire(5); extra != 0 {
		t.Fatalf("drained pool should yield 0, got %d", extra)
	}
	g.release(got)
	if got2 := g.tryAcquire(capN); got2 != capN {
		t.Fatalf("after release expected %d, got %d", capN, got2)
	}
}

func TestCPUGovernorNeverOverReleases(t *testing.T) {
	const capN = 3
	g := newCPUGovernor(capN)
	g.release(capN + 50) // over-release must not grow the pool
	if got := g.tryAcquire(capN + 50); got != capN {
		t.Fatalf("pool capacity drifted: got %d, want %d", got, capN)
	}
}

// TestCPUGovernorConcurrentCap is the core guarantee: no matter how many
// goroutines contend, the number of simultaneously-held tokens never exceeds
// the configured cap. This is what prevents NumCPU*NumCPU oversubscription.
func TestCPUGovernorConcurrentCap(t *testing.T) {
	const capN = 4
	g := newCPUGovernor(capN)
	var cur, max int64
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				got := g.tryAcquire(3)
				if got == 0 {
					runtime.Gosched()
					continue
				}
				n := atomic.AddInt64(&cur, int64(got))
				for {
					m := atomic.LoadInt64(&max)
					if n <= m || atomic.CompareAndSwapInt64(&max, m, n) {
						break
					}
				}
				runtime.Gosched()
				atomic.AddInt64(&cur, -int64(got))
				g.release(got)
			}
		}()
	}
	wg.Wait()
	if max > int64(capN) {
		t.Fatalf("held tokens peaked at %d, exceeds cap %d", max, capN)
	}
}

func sigOf(ms []types.Match) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.Pattern+"\x00"+m.Text)
	}
	sort.Strings(out)
	return out
}

// TestParallelMatchesEqualSequential proves the optimization is lossless: the
// parallel path returns exactly the same matches as a direct sequential scan.
func TestParallelMatchesEqualSequential(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.MaxMatchesPerFile = 1_000_000 // avoid cap-truncation skew between paths

	content := generateSmaliContent(8000)
	if len(content) < parallelThreshold {
		t.Skipf("generated content too small for parallel branch (%d bytes)", len(content))
	}
	lower := strings.ToLower(content)

	// Sequential ground truth.
	mSeq, err := NewMatcher(cfg)
	if err != nil {
		t.Fatal(err)
	}
	contentIsASCII := isASCII(content)
	fileIsSDK := isSDKPath("test.smali")
	candidates := mSeq.prefilterPatterns(lower, true, fileIsSDK)
	li := buildLineIndex(content)
	seq := mSeq.scanLines(content, lower, "test.smali", true, candidates, contentIsASCII, li, fileIsSDK)

	// Parallel path (fresh matcher so global counters do not cross-contaminate).
	mPar, _ := NewMatcher(cfg)
	par := mPar.MatchContentParallel(content, lower, "test.smali", true, 8)

	sSeq, sPar := sigOf(seq), sigOf(par)
	if len(sSeq) != len(sPar) {
		t.Fatalf("match count differs: sequential=%d parallel=%d", len(sSeq), len(sPar))
	}
	for i := range sSeq {
		if sSeq[i] != sPar[i] {
			t.Fatalf("match %d differs:\n seq=%q\n par=%q", i, sSeq[i], sPar[i])
		}
	}
}
