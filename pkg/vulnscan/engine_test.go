package vulnscan

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func newEngineForTest(t *testing.T) *Engine {
	t.Helper()
	s, err := NewScanner("http://example.com")
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	s.LogFunc = func(string) {}
	return NewEngine(s)
}

// TestRunInjection_CancellationClosesOutput verifies the leak claim: when ctx
// is cancelled while the producer NEVER closes the surfaces channel, all
// workers must exit and out must be closed (wg.Wait returning proves every
// worker goroutine terminated).
func TestRunInjection_CancellationClosesOutput(t *testing.T) {
	e := newEngineForTest(t)
	ctx, cancel := context.WithCancel(context.Background())
	surfaces := make(chan AttackSurface) // never closed, nothing sent

	out := e.RunInjection(ctx, surfaces, func(context.Context, AttackSurface) []Finding {
		return nil
	})

	cancel()
	select {
	case _, ok := <-out:
		if ok {
			t.Fatal("unexpected result after cancellation without input")
		}
		// ok == false: out closed, therefore wg.Wait returned and no worker leaked.
	case <-time.After(3 * time.Second):
		t.Fatal("out never closed after cancellation — goroutine leak")
	}
}

// TestRunInjection_ProcessesAllSurfaces is the happy path: every surface is
// processed exactly once and the channel closes when the producer finishes.
func TestRunInjection_ProcessesAllSurfaces(t *testing.T) {
	e := newEngineForTest(t)
	ctx := context.Background()

	const n = 6
	surfaces := make(chan AttackSurface, n)
	for i := 0; i < n; i++ {
		surfaces <- AttackSurface{ID: fmt.Sprintf("surf-%d", i)}
	}
	close(surfaces)

	out := e.RunInjection(ctx, surfaces, func(_ context.Context, as AttackSurface) []Finding {
		return []Finding{{ID: "TEST-" + as.ID}}
	})

	seen := make(map[string]bool)
	for res := range out {
		for _, f := range res.Findings {
			seen[f.ID] = true
		}
	}
	if len(seen) != n {
		t.Fatalf("got %d distinct findings, want %d (%v)", len(seen), n, seen)
	}
}

// TestRunInjection_PanicRecoveryContinues verifies a panicking checkFn does
// not kill the pool: the AIMD permit is released and remaining surfaces are
// still processed.
func TestRunInjection_PanicRecoveryContinues(t *testing.T) {
	e := newEngineForTest(t)
	ctx := context.Background()

	surfaces := make(chan AttackSurface, 3)
	surfaces <- AttackSurface{ID: "a"}
	surfaces <- AttackSurface{ID: "panic"}
	surfaces <- AttackSurface{ID: "b"}
	close(surfaces)

	out := e.RunInjection(ctx, surfaces, func(_ context.Context, as AttackSurface) []Finding {
		if as.ID == "panic" {
			panic("boom")
		}
		return []Finding{{ID: "TEST-" + as.ID}}
	})

	seen := make(map[string]bool)
	done := make(chan struct{})
	go func() {
		for res := range out {
			for _, f := range res.Findings {
				seen[f.ID] = true
			}
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("out never closed after panic — worker or permit leak")
	}
	if !seen["TEST-a"] || !seen["TEST-b"] {
		t.Fatalf("expected surfaces a and b processed despite panic, got %v", seen)
	}
	if seen["TEST-panic"] {
		t.Fatal("panicking surface should not emit findings")
	}
}
