package web

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// withTimeout runs fn and fails the test if it does not return in time.
// Every test in this file guards against a hang, because the bugs they cover
// manifested as a permanent deadlock rather than a wrong value.
func withTimeout(t *testing.T, d time.Duration, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s deadlocked (waited %s)", what, d)
	}
}

// TestJobBacklogLargerThanOldChannelBuffer is the regression test for the bug
// that made the web UI hang forever.
//
// The old subscribe() replayed the whole backlog into a 512-slot channel while
// holding the job mutex. Any scan that emitted more than 512 lines blocked
// there permanently, which also blocked broadcast() and finish() — so the
// analyzer subprocess stalled on a full stdout pipe and the browser never
// received the "done" event.
func TestJobBacklogLargerThanOldChannelBuffer(t *testing.T) {
	const lines = 5000 // far beyond the old 512 buffer

	job := newScanJob("t1", "", "")
	withTimeout(t, 10*time.Second, "broadcast of large backlog", func() {
		for i := 0; i < lines; i++ {
			job.broadcast(fmt.Sprintf("line %d", i))
		}
	})

	// A reader arriving after the backlog exists must get everything at once.
	withTimeout(t, 10*time.Second, "read of large backlog", func() {
		got, next, done, _, _ := job.read(0)
		if len(got) != lines {
			t.Errorf("got %d lines, want %d", len(got), lines)
		}
		if next != lines {
			t.Errorf("next cursor = %d, want %d", next, lines)
		}
		if done {
			t.Error("job reported done before finish()")
		}
	})

	// finish() must still be able to take the lock and must wake readers.
	withTimeout(t, 10*time.Second, "finish after large backlog", func() {
		job.finish(0)
	})
	if !job.isDone() {
		t.Error("job should be done after finish()")
	}
}

// TestJobReadResumesFromCursor covers SSE reconnects: the browser sends
// Last-Event-ID and must receive only what it has not seen yet.
func TestJobReadResumesFromCursor(t *testing.T) {
	job := newScanJob("t2", "", "")
	for i := 0; i < 10; i++ {
		job.broadcast(fmt.Sprintf("line %d", i))
	}

	got, next, _, _, _ := job.read(4)
	if len(got) != 6 {
		t.Fatalf("got %d lines from cursor 4, want 6", len(got))
	}
	if got[0] != "line 4" {
		t.Errorf("first resumed line = %q, want %q", got[0], "line 4")
	}
	if next != 10 {
		t.Errorf("next cursor = %d, want 10", next)
	}

	// Reading at the head returns nothing and does not block.
	got, _, _, _, _ = job.read(next)
	if len(got) != 0 {
		t.Errorf("expected no lines at head, got %d", len(got))
	}
}

// TestJobWaitChannelWakesReader verifies the notification channel a streaming
// reader parks on is actually closed when new data or completion arrives.
func TestJobWaitChannelWakesReader(t *testing.T) {
	job := newScanJob("t3", "", "")
	_, _, _, _, wait := job.read(0)

	go func() {
		time.Sleep(20 * time.Millisecond)
		job.broadcast("hello")
	}()

	select {
	case <-wait:
	case <-time.After(5 * time.Second):
		t.Fatal("reader was not woken by broadcast")
	}

	_, _, _, _, wait2 := job.read(1)
	go func() {
		time.Sleep(20 * time.Millisecond)
		job.finish(3)
	}()

	select {
	case <-wait2:
	case <-time.After(5 * time.Second):
		t.Fatal("reader was not woken by finish")
	}

	if _, _, done, code, _ := job.read(1); !done || code != 3 {
		t.Errorf("done=%v code=%d, want true/3", done, code)
	}
}

// TestJobConcurrentReadersAndWriter simulates several browser tabs streaming
// the same job while output is still being produced.
func TestJobConcurrentReadersAndWriter(t *testing.T) {
	const (
		lines   = 2000
		readers = 8
	)
	job := newScanJob("t4", "", "")

	withTimeout(t, 20*time.Second, "concurrent readers and writer", func() {
		var wg sync.WaitGroup

		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < lines; i++ {
				job.broadcast(fmt.Sprintf("line %d", i))
			}
			job.finish(0)
		}()

		for r := 0; r < readers; r++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				cursor, seen := 0, 0
				for {
					batch, next, done, _, wait := job.read(cursor)
					seen += len(batch)
					cursor = next
					if done {
						break
					}
					<-wait
				}
				if seen != lines {
					t.Errorf("reader saw %d lines, want %d", seen, lines)
				}
			}()
		}

		wg.Wait()
	})
}

// TestJobTrimKeepsCursorsConsistent checks that trimming the buffer advances
// `base` so a stale cursor is clamped instead of returning wrong lines.
func TestJobTrimKeepsCursorsConsistent(t *testing.T) {
	job := newScanJob("t5", "", "")
	job.mu.Lock()
	job.lines = []string{"c", "d"}
	job.base = 2 // pretend lines 0 and 1 were trimmed away
	job.mu.Unlock()

	got, next, _, _, _ := job.read(0)
	if next != 4 {
		t.Errorf("next cursor = %d, want 4", next)
	}
	if len(got) != 2 || got[0] != "c" {
		t.Errorf("got %v, want [c d]", got)
	}
}
