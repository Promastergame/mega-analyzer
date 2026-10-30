package web

import (
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func awaitQueueSignal(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("queue did not make progress")
	}
}

func TestQueueBoundsExecutionAndCancelsWaitingJob(t *testing.T) {
	q := newScanQueue(1, 1)
	first := newScanJob("first", "", "")
	started, release := make(chan struct{}), make(chan struct{})
	if !q.reserve() {
		t.Fatal("first reservation")
	}
	if err := q.submit(first, func() { close(started); <-release; first.finish(0) }); err != nil {
		t.Fatal(err)
	}
	awaitQueueSignal(t, started)
	defer close(release)
	tmp := t.TempDir()
	second := newScanJob("second", tmp, "")
	var secondRan atomic.Bool
	if !q.reserve() {
		t.Fatal("second reservation")
	}
	if err := q.submit(second, func() { secondRan.Store(true); second.finish(0) }); err != nil {
		t.Fatal(err)
	}
	if q.reserve() {
		t.Fatal("queue accepted beyond its capacity")
	}
	if second.status() != "queued" {
		t.Fatal("second job must wait")
	}
	second.stop()
	if !second.isDone() || second.status() != "stopped" || secondRan.Load() {
		t.Fatal("cancelled job executed or did not finish")
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatal("cancelled upload was not removed")
	}
	if !q.reserve() {
		t.Fatal("cancel did not release capacity")
	}
	q.release()
	q.shutdown()
	if q.reserve() {
		t.Fatal("shut down queue accepted work")
	}
}

func TestQueueStartsPendingJobsInOrder(t *testing.T) {
	q := newScanQueue(1, 2)
	start, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	order := make(chan string, 3)
	first := newScanJob("one", "", "")
	q.reserve()
	q.submit(first, func() { order <- "one"; close(start); <-release; first.finish(0) })
	awaitQueueSignal(t, start)
	for _, id := range []string{"two", "three"} {
		job := newScanJob(id, "", "")
		if !q.reserve() {
			t.Fatal("reservation")
		}
		if err := q.submit(job, func() {
			order <- job.id
			job.finish(0)
			if job.id == "three" {
				close(finished)
			}
		}); err != nil {
			t.Fatal(err)
		}
	}
	close(release)
	awaitQueueSignal(t, finished)
	for _, want := range []string{"one", "two", "three"} {
		if got := <-order; got != want {
			t.Fatalf("got %s, want %s", got, want)
		}
	}
}
