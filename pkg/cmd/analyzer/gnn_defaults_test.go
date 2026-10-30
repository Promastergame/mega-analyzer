package main

import (
	"context"
	"testing"
	"time"
)

func TestGNNCacheDiskLimitBytes(t *testing.T) {
	const maxInt64 = int64(1<<63 - 1)
	tests := []struct {
		name string
		mb   int64
		want int64
	}{
		{name: "negative remains invalid", mb: -1, want: -1},
		{name: "zero means unlimited", mb: 0, want: 0},
		{name: "one MiB", mb: 1, want: 1024 * 1024},
		{name: "overflow saturates", mb: maxInt64, want: maxInt64},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := gnnCacheDiskLimitBytes(tt.mb); got != tt.want {
				t.Fatalf("gnnCacheDiskLimitBytes(%d) = %d, want %d", tt.mb, got, tt.want)
			}
		})
	}
}

func TestFeedGNNJobsStopsWhenWorkersCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	jobs := make(chan int)
	done := make(chan bool, 1)
	go func() {
		done <- feedGNNJobs(ctx, jobs, []int{1, 2, 3})
	}()

	if got := <-jobs; got != 1 {
		t.Fatalf("first job = %d, want 1", got)
	}
	// Simulate the fatal-model path: the only worker exits and cancels the
	// internal context while the producer is about to send the next job.
	cancel()
	select {
	case stopped := <-done:
		if !stopped {
			t.Fatal("feed reported normal completion after cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("job feeder remained blocked after all workers exited")
	}
}
