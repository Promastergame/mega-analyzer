package main

import (
	"context"
	"os"
	"path/filepath"
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

func TestBundledGNNDiscoverySelectsSupportedJSON(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	rustDir := filepath.Join(root, "rust")
	if err := os.MkdirAll(rustDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rustDir, "gnn_weights.gnnbuf"), []byte("native-only"), 0600); err != nil {
		t.Fatal(err)
	}
	if path := discoverBundledGNNWeights(binDir); path != "" {
		t.Fatalf("unsupported compact weights selected: %s", path)
	}
	want := filepath.Join(rustDir, "gnn_weights.json")
	if err := os.WriteFile(want, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := discoverBundledGNNWeights(binDir); got != want {
		t.Fatalf("bundled JSON not discovered: %s, want %s", got, want)
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
