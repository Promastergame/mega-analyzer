package progress

import (
	"sync"
	"testing"
	"time"
)

func TestProgressBar_Ext(t *testing.T) {
	// Force enable for testing
	pb := NewProgressBar(100, "Test")
	pb.disabled = false

	pb.Increment()
	pb.Advance(10)
	pb.Set(50)

	curr, total := pb.GetProgress()
	if curr != 50 || total != 100 {
		t.Errorf("Wrong progress: %d/%d", curr, total)
	}

	pb.SetTotal(200)
	_, total2 := pb.GetProgress()
	if total2 != 200 {
		t.Error("SetTotal failed")
	}

	// Test rendering
	pb.render()
	pb.Finish()
}

func TestLiveStats_Ext(t *testing.T) {
	var mu sync.Mutex
	var lastSnapshot *LiveStatsSnapshot
	ls := NewLiveStats(func(s *LiveStatsSnapshot) {
		mu.Lock()
		lastSnapshot = s
		mu.Unlock()
	})
	// Manually start loop if it didn't start (e.g. in non-terminal mode)
	if ls.disabled {
		ls.disabled = false
		go ls.runUpdateLoop()
	}

	ls.RecordFile(1024, "category1")
	ls.RecordFile(2048, "category1")
	ls.RecordFile(512, "category2")
	ls.RecordMatch()
	ls.SetMemoryUsage(128.5)

	snapshot := ls.Snapshot()
	if snapshot.FilesScanned != 3 {
		t.Errorf("Expected 3 files, got %d", snapshot.FilesScanned)
	}

	ls.PrintFinal()

	// Wait a bit for the async update loop
	time.Sleep(700 * time.Millisecond)
	mu.Lock()
	snap := lastSnapshot
	mu.Unlock()
	if snap == nil {
		t.Error("Async update callback was not called")
	}
}

func TestFormatHelpers(t *testing.T) {
	s := formatSpeed(123.4)
	if s != "123 files/s" {
		t.Errorf("unexpected speed format: %s", s)
	}

	d1 := formatDuration(30 * time.Second)
	if d1 != "30.0s" {
		t.Errorf("unexpected duration format: %s", d1)
	}

	d2 := formatDuration(125 * time.Second)
	if d2 != "2m5s" {
		t.Errorf("unexpected duration format: %s", d2)
	}
}
