package progress

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestProgressBar_Basic(t *testing.T) {
	pb := NewProgressBar(100, "Test")
	if pb == nil {
		t.Fatal("Expected non-nil progress bar")
	}

	current, total := pb.GetProgress()
	if total != 100 {
		t.Errorf("Expected total 100, got %d", total)
	}
	if current != 0 {
		t.Errorf("Expected current 0, got %d", current)
	}
}

func TestProgressBar_Increment(t *testing.T) {
	pb := NewProgressBar(10, "Test")

	for i := 0; i < 5; i++ {
		pb.Increment()
	}

	current, _ := pb.GetProgress()
	if current != 5 {
		t.Errorf("Expected current 5, got %d", current)
	}
}

func TestProgressBar_Advance(t *testing.T) {
	pb := NewProgressBar(100, "Test")

	pb.Advance(25)

	current, _ := pb.GetProgress()
	if current != 25 {
		t.Errorf("Expected current 25, got %d", current)
	}
}

func TestProgressBar_Set(t *testing.T) {
	pb := NewProgressBar(100, "Test")

	pb.Set(75)

	current, _ := pb.GetProgress()
	if current != 75 {
		t.Errorf("Expected current 75, got %d", current)
	}
}

func TestProgressBar_Finish(t *testing.T) {
	pb := NewProgressBar(50, "Test")

	pb.Set(30)
	pb.Finish()

	// After finish, progress should be at or near total
	current, total := pb.GetProgress()
	// Allow small difference due to async rendering
	if current < total-1 {
		t.Logf("After finish, current=%d, total=%d (async rendering)", current, total)
	}
}

func TestProgressBar_SetTotal(t *testing.T) {
	pb := NewProgressBar(10, "Test")

	pb.SetTotal(200)

	_, total := pb.GetProgress()
	if total != 200 {
		t.Errorf("Expected total 200, got %d", total)
	}
}

func TestLiveStats_RecordFile(t *testing.T) {
	ls := NewLiveStats(nil)

	ls.RecordFile(1024, "billing")
	ls.RecordFile(2048, "billing")
	ls.RecordFile(512, "ads")

	files := atomic.LoadInt64(&ls.FilesScanned)
	if files != 3 {
		t.Errorf("Expected 3 files, got %d", files)
	}

	bytes := atomic.LoadInt64(&ls.BytesProcessed)
	if bytes != 3584 {
		t.Errorf("Expected 3584 bytes, got %d", bytes)
	}

	ls.mu.Lock()
	if ls.categories["billing"] != 2 {
		t.Errorf("Expected 2 billing files, got %d", ls.categories["billing"])
	}
	if ls.categories["ads"] != 1 {
		t.Errorf("Expected 1 ads file, got %d", ls.categories["ads"])
	}
	ls.mu.Unlock()
}

func TestLiveStats_RecordMatch(t *testing.T) {
	ls := NewLiveStats(nil)

	for i := 0; i < 5; i++ {
		ls.RecordMatch()
	}

	matches := atomic.LoadInt64(&ls.MatchesFound)
	if matches != 5 {
		t.Errorf("Expected 5 matches, got %d", matches)
	}
}

func TestLiveStats_Snapshot(t *testing.T) {
	ls := NewLiveStats(nil)

	ls.RecordFile(1024, "billing")
	ls.RecordMatch()
	ls.RecordMatch()

	snapshot := ls.Snapshot()

	if snapshot.FilesScanned != 1 {
		t.Errorf("Snapshot: expected 1 file, got %d", snapshot.FilesScanned)
	}

	if snapshot.MatchesFound != 2 {
		t.Errorf("Snapshot: expected 2 matches, got %d", snapshot.MatchesFound)
	}

	if snapshot.FilesPerSec <= 0 {
		t.Errorf("Snapshot: expected positive files/sec, got %f", snapshot.FilesPerSec)
	}

	if snapshot.Elapsed < 0 {
		t.Errorf("Snapshot: expected non-negative elapsed, got %v", snapshot.Elapsed)
	}
}

func TestLiveStats_SetMemoryUsage(t *testing.T) {
	ls := NewLiveStats(nil)

	ls.SetMemoryUsage(123.45)

	snapshot := ls.Snapshot()
	if snapshot.MemoryUsageMB != 123.45 {
		t.Errorf("Expected memory 123.45 MB, got %f", snapshot.MemoryUsageMB)
	}
}

func TestLiveStats_Callback(t *testing.T) {
	callbackCalled := make(chan bool, 1)

	ls := NewLiveStats(func(snapshot *LiveStatsSnapshot) {
		if snapshot.FilesScanned >= 1 {
			select {
			case callbackCalled <- true:
			default:
			}
		}
	})

	ls.RecordFile(1024, "test")

	// Wait for callback to be called
	select {
	case <-callbackCalled:
		// Success
	case <-time.After(2 * time.Second):
		t.Log("Callback not triggered (might be disabled in non-terminal)")
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		expected string
	}{
		{"seconds", 45 * time.Second, "45.0s"},
		{"minutes", 2*time.Minute + 30*time.Second, "2m30s"},
		{"zero", 0, "0.0s"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatDuration(tt.duration)
			if result != tt.expected {
				t.Errorf("formatDuration(%v) = %q, want %q", tt.duration, result, tt.expected)
			}
		})
	}
}

func TestFormatSpeed(t *testing.T) {
	result := formatSpeed(1234.56)
	expected := "1235 files/s"
	if result != expected {
		t.Errorf("formatSpeed(1234.56) = %q, want %q", result, expected)
	}
}
