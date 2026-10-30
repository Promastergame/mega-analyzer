package progress

import (
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// Review round: the package has no production callers, so these bugs lived
// unexercised — double Stop panicking on a closed channel, garbage first-
// frame ETA (0/0 speed), Repeat panicking on negative progress, and a
// nil-deref in isTerminal.

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()
	fn()
	_ = w.Close()
	os.Stdout = old
	out, _ := io.ReadAll(r)
	return string(out)
}

func testBar(current, total int64) *ProgressBar {
	return &ProgressBar{
		total: total, current: current,
		width: 50, label: "x", showETA: true, showSpeed: true,
		startTime: time.Now(),
	}
}

func TestReviewRenderNegativeNoPanic(t *testing.T) {
	out := captureStdout(t, func() {
		pb := testBar(-5, 100)
		pb.render()
		pb.render() // idempotent, still no panic
	})
	if !strings.Contains(out, "(0/100)") {
		t.Errorf("negative progress should display clamped (0/100), got %q", out)
	}
	if strings.Contains(out, "-") {
		t.Errorf("clamped render must not contain '-': %q", out)
	}
}

func TestReviewRenderOvershootNoPanic(t *testing.T) {
	out := captureStdout(t, func() {
		testBar(150, 100).render()
	})
	if !strings.Contains(out, "(100/100)") {
		t.Errorf("overshoot should display clamped (100/100), got %q", out)
	}
}

func TestReviewFirstFrameNoGarbageETA(t *testing.T) {
	// current == 0 means speed == 0; the old code divided by it and printed
	// a platform-defined garbage duration on the very first frame.
	out := captureStdout(t, func() {
		testBar(0, 100).render()
	})
	if !strings.Contains(out, "(0/100)") {
		t.Fatalf("expected counts in output, got %q", out)
	}
	if strings.Contains(out, "-") {
		t.Errorf("zero-progress frame must not print a garbage ETA: %q", out)
	}
}

func TestReviewFinishZeroTotalNoPanic(t *testing.T) {
	captureStdout(t, func() {
		pb := testBar(0, 0)
		pb.Finish()
	})
}

func TestReviewDoubleStopNoPanic(t *testing.T) {
	ls := &LiveStats{
		stopChan:  make(chan struct{}),
		startTime: time.Now(), lastStats: time.Now(),
		categories: make(map[string]int64),
	}
	go ls.runUpdateLoop()
	ls.Stop()
	ls.Stop() // old code panicked: close of closed channel

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); ls.Stop() }()
	}
	wg.Wait()
}

func TestReviewStopDisabledNoPanic(t *testing.T) {
	ls := NewLiveStats(nil)
	ls.disabled = true
	ls.Stop()
	ls.Stop()
}

func TestReviewIsTerminal(t *testing.T) {
	_ = isTerminal() // must not panic even with redirected stdout
}
