package web

import (
	"context"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestLiveEnqueueInput_OrderAndOverflow(t *testing.T) {
	orig := liveRunInput
	defer func() { liveRunInput = orig }()

	release := make(chan struct{})
	var mu sync.Mutex
	var got []string
	liveRunInput = func(ctx context.Context, adb string, args []string) error {
		<-release
		mu.Lock()
		got = append(got, args[len(args)-1])
		mu.Unlock()
		return nil
	}

	serial := "test-order-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	var accepted []string
	for i := 0; i < liveInputQueueSize+10; i++ {
		k := strconv.Itoa(i)
		if liveEnqueueInput("adb-test", serial, "input", "keyevent", k) {
			accepted = append(accepted, k)
		}
	}
	// At most one event in flight plus a full queue.
	if len(accepted) > liveInputQueueSize+1 {
		t.Fatalf("queue not bounded: accepted %d events", len(accepted))
	}
	if len(accepted) < liveInputQueueSize {
		t.Fatalf("queue too small: accepted only %d events", len(accepted))
	}
	close(release)

	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n == len(accepted) || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != len(accepted) {
		t.Fatalf("ran %d of %d accepted events", len(got), len(accepted))
	}
	for i := range got {
		if got[i] != accepted[i] {
			t.Fatalf("event %d out of order: got %q want %q", i, got[i], accepted[i])
		}
	}
}

func TestClampLiveDur(t *testing.T) {
	if clampLiveDur(500) != 500 || clampLiveDur(liveMaxGestureMs+1) != liveMaxGestureMs {
		t.Fatal("clampLiveDur wrong")
	}
}
