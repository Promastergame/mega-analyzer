package web

import (
	"context"
	"os/exec"
	"sync"
	"time"
)

// Live input (tap / swipe / key) used to spawn one detached `adb` process per
// browser event with no timeout. A held swipe or fast tapping could pile up
// hundreds of adb processes. Now every device gets one bounded FIFO queue and
// a single worker: events run in order, each with a hard timeout, and when
// the queue is full new events are dropped instead of spawning more work.

const (
	liveInputQueueSize = 32
	liveInputTimeout   = 15 * time.Second
	liveMaxGestureMs   = 10000
)

var liveInputQueues sync.Map // adb+"\x00"+serial -> chan []string

// liveRunInput is a variable so tests can replace the adb call.
var liveRunInput = func(ctx context.Context, adb string, args []string) error {
	return exec.CommandContext(ctx, adb, args...).Run()
}

// liveEnqueueInput queues `adb -s <serial> shell <shellArgs...>` for the
// device worker. It returns false when the queue is full (event dropped).
func liveEnqueueInput(adb, serial string, shellArgs ...string) bool {
	key := adb + "\x00" + serial
	v, ok := liveInputQueues.Load(key)
	if !ok {
		ch := make(chan []string, liveInputQueueSize)
		var loaded bool
		v, loaded = liveInputQueues.LoadOrStore(key, ch)
		if !loaded {
			go liveInputWorker(adb, ch)
		}
	}
	args := append([]string{"-s", serial, "shell"}, shellArgs...)
	select {
	case v.(chan []string) <- args:
		return true
	default:
		return false
	}
}

func liveInputWorker(adb string, ch <-chan []string) {
	for args := range ch {
		ctx, cancel := context.WithTimeout(context.Background(), liveInputTimeout)
		_ = liveRunInput(ctx, adb, args)
		cancel()
	}
}

// clampLiveDur caps swipe / long-press duration so one gesture cannot hold
// the device queue for minutes.
func clampLiveDur(ms int) int {
	if ms > liveMaxGestureMs {
		return liveMaxGestureMs
	}
	return ms
}
