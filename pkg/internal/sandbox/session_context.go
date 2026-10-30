package sandbox

import (
	"context"
	"time"
)

// observationContext keeps cancellation (Stop / server shutdown) in both modes.
// No artificial deadline is attached when duration is zero.
func observationContext(parent context.Context, duration time.Duration) (context.Context, context.CancelFunc) {
	if duration == 0 {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, duration)
}
