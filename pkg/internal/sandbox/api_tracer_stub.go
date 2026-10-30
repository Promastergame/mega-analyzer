//go:build !windows

package sandbox

import (
	"context"
	"fmt"
)

// stubAPITracer is a no-op implementation for non-Windows platforms.
type stubAPITracer struct {
	calls chan APICall
}

func newAPITracer(categories []string) APITracer {
	return &stubAPITracer{
		calls: make(chan APICall),
	}
}

func (t *stubAPITracer) Attach(ctx context.Context, pid int) error {
	return fmt.Errorf("api tracing is only supported on Windows")
}

func (t *stubAPITracer) Detach(pid int) error {
	return fmt.Errorf("api tracing is only supported on Windows")
}

func (t *stubAPITracer) Calls() <-chan APICall {
	return t.calls
}

func (t *stubAPITracer) Stop() error {
	close(t.calls)
	return nil
}
