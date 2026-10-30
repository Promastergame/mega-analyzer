//go:build !windows

package sandbox

import (
	"context"
	"fmt"
)

// Stub implementations for non-Windows platforms

// pipeHandle is a stub for non-Windows platforms.
type pipeHandle struct{}

// connectToPipe is not supported on non-Windows platforms.
func (km *kernelMonitorImpl) connectToPipe(ctx context.Context) (pipeHandle, error) {
	return pipeHandle{}, fmt.Errorf("kernel monitor is only supported on Windows")
}

// readEvent is not supported on non-Windows platforms.
func (km *kernelMonitorImpl) readEvent(pipe pipeHandle, buffer []byte) (KernelEvent, error) {
	return KernelEvent{}, fmt.Errorf("kernel monitor is only supported on Windows")
}

// closePipe is not supported on non-Windows platforms.
func (km *kernelMonitorImpl) closePipe(pipe pipeHandle) {
	// No-op on non-Windows
}

// verifyDriverLoaded is not supported on non-Windows platforms.
func (km *kernelMonitorImpl) verifyDriverLoaded() error {
	return fmt.Errorf("kernel monitor is only supported on Windows")
}
