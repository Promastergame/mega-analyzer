//go:build !windows

package sandbox

import (
	"fmt"
	"time"
)

// stubTimeManipulator is a no-op implementation for non-Windows platforms.
type stubTimeManipulator struct{}

func newTimeManipulator() TimeManipulator {
	return &stubTimeManipulator{}
}

func (tm *stubTimeManipulator) Enable(scaleFactor float64) error {
	return fmt.Errorf("time manipulation is only supported on Windows")
}

func (tm *stubTimeManipulator) Disable() error {
	return nil
}

func (tm *stubTimeManipulator) GetVirtualTime() time.Time {
	return time.Now()
}

func (tm *stubTimeManipulator) GetRealTime() time.Time {
	return time.Now()
}

func (tm *stubTimeManipulator) GetOffset() time.Duration {
	return 0
}

func (tm *stubTimeManipulator) GetLog() *TimeManipulationLog {
	return &TimeManipulationLog{
		Enabled:     false,
		ScaleFactor: 1.0,
		SkipEvents:  []TimeSkipEvent{},
	}
}
