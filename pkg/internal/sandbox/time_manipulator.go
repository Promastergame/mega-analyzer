package sandbox

import (
	"time"
)

// TimeManipulator accelerates analysis by skipping sleep delays and
// manipulating system time perception.
//
// Validates: Requirements 9.1, 9.2, 9.3
type TimeManipulator interface {
	// Enable activates time manipulation with the specified scale factor
	// scaleFactor: 1.0 = real-time, 10.0 = 10x faster
	Enable(scaleFactor float64) error

	// Disable deactivates time manipulation
	Disable() error

	// GetVirtualTime returns the current virtual time (as seen by the target process)
	GetVirtualTime() time.Time

	// GetRealTime returns the actual system time
	GetRealTime() time.Time

	// GetOffset returns the time offset between virtual and real time
	GetOffset() time.Duration

	// GetLog returns the time manipulation log
	GetLog() *TimeManipulationLog
}

// NewTimeManipulator creates a new time manipulator.
func NewTimeManipulator() TimeManipulator {
	return newTimeManipulator()
}

// TimeConfig holds configuration for time manipulation.
type TimeConfig struct {
	ScaleFactor float64       // 1.0 = real-time, 10.0 = 10x faster
	MaxSkip     time.Duration // Maximum single skip
}

// DefaultTimeConfig returns the default time manipulation configuration.
func DefaultTimeConfig() TimeConfig {
	return TimeConfig{
		ScaleFactor: 10.0,
		MaxSkip:     60 * time.Second,
	}
}
