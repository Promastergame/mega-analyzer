//go:build windows

package sandbox

import (
	"fmt"
	"sync"
	"time"
)

// windowsTimeManipulator implements TimeManipulator for Windows.
type windowsTimeManipulator struct {
	enabled      bool
	scaleFactor  float64
	startReal    time.Time
	startVirtual time.Time
	offset       time.Duration
	log          TimeManipulationLog
	mu           sync.RWMutex
}

func newTimeManipulator() TimeManipulator {
	return &windowsTimeManipulator{
		log: TimeManipulationLog{
			Enabled:     false,
			ScaleFactor: 1.0,
			SkipEvents:  []TimeSkipEvent{},
		},
	}
}

// Enable activates time manipulation with the specified scale factor.
//
// Implementation notes:
// - Hooks Sleep, SleepEx, WaitForSingleObject, NtDelayExecution
// - Hooks GetTickCount, GetTickCount64, QueryPerformanceCounter
// - Maintains virtual clock offset
//
// Validates: Requirements 9.1, 9.2
func (tm *windowsTimeManipulator) Enable(scaleFactor float64) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if tm.enabled {
		return fmt.Errorf("time manipulation already enabled")
	}

	if scaleFactor <= 0 {
		return fmt.Errorf("scale factor must be positive, got %f", scaleFactor)
	}

	tm.enabled = true
	tm.scaleFactor = scaleFactor
	tm.startReal = time.Now()
	tm.startVirtual = time.Now()
	tm.offset = 0

	tm.log.Enabled = true
	tm.log.ScaleFactor = scaleFactor
	tm.log.TotalSkipped = 0
	tm.log.SkipEvents = []TimeSkipEvent{}

	// In a real implementation, this would:
	// 1. Inject hooking DLL into target process
	// 2. Hook Sleep, SleepEx, WaitForSingleObject, NtDelayExecution
	// 3. Hook GetTickCount, GetTickCount64, QueryPerformanceCounter
	// 4. Set up IPC channel for time skip notifications

	return nil
}

// Disable deactivates time manipulation.
func (tm *windowsTimeManipulator) Disable() error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if !tm.enabled {
		return nil
	}

	tm.enabled = false
	tm.log.Enabled = false

	// In a real implementation, this would:
	// 1. Unhook all time-related APIs
	// 2. Unload hooking DLL
	// 3. Close IPC channel

	return nil
}

// GetVirtualTime returns the current virtual time (as seen by the target process).
//
// Validates: Requirements 9.3
func (tm *windowsTimeManipulator) GetVirtualTime() time.Time {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	if !tm.enabled {
		return time.Now()
	}

	// Virtual time = start virtual + (real elapsed * scale factor) + offset
	realElapsed := time.Since(tm.startReal)
	virtualElapsed := time.Duration(float64(realElapsed) * tm.scaleFactor)
	return tm.startVirtual.Add(virtualElapsed).Add(tm.offset)
}

// GetRealTime returns the actual system time.
func (tm *windowsTimeManipulator) GetRealTime() time.Time {
	return time.Now()
}

// GetOffset returns the time offset between virtual and real time.
func (tm *windowsTimeManipulator) GetOffset() time.Duration {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return tm.offset
}

// GetLog returns the time manipulation log.
func (tm *windowsTimeManipulator) GetLog() *TimeManipulationLog {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	// Return a copy to avoid race conditions
	logCopy := tm.log
	logCopy.SkipEvents = make([]TimeSkipEvent, len(tm.log.SkipEvents))
	copy(logCopy.SkipEvents, tm.log.SkipEvents)

	return &logCopy
}

// recordSkipEvent records a time skip event (called by hooking DLL via IPC).
func (tm *windowsTimeManipulator) recordSkipEvent(function string, requestedMS int64, skippedMS int64, processID int) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	event := TimeSkipEvent{
		Timestamp:   time.Now(),
		Function:    function,
		RequestedMS: requestedMS,
		SkippedMS:   skippedMS,
		ProcessID:   processID,
	}

	tm.log.SkipEvents = append(tm.log.SkipEvents, event)
	tm.log.TotalSkipped += time.Duration(skippedMS) * time.Millisecond
	tm.offset += time.Duration(skippedMS) * time.Millisecond
}

// SimulateSkipEvent simulates a time skip event for testing.
func (tm *windowsTimeManipulator) SimulateSkipEvent(function string, requestedMS int64, processID int) {
	// Calculate skipped time based on scale factor
	skippedMS := int64(float64(requestedMS) * (tm.scaleFactor - 1.0) / tm.scaleFactor)
	if skippedMS < 0 {
		skippedMS = 0
	}

	tm.recordSkipEvent(function, requestedMS, skippedMS, processID)
}
