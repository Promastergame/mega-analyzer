package sandbox

import (
	"testing"
	"time"
)

func TestTimeManipulator_Enable(t *testing.T) {
	tm := NewTimeManipulator()

	err := tm.Enable(10.0)
	if err != nil {
		t.Skipf("Time manipulation enable failed (expected on non-Windows): %v", err)
	}

	defer tm.Disable()

	log := tm.GetLog()
	if !log.Enabled {
		t.Error("Expected time manipulation to be enabled")
	}
	if log.ScaleFactor != 10.0 {
		t.Errorf("Expected scale factor 10.0, got %f", log.ScaleFactor)
	}
}

func TestTimeManipulator_Disable(t *testing.T) {
	tm := NewTimeManipulator()

	err := tm.Enable(10.0)
	if err != nil {
		t.Skipf("Time manipulation enable failed (expected on non-Windows): %v", err)
	}

	err = tm.Disable()
	if err != nil {
		t.Errorf("Disable failed: %v", err)
	}

	log := tm.GetLog()
	if log.Enabled {
		t.Error("Expected time manipulation to be disabled")
	}
}

func TestTimeManipulator_VirtualTime(t *testing.T) {
	tm := NewTimeManipulator()

	err := tm.Enable(10.0)
	if err != nil {
		t.Skipf("Time manipulation enable failed (expected on non-Windows): %v", err)
	}

	defer tm.Disable()

	// Wait a short time
	time.Sleep(100 * time.Millisecond)

	virtualTime := tm.GetVirtualTime()
	realTime := tm.GetRealTime()

	// Virtual time should be ahead of real time (or equal on non-Windows)
	if virtualTime.Before(realTime) {
		t.Errorf("Virtual time should not be before real time")
	}
}

func TestTimeManipulator_Offset(t *testing.T) {
	tm := NewTimeManipulator()

	err := tm.Enable(10.0)
	if err != nil {
		t.Skipf("Time manipulation enable failed (expected on non-Windows): %v", err)
	}

	defer tm.Disable()

	offset := tm.GetOffset()
	if offset < 0 {
		t.Errorf("Offset should not be negative, got %v", offset)
	}
}

func TestTimeManipulator_InvalidScaleFactor(t *testing.T) {
	tm := NewTimeManipulator()

	err := tm.Enable(0.0)
	if err == nil {
		t.Error("Expected error for zero scale factor")
	}

	err = tm.Enable(-1.0)
	if err == nil {
		t.Error("Expected error for negative scale factor")
	}
}

func TestTimeManipulator_GetLog(t *testing.T) {
	tm := NewTimeManipulator()

	err := tm.Enable(10.0)
	if err != nil {
		t.Skipf("Time manipulation enable failed (expected on non-Windows): %v", err)
	}

	defer tm.Disable()

	log := tm.GetLog()
	if log == nil {
		t.Fatal("Expected non-nil log")
	}

	if !log.Enabled {
		t.Error("Expected log to show enabled state")
	}

	if log.ScaleFactor != 10.0 {
		t.Errorf("Expected scale factor 10.0, got %f", log.ScaleFactor)
	}

	if log.SkipEvents == nil {
		t.Error("Expected non-nil SkipEvents slice")
	}
}

func TestDefaultTimeConfig(t *testing.T) {
	config := DefaultTimeConfig()

	if config.ScaleFactor != 10.0 {
		t.Errorf("Expected default scale factor 10.0, got %f", config.ScaleFactor)
	}

	if config.MaxSkip != 60*time.Second {
		t.Errorf("Expected default max skip 60s, got %v", config.MaxSkip)
	}
}
