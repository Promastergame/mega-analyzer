package androidruntime

import (
	"testing"
)

func TestRunnerGetters(t *testing.T) {
	runner, err := NewEmulatorRunner(RunnerConfig{
		Profile:     DefaultProfile(),
		EmulatorBin: "emulator",
		ADBBin:      "adb",
		SessionDir:  t.TempDir(),
	})
	if err != nil {
		t.Fatalf("NewEmulatorRunner: %v", err)
	}

	// Initial values must be sane / zero / unset.
	if got := runner.ConsolePort(); got != 0 {
		t.Errorf("ConsolePort initial = %d, want 0", got)
	}
	if got := runner.EmulatorPID(); got != 0 {
		t.Errorf("EmulatorPID initial = %d, want 0", got)
	}
	if !runner.StartedAt().IsZero() {
		t.Errorf("StartedAt initial should be zero time")
	}
	if !runner.StoppedAt().IsZero() {
		t.Errorf("StoppedAt initial should be zero time")
	}
	if got := runner.Warnings(); len(got) != 0 {
		t.Errorf("Warnings initial should be empty, got %v", got)
	}
}
