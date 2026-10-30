package sandbox

import (
	"testing"
	"time"
)

func TestNewScrcpyManager(t *testing.T) {
	config := &ScrcpyConfig{
		Enabled:        true,
		Serial:         "emulator-5554",
		MaxSize:        1080,
		VideoBitrate:   "8M",
		AudioBitrate:   "128K",
		MaxFPS:         60,
		StayAwake:      true,
		TurnScreenOff:  true,
		ShowTouches:    true,
		RecordingPath:  "test.mp4",
		LogPath:        "test.log",
		Timeout:        30 * time.Second,
		AdditionalArgs: []string{"--no-control"},
	}

	sm := NewScrcpyManager(config)
	if sm == nil {
		t.Fatal("expected ScrcpyManager, got nil")
	}
	if sm.config != config {
		t.Errorf("expected config %v, got %v", config, sm.config)
	}
	if sm.eventChan == nil {
		t.Error("expected eventChan to be initialized")
	}
	if sm.ctx == nil {
		t.Error("expected ctx to be initialized")
	}

	args := sm.buildScrcpyArgs()
	expectedArgs := []string{
		"--serial", "emulator-5554",
		"--max-size", "1080",
		"--video-bit-rate", "8M",
		"--max-fps", "60",
		"--audio-bit-rate", "128K",
		"--stay-awake",
		"--turn-screen-off",
		"--show-touches",
		"--record", "test.mp4",
		"--no-control",
	}

	if len(args) != len(expectedArgs) {
		t.Fatalf("expected args len %d, got %d. args: %v", len(expectedArgs), len(args), args)
	}

	for i, arg := range expectedArgs {
		if args[i] != arg {
			t.Errorf("expected arg[%d]=%s, got %s", i, arg, args[i])
		}
	}
}

func TestScrcpyManager_StartStop_Disabled(t *testing.T) {
	config := &ScrcpyConfig{
		Enabled: false,
	}
	sm := NewScrcpyManager(config)

	err := sm.Start()
	if err != nil {
		t.Errorf("expected nil error when starting disabled manager, got %v", err)
	}
	if sm.IsRunning() {
		t.Error("expected IsRunning to be false")
	}

	err = sm.Stop()
	if err != nil {
		t.Errorf("expected nil error when stopping disabled manager, got %v", err)
	}
}

func TestScrcpyManager_GetEventChannel(t *testing.T) {
	sm := NewScrcpyManager(&ScrcpyConfig{})
	ch := sm.GetEventChannel()
	if ch == nil {
		t.Error("expected event channel, got nil")
	}
}

func TestScrcpyManager_IsRunning_Initially(t *testing.T) {
	sm := NewScrcpyManager(&ScrcpyConfig{})
	if sm.IsRunning() {
		t.Error("expected IsRunning to be false initially")
	}
}
