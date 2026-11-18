package adapter

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPlaybackFailureAfterStartupIsObservable(t *testing.T) {
	t.Setenv("ANTIVM_ADB_HELPER", "motion")
	t.Setenv("ANTIVM_MOTION_FAIL_LATER", "1")
	t.Setenv("ANTIVM_MOTION_TRACE", filepath.Join(t.TempDir(), "commands.txt"))
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dev := NewADBAdapter(binary, "emulator-5584")
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); _ = dev.Stop(context.Background()) }()
	cfg := motionFixture()
	result, err := dev.ApplyTestConfig(ctx, TestConfig{Motion: &cfg})
	if err != nil || !result.OK() {
		t.Fatalf("startup=%+v err=%v", result, err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for dev.SensorPlaybackStatus().Active && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	st, err := dev.ReadState(ctx)
	if err != nil || st.Sensors["motion.active"] != "false" || !strings.Contains(st.Extra["sensor-playback.error"], "playback transport failed") {
		t.Fatalf("failed worker reported success: %+v, %v", st, err)
	}
	if err := dev.Stop(context.Background()); err == nil {
		t.Fatal("playback/restore error was swallowed")
	}
}
