package adapter

import (
	"context"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func motionFixture() MotionConfig {
	return MotionConfig{IntervalMillis: 100, DurationSeconds: 5, Frames: []MotionFrame{
		{Readings: []SensorVector{{Name: "acceleration", Values: [3]float64{.1, 0, 9.8}}, {Name: "gyroscope", Values: [3]float64{.01, 0, 0}}}},
		{Readings: []SensorVector{{Name: "acceleration", Values: [3]float64{0, .1, 9.8}}, {Name: "gyroscope", Values: [3]float64{0, .01, 0}}}},
	}}
}

func TestSensorVectorParserRejectsInvalidReadings(t *testing.T) {
	for _, text := range []string{"OK", "acceleration = 1:2", "acceleration = 1:NaN:3", "acceleration = 1:Inf:3", "gyroscope = 1:2:3"} {
		if _, err := parseSensorVector(text, "acceleration"); err == nil {
			t.Fatalf("accepted %q", text)
		}
	}
	reading, err := parseSensorVector("acceleration = 2.23517e-07:9.77631:0.812348\nOK", "acceleration")
	if err != nil || reading.Values[1] != 9.77631 {
		t.Fatalf("reading=%+v err=%v", reading, err)
	}
	cfg := motionFixture()
	cfg.Frames[0].Readings[0].Values[0] = math.NaN()
	if err := validateMotion(cfg); err == nil {
		t.Fatal("accepted NaN playback")
	}
}

func TestPlaybackObservesAndroidEventsAndRestoresOriginalVectors(t *testing.T) {
	for _, frozen := range []string{"0", "1"} {
		t.Run("frozen="+frozen, func(t *testing.T) {
			t.Setenv("ANTIVM_ADB_HELPER", "motion")
			t.Setenv("ANTIVM_MOTION_FROZEN", frozen)
			trace := filepath.Join(t.TempDir(), "commands.txt")
			t.Setenv("ANTIVM_MOTION_TRACE", trace)
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			dev := NewADBAdapter(binary, "emulator-5584")
			ctx, cancel := context.WithCancel(context.Background())
			defer func() {
				cancel()
				if err := dev.Stop(context.Background()); err != nil {
					t.Error(err)
				}
			}()
			dev.BindSensorLifetime(ctx)
			cfg := motionFixture()
			applyCtx, applyCancel := context.WithCancel(ctx)
			result, err := dev.ApplyTestConfig(applyCtx, TestConfig{EmulatorOnly: true, Motion: &cfg})
			applyCancel() // ending a module must not end the bound analysis lifetime
			if err != nil || !result.OK() {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			time.Sleep(250 * time.Millisecond)
			st, err := dev.ReadState(ctx)
			if err != nil || st.Sensors["motion.active"] != "true" || st.Sensors["acceleration.samples"] != "12" {
				t.Fatalf("state=%+v err=%v", st, err)
			}
			want := "true"
			if frozen == "1" {
				want = "false"
			}
			if st.Sensors["acceleration.moving"] != want || st.Sensors["gyroscope.moving"] != want {
				t.Fatalf("probe output ignored: %+v", st.Sensors)
			}
			cancel()
			if err := dev.Stop(context.Background()); err != nil {
				t.Fatal(err)
			}
			commands, err := os.ReadFile(trace)
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(strings.TrimSpace(string(commands)), "\n")
			last := strings.Join(lines[len(lines)-2:], "\n")
			if !strings.Contains(last, "sensor set acceleration 0.000000:0.000000:9.806650") || !strings.Contains(last, "sensor set gyroscope 0.000000:0.000000:0.000000") {
				t.Fatalf("original values not restored: %s", last)
			}
		})
	}
}

func TestPlaybackDoesNotTreatConsoleKOAsSuccess(t *testing.T) {
	t.Setenv("ANTIVM_ADB_HELPER", "motion")
	t.Setenv("ANTIVM_MOTION_DENIED", "1")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dev := NewADBAdapter(binary, "emulator-5584")
	cfg := motionFixture()
	result, err := dev.ApplyTestConfig(context.Background(), TestConfig{Motion: &cfg})
	if err != nil || result.OK() || !strings.Contains(result.Failed[0].Err, "sensor disabled") {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}
