package antivm

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	// Use the test executable as ADB to exercise the legacy runtime on Windows
	// and POSIX without connecting to a device or launching the fixture.
	if os.Getenv("ANTIVM_THERMAL_HELPER") == "1" {
		command := os.Args[len(os.Args)-1]
		switch {
		case command == "get-serialno":
			fmt.Println(os.Getenv("ANTIVM_THERMAL_SERIAL"))
		case command == "acceleration" || command == "gyroscope":
			fmt.Printf("%s = 0:0:9.80665\nOK\n", command)
		case strings.Contains(command, "app_process /system/bin MegaSensorProbe"):
			moving := os.Getenv("ANTIVM_THERMAL_FROZEN") != "1"
			fmt.Printf("sensor.acceleration.available=true\nsensor.acceleration.moving=%t\nsensor.gyroscope.available=true\nsensor.gyroscope.moving=%t\n", moving, moving)
		case command == "cat '/sys/class/thermal/thermal_zone0/temp'":
			reading := os.Getenv("ANTIVM_THERMAL_READING")
			if reading == "missing" {
				os.Exit(1)
			}
			fmt.Println(reading)
		case strings.Contains(command, "nsenter -t 1 -m"):
			if os.Getenv("ANTIVM_THERMAL_APPLY_FAILED") == "1" {
				fmt.Fprintln(os.Stderr, "mount denied")
				os.Exit(1)
			}
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestLegacyThermalReportRequiresSuccessfulReadback(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, serial, reading, applyFailed string
		want                               int
	}{
		{"verified", "emulator-5582", "28000", "", 28000},
		{"zero", "emulator-5582", "0", "", 0},
		{"missing", "emulator-5582", "missing", "", 0},
		{"failed mount", "emulator-5582", "28000", "1", 0},
		{"physical device", "physical-phone", "28000", "", 0},
		{"unselected", "unknown", "28000", "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("ANTIVM_THERMAL_HELPER", "1")
			t.Setenv("ANTIVM_THERMAL_SERIAL", tc.serial)
			t.Setenv("ANTIVM_THERMAL_READING", tc.reading)
			t.Setenv("ANTIVM_THERMAL_APPLY_FAILED", tc.applyFailed)
			engine := NewEvasionEngine(EvasionConfig{Enabled: true, SensorNoise: true})
			engine.report.ThermalTemperatureMilliC = 28000 // stale success must not survive
			ctx, cancel := context.WithCancel(context.Background())
			defer func() {
				cancel()
				if err := engine.StopSensorNoise(context.Background()); err != nil {
					t.Error(err)
				}
			}()
			if err := engine.Apply(ctx, binary, ""); err != nil {
				t.Fatal(err)
			}
			report := engine.Report()
			if report.ThermalTemperatureMilliC != tc.want {
				t.Fatalf("report=%+v", report)
			}
			if tc.name == "verified" && !report.SensorNoiseActive {
				t.Fatal("verified Android motion events were not reported")
			}
			if tc.want == 0 && len(report.Warnings) == 0 {
				t.Fatal("thermal failure was not reported")
			}
			if tc.name == "verified" {
				if err := engine.StopSensorNoise(context.Background()); err != nil {
					t.Fatal(err)
				}
				if engine.Report().SensorNoiseActive {
					t.Fatal("stopped playback still reported active")
				}
			}
		})
	}
}

func TestLegacySensorNoiseRejectsStaticAndroidEvents(t *testing.T) {
	t.Setenv("ANTIVM_THERMAL_HELPER", "1")
	t.Setenv("ANTIVM_THERMAL_SERIAL", "emulator-5584")
	t.Setenv("ANTIVM_THERMAL_READING", "28000")
	t.Setenv("ANTIVM_THERMAL_FROZEN", "1")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	engine := NewEvasionEngine(EvasionConfig{Enabled: true, SensorNoise: true})
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		if err := engine.StopSensorNoise(context.Background()); err != nil {
			t.Error(err)
		}
	}()
	if err := engine.Apply(ctx, binary, ""); err != nil {
		t.Fatal(err)
	}
	report := engine.Report()
	if report.SensorNoiseActive || report.ThermalTemperatureMilliC != 28000 || len(report.Warnings) == 0 {
		t.Fatalf("static events passed: %+v", report)
	}
}
