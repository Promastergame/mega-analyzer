package adapter

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	if os.Getenv("ANTIVM_ADB_HELPER") == "motion" {
		command := strings.Join(os.Args[1:], " ")
		if trace := os.Getenv("ANTIVM_MOTION_TRACE"); trace != "" {
			file, err := os.OpenFile(trace, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				os.Exit(2)
			}
			fmt.Fprintln(file, command)
			file.Close()
		}
		if strings.Contains(command, "emu sensor set") && os.Getenv("ANTIVM_MOTION_FAIL_LATER") == "1" {
			trace, err := os.ReadFile(os.Getenv("ANTIVM_MOTION_TRACE"))
			if err != nil {
				os.Exit(2)
			}
			if strings.Count(string(trace), "emu sensor set") > 2 {
				fmt.Println("KO: playback transport failed")
				os.Exit(0)
			}
		}
		switch {
		case strings.Contains(command, "emu sensor get acceleration"):
			fmt.Println("acceleration = 0:0:9.80665\nOK")
		case strings.Contains(command, "emu sensor get gyroscope"):
			fmt.Println("gyroscope = 0:0:0\nOK")
		case strings.Contains(command, "emu sensor set") && os.Getenv("ANTIVM_MOTION_DENIED") == "1":
			fmt.Println("KO: sensor disabled")
		case strings.Contains(command, "app_process /system/bin MegaSensorProbe"):
			moving := os.Getenv("ANTIVM_MOTION_FROZEN") != "1"
			fmt.Printf("sensor.acceleration.available=true\nsensor.acceleration.samples=12\nsensor.acceleration.moving=%t\nsensor.gyroscope.available=true\nsensor.gyroscope.samples=12\nsensor.gyroscope.moving=%t\n", moving, moving)
		default:
			fmt.Println("OK")
		}
		os.Exit(0)
	}
	if os.Getenv("ANTIVM_ADB_HELPER") == "root-writer" {
		command := os.Args[len(os.Args)-1]
		if trace := os.Getenv("ANTIVM_ADB_TRACE"); trace != "" {
			file, err := os.OpenFile(trace, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				os.Exit(2)
			}
			fmt.Fprintln(file, command)
			file.Close()
		}
		if command == "id -u" {
			fmt.Println("0")
		}
		os.Exit(0)
	}
	if os.Getenv("ANTIVM_ADB_HELPER") == "setprop-failure" {
		fmt.Fprintln(os.Stderr, "Failed to set property 'ro.product.model' to 'Pixel 8'.")
		fmt.Fprintln(os.Stderr, "See dmesg for error reason.")
		os.Exit(1)
	}
	if os.Getenv("ANTIVM_ADB_HELPER") == "state" {
		command := os.Args[len(os.Args)-1]
		switch command {
		case "getprop":
			fmt.Println("[ro.kernel.qemu]: [1]\n[ro.product.cpu.abi]: [x86_64]\n[ro.build.version.sdk]: [35]")
		case "wm size":
			fmt.Println("Physical size: 1080x2400\nOverride size: 1080x2160")
		case "wm density":
			fmt.Println("Physical density: 420\nOverride density: 440")
		case "dumpsys battery":
			fmt.Println("AC powered: false\nUSB powered: true\nlevel: 71\nstatus: 2\nhealth: 2\ntemperature: 315")
		case "cat '" + ThermalTemperaturePath + "'":
			fmt.Println("28000")
		default:
			if strings.Contains(command, "/dev/qemu_pipe") {
				fmt.Println("yes")
			} else {
				fmt.Println("no")
			}
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestConfiguredWriterIsUsedAndRequiresAnExplicitAVD(t *testing.T) {
	t.Setenv("ANTIVM_ADB_HELPER", "root-writer")
	trace := t.TempDir() + string(os.PathSeparator) + "commands.txt"
	t.Setenv("ANTIVM_ADB_TRACE", trace)
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dev := NewADBAdapter(binary, "physical-phone")
	if err := dev.ConfigureResetprop(context.Background(), "/data/local/tmp/resetprop", false); err == nil {
		t.Fatal("physical device accepted")
	}
	dev.Serial = "emulator-5572"
	if err := dev.ConfigureResetprop(context.Background(), "/data/local/tmp/resetprop", false); err != nil {
		t.Fatal(err)
	}
	res, err := dev.ApplyTestConfig(context.Background(), TestConfig{Props: []PropSet{{Key: "ro.product.model", Value: "Pixel 3"}}})
	if err != nil || !res.OK() {
		t.Fatalf("apply=%+v, %v", res, err)
	}
	commands, err := os.ReadFile(trace)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(commands), "'/data/local/tmp/resetprop' -n ro.product.model 'Pixel 3'") || strings.Contains(string(commands), "setprop ro.product.model") {
		t.Fatalf("wrong property writer: %s", commands)
	}
}

func TestADBApplyPreservesGuestFailureDiagnostic(t *testing.T) {
	// The test binary acts as a failing ADB child on Windows as well as POSIX.
	// Exercise the real subprocess path, not a mocked error formatter.
	t.Setenv("ANTIVM_ADB_HELPER", "setprop-failure")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dev := NewADBAdapter(binary, "emulator-5570")
	result, err := dev.ApplyTestConfig(context.Background(), TestConfig{
		Props: []PropSet{{Key: "ro.product.model", Value: "Pixel 8"}},
	})
	if err != nil || result.OK() || len(result.Failed) != 1 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	for _, want := range []string{"exit status 1", "Failed to set property", "See dmesg for error reason."} {
		if !strings.Contains(result.Failed[0].Err, want) {
			t.Fatalf("guest diagnostic missing %q: %s", want, result.Failed[0].Err)
		}
	}
}

func TestADBReadStateCapturesEffectiveDisplayBatteryAndArtifacts(t *testing.T) {
	t.Setenv("ANTIVM_ADB_HELPER", "state")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	st, err := NewADBAdapter(binary, "emulator-5570").ReadState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.Display["resolution"] != "1080x2160" || st.Display["density"] != "440" || st.Battery["health"] != "good" || st.Battery["plugged"] != "usb" || st.Extra["file:/dev/qemu_pipe"] != "yes" || st.Extra["file:/dev/socket/qemud"] != "no" {
		t.Fatalf("state=%+v", st)
	}
	if st.Sensors[ThermalTemperatureKey] != "28000" {
		t.Fatalf("thermal temperature was not captured: %+v", st.Sensors)
	}
}

func TestEmulatorOnlyConfigRejectsUnselectedOrPhysicalDevices(t *testing.T) {
	for _, serial := range []string{"", "physical-phone", "192.0.2.1:5555"} {
		dev := NewADBAdapter("missing-adb", serial)
		res, err := dev.ApplyTestConfig(context.Background(), TestConfig{
			EmulatorOnly: true,
			Commands:     []ShellCmd{{Cmd: "mount --bind source target"}},
		})
		if err == nil || !strings.Contains(err.Error(), "explicit emulator serial") || len(res.Succeeded) != 0 {
			t.Fatalf("serial %q reached ADB: %+v, %v", serial, res, err)
		}
	}
}

func TestADBConfigRejectsPropertyKeyAndHonorsCancellation(t *testing.T) {
	dev := NewADBAdapter("missing-adb", "emulator-5570")
	res, err := dev.ApplyTestConfig(context.Background(), TestConfig{Props: []PropSet{{Key: "ro.model; id", Value: "Pixel"}}})
	if err != nil || len(res.Failed) != 1 || !strings.Contains(res.Failed[0].Err, "invalid property key") {
		t.Fatalf("invalid property reached shell: %+v, %v", res, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err = dev.ApplyTestConfig(ctx, TestConfig{Commands: []ShellCmd{{Cmd: "wm size"}}})
	if err != context.Canceled || len(res.Failed) != 0 {
		t.Fatalf("canceled config launched commands: %+v, %v", res, err)
	}
	if quoted := quoteShell("Pixel's $(id)"); quoted != "'Pixel'\"'\"'s $(id)'" {
		t.Fatalf("unsafe value quoting: %s", quoted)
	}
}
