package sandbox

import (
	"testing"
)

// ─── androidHostIP helper ──────────────────────────────────────────────────

func TestAndroidHostIP_EmulatorDevice(t *testing.T) {
	ip := androidHostIP("adb", "emulator-5554")
	if ip != "10.0.2.2" {
		t.Errorf("expected emulator IP 10.0.2.2, got %q", ip)
	}
}

func TestAndroidHostIP_EmulatorDevice_Different(t *testing.T) {
	ip := androidHostIP("adb", "emulator-5556")
	if ip != "10.0.2.2" {
		t.Errorf("expected emulator IP 10.0.2.2, got %q", ip)
	}
}

func TestAndroidHostIP_NonEmulator(t *testing.T) {
	// Physical device - will try to get actual host IP
	// Could return empty string if no interfaces available, or an actual IP
	ip := androidHostIP("adb", "device123")
	// Just check it doesn't crash and returns string (may be empty or valid IP)
	_ = ip
}

func TestAndroidHostIP_EmptyDeviceID(t *testing.T) {
	// Should not be treated as emulator
	ip := androidHostIP("adb", "")
	// Will try to find host IP, could be empty or valid
	_ = ip
}
