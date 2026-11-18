package antivm

import (
	"strings"
	"testing"
)

// ── IMEI Tests ───────────────────────────────────────────────

func TestRandomIMEI(t *testing.T) {
	for i := 0; i < 100; i++ {
		imei := RandomIMEI()
		if len(imei) != 15 {
			t.Fatalf("IMEI length = %d, want 15: %q", len(imei), imei)
		}
		if !ValidateIMEI(imei) {
			t.Fatalf("generated IMEI failed Luhn validation: %q", imei)
		}
	}
}

func TestValidateIMEI(t *testing.T) {
	tests := []struct {
		imei  string
		valid bool
	}{
		{"490154203237518", true},  // known valid
		{"490154203237510", false}, // wrong check digit (should be 8)
		{"12345", false},           // too short
		{"abcdefghijklmno", false},
	}
	for _, tt := range tests {
		got := ValidateIMEI(tt.imei)
		if got != tt.valid {
			t.Errorf("ValidateIMEI(%q) = %v, want %v", tt.imei, got, tt.valid)
		}
	}
}

func TestLuhnCheckDigit(t *testing.T) {
	// Known valid: 490154203237518, check digit is 8.
	partial := "49015420323751"
	cd := luhnCheckDigit(partial)
	if cd != 8 {
		t.Errorf("luhnCheckDigit(%q) = %d, want 8", partial, cd)
	}
}

// ── Serial Number Tests ──────────────────────────────────────

func TestRandomSerial(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 50; i++ {
		s := RandomSerial()
		if len(s) < 8 || len(s) > 12 {
			t.Errorf("serial length %d out of range [8,12]: %q", len(s), s)
		}
		// All hex uppercase.
		for _, r := range s {
			if !((r >= '0' && r <= '9') || (r >= 'A' && r <= 'F')) {
				t.Errorf("serial contains non-hex char: %q in %q", string(r), s)
			}
		}
		seen[s] = true
	}
	if len(seen) < 40 {
		t.Errorf("low uniqueness: only %d unique serials out of 50", len(seen))
	}
}

// ── MAC Address Tests ────────────────────────────────────────

func TestRandomMAC(t *testing.T) {
	for i := 0; i < 50; i++ {
		mac := RandomMAC()
		parts := strings.Split(mac, ":")
		if len(parts) != 6 {
			t.Fatalf("MAC has %d octets, want 6: %q", len(parts), mac)
		}
		for _, part := range parts {
			if len(part) != 2 {
				t.Errorf("MAC octet length = %d, want 2: %q", len(part), part)
			}
		}
	}
}

// ── Device Profile Tests ─────────────────────────────────────

func TestRandomDeviceProfile(t *testing.T) {
	for i := 0; i < 20; i++ {
		p := RandomDeviceProfile()
		if p.Model == "" {
			t.Fatal("empty model")
		}
		if p.Hardware == "" {
			t.Fatal("empty hardware")
		}
		if p.Fingerprint == "" {
			t.Fatal("empty fingerprint")
		}
		// Fingerprint should not contain "generic" or "goldfish".
		lower := strings.ToLower(p.Fingerprint)
		if strings.Contains(lower, "generic") {
			t.Errorf("fingerprint contains 'generic': %q", p.Fingerprint)
		}
		if strings.Contains(lower, "goldfish") {
			t.Errorf("fingerprint contains 'goldfish': %q", p.Fingerprint)
		}
		if strings.Contains(lower, "sdk") {
			t.Errorf("fingerprint contains 'sdk': %q", p.Fingerprint)
		}
	}
}

func TestDeviceProfileByModel(t *testing.T) {
	// Known model.
	p := DeviceProfileByModel("Pixel 7")
	if p.Model != "Pixel 7" {
		t.Errorf("expected Pixel 7, got %q", p.Model)
	}
	if p.Device != "panther" {
		t.Errorf("expected panther device, got %q", p.Device)
	}

	// Case insensitive.
	p2 := DeviceProfileByModel("pixel 8")
	if p2.Model != "Pixel 8" {
		t.Errorf("expected Pixel 8, got %q", p2.Model)
	}

	// Unknown model → random fallback.
	p3 := DeviceProfileByModel("UnknownModel123")
	if p3.Model == "" {
		t.Fatal("fallback should return a non-empty model")
	}
}

// ── WiFi SSID Tests ──────────────────────────────────────────

func TestRandomSSID(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 30; i++ {
		ssid := RandomSSID()
		if ssid == "" {
			t.Fatal("empty SSID")
		}
		seen[ssid] = true
	}
	if len(seen) < 20 {
		t.Errorf("low SSID uniqueness: %d/30", len(seen))
	}
}

// ── Operator Tests ───────────────────────────────────────────

func TestRandomOperator(t *testing.T) {
	name, numeric := RandomOperator()
	if name == "" {
		t.Fatal("empty operator name")
	}
	if numeric == "" {
		t.Fatal("empty operator numeric")
	}
}

// ── Battery Tests ────────────────────────────────────────────

func TestRandomBatteryLevel(t *testing.T) {
	for i := 0; i < 100; i++ {
		level := RandomBatteryLevel()
		if level < 40 || level > 87 {
			t.Errorf("battery level %d out of range [40, 87]", level)
		}
	}
}

// ── Sensor Noise Tests ───────────────────────────────────────

func TestAccelerometerNoise(t *testing.T) {
	for i := 0; i < 50; i++ {
		x, y, z := AccelerometerNoise()
		if x < -0.5 || x > 0.5 {
			t.Errorf("accel X = %f, out of expected range", x)
		}
		if y < -0.5 || y > 0.5 {
			t.Errorf("accel Y = %f, out of expected range", y)
		}
		if z < 9.0 || z > 10.5 {
			t.Errorf("accel Z = %f, should be near 9.81", z)
		}
	}
}

func TestGyroscopeNoise(t *testing.T) {
	for i := 0; i < 50; i++ {
		x, y, z := GyroscopeNoise()
		if x < -0.05 || x > 0.05 {
			t.Errorf("gyro X = %f, out of expected range", x)
		}
		if y < -0.05 || y > 0.05 {
			t.Errorf("gyro Y = %f, out of expected range", y)
		}
		if z < -0.05 || z > 0.05 {
			t.Errorf("gyro Z = %f, out of expected range", z)
		}
	}
}

// ── Evasion Config Tests ─────────────────────────────────────

func TestDefaultEvasionConfig(t *testing.T) {
	cfg := DefaultEvasionConfig()
	if !cfg.Enabled {
		t.Error("default config should be enabled")
	}
	if !cfg.RandomizeIMEI {
		t.Error("default config should randomize IMEI")
	}
	if !cfg.SensorNoise {
		t.Error("default config should enable sensor noise")
	}
	if !cfg.PatchBattery {
		t.Error("default config should patch battery")
	}
	if !cfg.PatchNetwork {
		t.Error("default config should patch network")
	}
	if !cfg.PatchOperator {
		t.Error("default config should patch operator")
	}
}

func TestEvasionEngineReport(t *testing.T) {
	engine := NewEvasionEngine(EvasionConfig{Enabled: false})
	r := engine.Report()
	if r.Applied {
		t.Error("report should not be marked applied when disabled")
	}
}

// ── Helper Tests ─────────────────────────────────────────────

func TestCryptoRandIntn(t *testing.T) {
	seen := make(map[int]bool)
	for i := 0; i < 100; i++ {
		n := cryptoRandIntn(100)
		if n < 0 || n >= 100 {
			t.Errorf("cryptoRandIntn(100) = %d, out of range", n)
		}
		seen[n] = true
	}
	if len(seen) < 30 {
		t.Errorf("low randomness: only %d unique values in 100 calls", len(seen))
	}
}

func TestCryptoRandIntnZero(t *testing.T) {
	n := cryptoRandIntn(0)
	if n != 0 {
		t.Errorf("cryptoRandIntn(0) = %d, want 0", n)
	}
}

func TestRandomBuildID(t *testing.T) {
	id := randomBuildID()
	if !strings.Contains(id, ".") {
		t.Errorf("invalid build ID format: %q", id)
	}
}

func TestRandomSecurityPatch(t *testing.T) {
	patch := randomSecurityPatch()
	if len(patch) != 10 { // YYYY-MM-DD
		t.Errorf("invalid security patch format: %q", patch)
	}
}

func TestRandomHex(t *testing.T) {
	hex := randomHex(8)
	if len(hex) != 8 {
		t.Errorf("randomHex(8) length = %d, want 8", len(hex))
	}
}

func TestRandomDigits(t *testing.T) {
	digits := randomDigits(10)
	if len(digits) != 10 {
		t.Errorf("randomDigits(10) length = %d, want 10", len(digits))
	}
	for _, r := range digits {
		if r < '0' || r > '9' {
			t.Errorf("randomDigits contains non-digit: %q", string(r))
		}
	}
}

func TestAllKnownDevices(t *testing.T) {
	for _, tmpl := range knownDevices {
		t.Run(tmpl.Model, func(t *testing.T) {
			p := DeviceProfileByModel(tmpl.Model)
			if p.Model != tmpl.Model {
				t.Errorf("Expected model %s, got %s", tmpl.Model, p.Model)
			}
			if p.Fingerprint == "" {
				t.Error("Fingerprint is empty")
			}
			// Test by device name too
			p2 := DeviceProfileByModel(tmpl.Device)
			if p2.Model != tmpl.Model {
				t.Errorf("Expected model %s when searching by device %s, got %s", tmpl.Model, tmpl.Device, p2.Model)
			}
		})
	}
}

func TestRandomDeviceProfile_Variety(t *testing.T) {
	models := make(map[string]bool)
	for i := 0; i < 50; i++ {
		p := RandomDeviceProfile()
		models[p.Model] = true
	}
	if len(models) < 2 {
		t.Error("RandomDeviceProfile doesn't seem to provide enough variety")
	}
}
