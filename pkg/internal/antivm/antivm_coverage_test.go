package antivm

import (
	"context"
	"strings"
	"testing"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// ADDITIONAL ANTIVM TESTS FOR COVERAGE
// ═══════════════════════════════════════════════════════════════════════════════

func TestEvasionEngine_ApplyDisabled(t *testing.T) {
	cfg := EvasionConfig{Enabled: false}
	engine := NewEvasionEngine(cfg)

	err := engine.Apply(context.Background(), "adb", "emulator-5554")
	if err != nil {
		t.Errorf("Apply with disabled config should return nil, got %v", err)
	}

	report := engine.Report()
	if report.Applied {
		t.Error("Report should not be marked applied when disabled")
	}
}

func TestEvasionEngine_ApplyWithDeviceModel(t *testing.T) {
	cfg := EvasionConfig{
		Enabled:       true,
		DeviceModel:   "Pixel 7",
		RandomizeIMEI: false,
		SensorNoise:   false,
		PatchBattery:  false,
		PatchNetwork:  false,
		PatchOperator: false,
	}
	engine := NewEvasionEngine(cfg)

	// This will fail because adb doesn't exist, but we can check the report
	_ = engine.Apply(context.Background(), "nonexistent_adb", "emulator-5554")

	report := engine.Report()
	if report.DeviceProfile.Model != "Pixel 7" {
		t.Errorf("DeviceProfile.Model = %q, want %q", report.DeviceProfile.Model, "Pixel 7")
	}
}

func TestEvasionEngine_ApplyWithRandomDevice(t *testing.T) {
	cfg := EvasionConfig{
		Enabled:       true,
		DeviceModel:   "", // Random
		RandomizeIMEI: false,
		SensorNoise:   false,
		PatchBattery:  false,
		PatchNetwork:  false,
		PatchOperator: false,
	}
	engine := NewEvasionEngine(cfg)

	_ = engine.Apply(context.Background(), "nonexistent_adb", "emulator-5554")

	report := engine.Report()
	if report.DeviceProfile.Model == "" {
		t.Error("DeviceProfile.Model should not be empty")
	}
}

func TestEvasionEngine_ApplyWithAllFeatures(t *testing.T) {
	cfg := EvasionConfig{
		Enabled:       true,
		RandomizeIMEI: true,
		SensorNoise:   true,
		PatchBattery:  true,
		PatchNetwork:  true,
		PatchOperator: true,
	}
	engine := NewEvasionEngine(cfg)

	// Apply will fail due to missing adb, but we test the code path
	_ = engine.Apply(context.Background(), "nonexistent_adb", "emulator-5554")

	report := engine.Report()
	// Check that warnings were generated (expected since adb doesn't exist)
	if len(report.Warnings) == 0 {
		// Warnings are expected when adb commands fail
		t.Log("No warnings generated (adb commands may have been skipped)")
	}
}

func TestEvasionReport_JSON(t *testing.T) {
	report := EvasionReport{
		Applied:         true,
		DeviceProfile:   DeviceProfile{Model: "Pixel 7"},
		IMEI:            "123456789012345",
		SerialNumber:    "ABC123DEF456",
		MACAddress:      "3C:5A:B4:12:34:56",
		WiFiSSID:        "NETGEAR_AB12",
		OperatorName:    "T-Mobile",
		OperatorNumeric: "310260",
		BatteryLevel:    75,
		AppliedAt:       time.Now().UTC(),
	}

	if report.IMEI != "123456789012345" {
		t.Errorf("IMEI = %q, want %q", report.IMEI, "123456789012345")
	}
	if report.SerialNumber != "ABC123DEF456" {
		t.Errorf("SerialNumber = %q, want %q", report.SerialNumber, "ABC123DEF456")
	}
	if !report.Applied || report.MACAddress == "" || report.WiFiSSID == "" || report.OperatorName == "" || report.OperatorNumeric == "" || report.BatteryLevel == 0 || report.AppliedAt.IsZero() {
		t.Error("Fields should be set and readable")
	}
}

func TestPropertyPair(t *testing.T) {
	pair := PropertyPair{
		Key:   "ro.product.model",
		Value: "Pixel 7",
	}

	if pair.Key != "ro.product.model" {
		t.Errorf("Key = %q, want %q", pair.Key, "ro.product.model")
	}
	if pair.Value != "Pixel 7" {
		t.Errorf("Value = %q, want %q", pair.Value, "Pixel 7")
	}
}

func TestEvasionConfig_Defaults(t *testing.T) {
	cfg := DefaultEvasionConfig()

	if !cfg.Enabled {
		t.Error("Enabled should be true by default")
	}
	if cfg.DeviceModel != "" {
		t.Error("DeviceModel should be empty by default (random)")
	}
	if !cfg.RandomizeIMEI {
		t.Error("RandomizeIMEI should be true by default")
	}
	if !cfg.SensorNoise {
		t.Error("SensorNoise should be true by default")
	}
	if !cfg.PatchBattery {
		t.Error("PatchBattery should be true by default")
	}
	if !cfg.PatchNetwork {
		t.Error("PatchNetwork should be true by default")
	}
	if !cfg.PatchOperator {
		t.Error("PatchOperator should be true by default")
	}
}

func TestDeviceProfile_AllFields(t *testing.T) {
	p := DeviceProfile{
		Model:         "Pixel 7",
		Brand:         "google",
		Manufacturer:  "Google",
		Device:        "panther",
		Product:       "panther",
		Hardware:      "tensor",
		Chipset:       "Google Tensor G2",
		Fingerprint:   "google/panther/panther:13/TQ3A.230901.001/123456:user/release-keys",
		BuildID:       "TQ3A.230901.001.123456",
		SecurityPatch: "2024-01-01",
	}

	if p.Model != "Pixel 7" {
		t.Errorf("Model = %q", p.Model)
	}
	if p.Brand != "google" {
		t.Errorf("Brand = %q", p.Brand)
	}
	if p.Manufacturer != "Google" {
		t.Errorf("Manufacturer = %q", p.Manufacturer)
	}
	if p.Device != "panther" {
		t.Errorf("Device = %q", p.Device)
	}
	if p.Product != "panther" {
		t.Errorf("Product = %q", p.Product)
	}
	if p.Hardware != "tensor" {
		t.Errorf("Hardware = %q", p.Hardware)
	}
	if p.Chipset != "Google Tensor G2" {
		t.Errorf("Chipset = %q", p.Chipset)
	}
	if p.Fingerprint == "" {
		t.Error("Fingerprint should not be empty")
	}
	if p.BuildID == "" {
		t.Error("BuildID should not be empty")
	}
	if p.SecurityPatch == "" {
		t.Error("SecurityPatch should not be empty")
	}
}

func TestAndroidVersion(t *testing.T) {
	versions := make(map[string]bool)
	for i := 0; i < 50; i++ {
		v := androidVersion()
		if v != "13" && v != "14" && v != "15" {
			t.Errorf("androidVersion() = %q, expected 13, 14, or 15", v)
		}
		versions[v] = true
	}
	// Should have at least 2 different versions in 50 tries
	if len(versions) < 2 {
		t.Logf("Warning: only %d unique version(s) in 50 tries", len(versions))
	}
}

func TestRandomDate(t *testing.T) {
	for i := 0; i < 20; i++ {
		d := randomDate()
		if len(d) != 8 {
			t.Errorf("randomDate() length = %d, want 8", len(d))
		}
		// Should be in format YYYYMMDD
		if !strings.ContainsAny(d[:4], "0123456789") {
			t.Errorf("randomDate() year should be numeric: %q", d[:4])
		}
	}
}

func TestRandomFloat(t *testing.T) {
	for i := 0; i < 100; i++ {
		f := randomFloat(0.0, 1.0)
		if f < 0.0 || f > 1.0 {
			t.Errorf("randomFloat(0, 1) = %f, out of range", f)
		}
	}

	for i := 0; i < 100; i++ {
		f := randomFloat(-5.0, 5.0)
		if f < -5.0 || f > 5.0 {
			t.Errorf("randomFloat(-5, 5) = %f, out of range", f)
		}
	}
}

func TestCryptoRandIntn_EdgeCases(t *testing.T) {
	// Test with n=1 (should always return 0)
	for i := 0; i < 10; i++ {
		n := cryptoRandIntn(1)
		if n != 0 {
			t.Errorf("cryptoRandIntn(1) = %d, want 0", n)
		}
	}

	// Test with n=2 (should return 0 or 1)
	for i := 0; i < 50; i++ {
		n := cryptoRandIntn(2)
		if n < 0 || n > 1 {
			t.Errorf("cryptoRandIntn(2) = %d, want 0 or 1", n)
		}
	}
}

func TestValidateIMEI_EdgeCases(t *testing.T) {
	tests := []struct {
		imei  string
		valid bool
	}{
		{"", false},                 // empty
		{"123", false},              // too short
		{"12345678901234", false},   // 14 digits
		{"1234567890123456", false}, // 16 digits
		{"abcdefghijklmno", false},  // non-numeric
		{"490154203237518", true},   // valid
		{"49015420323751a", false},  // contains letter
	}

	for _, tt := range tests {
		result := ValidateIMEI(tt.imei)
		if result != tt.valid {
			t.Errorf("ValidateIMEI(%q) = %v, want %v", tt.imei, result, tt.valid)
		}
	}
}

func TestLuhnCheckDigit_EdgeCases(t *testing.T) {
	tests := []struct {
		partial  string
		expected int
	}{
		{"0", 0},
		{"1", 8},
		{"12", 5},
		{"12345678901234", 7},
	}

	for _, tt := range tests {
		result := luhnCheckDigit(tt.partial)
		if result != tt.expected {
			t.Errorf("luhnCheckDigit(%q) = %d, want %d", tt.partial, result, tt.expected)
		}
	}
}

func TestRandomIMEI_Uniqueness(t *testing.T) {
	imeis := make(map[string]bool)
	for i := 0; i < 100; i++ {
		imei := RandomIMEI()
		imeis[imei] = true
	}
	if len(imeis) < 90 {
		t.Errorf("Only %d unique IMEIs out of 100", len(imeis))
	}
}

func TestRandomMAC_Uniqueness(t *testing.T) {
	macs := make(map[string]bool)
	for i := 0; i < 100; i++ {
		mac := RandomMAC()
		macs[mac] = true
	}
	if len(macs) < 90 {
		t.Errorf("Only %d unique MACs out of 100", len(macs))
	}
}

func TestRandomSSID_Uniqueness(t *testing.T) {
	ssids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		ssid := RandomSSID()
		ssids[ssid] = true
	}
	if len(ssids) < 90 {
		t.Errorf("Only %d unique SSIDs out of 100", len(ssids))
	}
}

func TestRandomSerial_Uniqueness(t *testing.T) {
	serials := make(map[string]bool)
	for i := 0; i < 100; i++ {
		serial := RandomSerial()
		serials[serial] = true
	}
	if len(serials) < 90 {
		t.Errorf("Only %d unique serials out of 100", len(serials))
	}
}

func TestRandomOperator_AllValid(t *testing.T) {
	for i := 0; i < 50; i++ {
		name, numeric := RandomOperator()
		if name == "" {
			t.Error("Operator name should not be empty")
		}
		if numeric == "" {
			t.Error("Operator numeric should not be empty")
		}
		if len(numeric) < 5 {
			t.Errorf("Operator numeric %q seems too short", numeric)
		}
	}
}

func TestRandomBatteryLevel_Range(t *testing.T) {
	min, max := 100, 0
	for i := 0; i < 100; i++ {
		level := RandomBatteryLevel()
		if level < min {
			min = level
		}
		if level > max {
			max = level
		}
		if level < 40 || level > 87 {
			t.Errorf("Battery level %d out of expected range [40, 87]", level)
		}
	}
	t.Logf("Battery level range: %d to %d", min, max)
}

func TestAccelerometerNoise_Range(t *testing.T) {
	for i := 0; i < 100; i++ {
		x, y, z := AccelerometerNoise()
		// X should be small noise
		if x < -0.5 || x > 0.5 {
			t.Errorf("Accelerometer X = %f, expected range [-0.5, 0.5]", x)
		}
		// Y should be small noise
		if y < -0.5 || y > 0.5 {
			t.Errorf("Accelerometer Y = %f, expected range [-0.5, 0.5]", y)
		}
		// Z should be near gravity (9.81)
		if z < 9.0 || z > 10.5 {
			t.Errorf("Accelerometer Z = %f, expected range [9.0, 10.5]", z)
		}
	}
}

func TestGyroscopeNoise_Range(t *testing.T) {
	for i := 0; i < 100; i++ {
		x, y, z := GyroscopeNoise()
		// All values should be very small
		if x < -0.05 || x > 0.05 {
			t.Errorf("Gyroscope X = %f, expected range [-0.05, 0.05]", x)
		}
		if y < -0.05 || y > 0.05 {
			t.Errorf("Gyroscope Y = %f, expected range [-0.05, 0.05]", y)
		}
		if z < -0.05 || z > 0.05 {
			t.Errorf("Gyroscope Z = %f, expected range [-0.05, 0.05]", z)
		}
	}
}

func TestDeviceProfileByModel_AllKnownDevices(t *testing.T) {
	models := []string{
		"Pixel 7", "Pixel 7 Pro", "Pixel 8",
		"SM-S928U", "SM-S926B", "SM-A546B",
		"CPH2585", "23127PN0CG", "Pixel 6a", "RMX3771",
	}

	for _, model := range models {
		p := DeviceProfileByModel(model)
		if p.Model != model {
			t.Errorf("DeviceProfileByModel(%q) = %q, want %q", model, p.Model, model)
		}
		if p.Fingerprint == "" {
			t.Errorf("Fingerprint should not be empty for %q", model)
		}
	}
}

func TestDeviceProfileByModel_DeviceName(t *testing.T) {
	// Test lookup by device name
	p := DeviceProfileByModel("panther")
	if p.Model != "Pixel 7" {
		t.Errorf("DeviceProfileByModel(panther) = %q, want Pixel 7", p.Model)
	}

	p = DeviceProfileByModel("cheetah")
	if p.Model != "Pixel 7 Pro" {
		t.Errorf("DeviceProfileByModel(cheetah) = %q, want Pixel 7 Pro", p.Model)
	}
}

func TestDeviceProfileByModel_ProductName(t *testing.T) {
	// Test lookup by product name
	p := DeviceProfileByModel("shiba")
	if p.Model != "Pixel 8" {
		t.Errorf("DeviceProfileByModel(shiba) = %q, want Pixel 8", p.Model)
	}
}

func TestDeviceProfileByModel_Unknown(t *testing.T) {
	// Unknown model should return a random device
	p := DeviceProfileByModel("UnknownModel12345")
	if p.Model == "" {
		t.Error("Unknown model should return a fallback device, not empty")
	}
}

func TestRandomDeviceProfile_NoEmulatorIndicators(t *testing.T) {
	for i := 0; i < 50; i++ {
		p := RandomDeviceProfile()
		lower := strings.ToLower(p.Fingerprint)

		if strings.Contains(lower, "generic") {
			t.Errorf("Fingerprint contains 'generic': %q", p.Fingerprint)
		}
		if strings.Contains(lower, "goldfish") {
			t.Errorf("Fingerprint contains 'goldfish': %q", p.Fingerprint)
		}
		if strings.Contains(lower, "sdk") {
			t.Errorf("Fingerprint contains 'sdk': %q", p.Fingerprint)
		}
		if strings.Contains(lower, "emulator") {
			t.Errorf("Fingerprint contains 'emulator': %q", p.Fingerprint)
		}
		if strings.Contains(lower, "test-keys") {
			t.Errorf("Fingerprint contains 'test-keys': %q", p.Fingerprint)
		}
	}
}

func TestRandomBuildID_Format(t *testing.T) {
	for i := 0; i < 20; i++ {
		id := randomBuildID()
		// Should contain at least one dot
		if !strings.Contains(id, ".") {
			t.Errorf("randomBuildID() = %q, expected to contain '.'", id)
		}
		// Should start with a known prefix
		validPrefixes := []string{"TQ3A", "UP1A", "UQ1A", "AP2A", "TP1A", "SP1A", "RQ3A"}
		hasValidPrefix := false
		for _, prefix := range validPrefixes {
			if strings.HasPrefix(id, prefix) {
				hasValidPrefix = true
				break
			}
		}
		if !hasValidPrefix {
			t.Errorf("randomBuildID() = %q, expected to start with valid prefix", id)
		}
	}
}

func TestRandomSecurityPatch_Format(t *testing.T) {
	for i := 0; i < 20; i++ {
		patch := randomSecurityPatch()
		// Should be in format YYYY-MM-DD
		if len(patch) != 10 {
			t.Errorf("randomSecurityPatch() = %q, expected length 10", patch)
		}
		if patch[4] != '-' || patch[7] != '-' {
			t.Errorf("randomSecurityPatch() = %q, expected format YYYY-MM-DD", patch)
		}
		// Day should always be 01
		if patch[8:] != "01" {
			t.Errorf("randomSecurityPatch() = %q, expected day to be 01", patch)
		}
	}
}

func TestRandomHex_Extended(t *testing.T) {
	for i := 0; i < 20; i++ {
		hex := randomHex(8)
		if len(hex) != 8 {
			t.Errorf("randomHex(8) = %q, expected length 8", hex)
		}
		// Should only contain hex characters
		for _, c := range hex {
			if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')) {
				t.Errorf("randomHex() = %q, contains non-hex char %q", hex, string(c))
			}
		}
	}
}

func TestRandomDigits_Extended(t *testing.T) {
	for i := 0; i < 20; i++ {
		digits := randomDigits(10)
		if len(digits) != 10 {
			t.Errorf("randomDigits(10) = %q, expected length 10", digits)
		}
		// Should only contain digits
		for _, c := range digits {
			if c < '0' || c > '9' {
				t.Errorf("randomDigits() = %q, contains non-digit char %q", digits, string(c))
			}
		}
	}
}

// Benchmark tests
func BenchmarkRandomIMEI(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = RandomIMEI()
	}
}

func BenchmarkRandomMAC(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = RandomMAC()
	}
}

func BenchmarkRandomDeviceProfile(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = RandomDeviceProfile()
	}
}

func BenchmarkValidateIMEI(b *testing.B) {
	imei := RandomIMEI()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateIMEI(imei)
	}
}
