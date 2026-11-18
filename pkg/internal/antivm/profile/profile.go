// Package profile defines the DeviceProfile — the single source of truth for
// the expected state of an Android device under test. A profile describes an
// entire device identity with internally consistent values (model ↔ device ↔
// product, android ↔ api ↔ build id, and so on). Feature modules turn a
// profile into operations, and the verifier proves that the running device
// actually matches it.
package profile

// DeviceProfile is the complete, internally consistent description of a device.
// It is the expected state: modules apply it and the verifier diffs the real
// device against it.
type DeviceProfile struct {
	Name string `json:"name"`

	// ── Identity ─────────────────────────────────────────────
	Model        string `json:"model"`
	Brand        string `json:"brand"`
	Manufacturer string `json:"manufacturer"`
	Device       string `json:"device"`
	Product      string `json:"product"`
	Hardware     string `json:"hardware,omitempty"`
	Board        string `json:"board,omitempty"`

	// ── Build ────────────────────────────────────────────────
	AndroidVersion string `json:"android_version"`
	APILevel       int    `json:"api_level"`
	ABI            string `json:"abi"`
	BuildID        string `json:"build_id"`
	Fingerprint    string `json:"fingerprint"`
	SecurityPatch  string `json:"security_patch"`

	// ── Display / environment ────────────────────────────────
	Locale     string `json:"locale"`
	Timezone   string `json:"timezone"`
	Resolution string `json:"resolution"` // e.g. "1080x2400"
	Density    int    `json:"density"`    // dpi

	// ── Sub-profiles ─────────────────────────────────────────
	Network  NetworkProfile  `json:"network"`
	Battery  BatteryProfile  `json:"battery"`
	Sensor   SensorProfile   `json:"sensor"`
	Operator OperatorProfile `json:"operator"`
}

// NetworkProfile describes the expected network identity.
type NetworkProfile struct {
	MACAddress string `json:"mac_address"`
	WiFiSSID   string `json:"wifi_ssid"`
	IMEI       string `json:"imei"`
	Serial     string `json:"serial"`
}

// BatteryProfile describes the expected battery state.
type BatteryProfile struct {
	Level       int    `json:"level"`       // percent, 0..100
	Status      string `json:"status"`      // charging|discharging|full|not-charging
	Temperature int    `json:"temperature"` // tenths of a degree C, as dumpsys reports
	Health      string `json:"health"`      // good|overheat|cold|...
	Plugged     string `json:"plugged"`     // none|ac|usb|wireless
}

// ThermalTemperatureMilliC is the fixed 28 degree C reading for analysis AVDs.
const ThermalTemperatureMilliC = 28_000

// SensorProfile describes mock sensor readings the device should expose.
// Enabled also enables the fixed thermal_zone0 temperature fixture.
type SensorProfile struct {
	Enabled               bool   `json:"enabled"`
	Accelerometer         bool   `json:"accelerometer"`
	Gyroscope             bool   `json:"gyroscope"`
	MotionSeed            uint64 `json:"motion_seed,omitempty"`
	MotionIntervalMillis  int    `json:"motion_interval_millis,omitempty"`
	MotionDurationSeconds int    `json:"motion_duration_seconds,omitempty"`
}

// OperatorProfile describes the expected mobile operator / SIM identity.
type OperatorProfile struct {
	Name    string `json:"name"`
	Numeric string `json:"numeric"` // MCC+MNC, e.g. "310260"
	MCC     string `json:"mcc"`     // 3 digits
	MNC     string `json:"mnc"`     // 2-3 digits
}

// Clone returns a deep copy of the profile. Sub-profiles are value types, so a
// shallow struct copy is already deep; this is provided for intent clarity and
// future-proofing if slices/maps are added.
func (p DeviceProfile) Clone() DeviceProfile {
	return p
}
