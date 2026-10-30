// Package antivm provides device fingerprint generation for Android emulator
// anti-detection. It produces realistic build properties, IMEI numbers,
// serial numbers, and MAC addresses that defeat common VM-detection checks
// used by malware.
package antivm

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// DeviceProfile holds a complete realistic device identity.
type DeviceProfile struct {
	Model         string `json:"model"`
	Brand         string `json:"brand"`
	Manufacturer  string `json:"manufacturer"`
	Device        string `json:"device"`
	Product       string `json:"product"`
	Hardware      string `json:"hardware"`
	Chipset       string `json:"chipset"`
	Fingerprint   string `json:"fingerprint"`
	BuildID       string `json:"build_id"`
	SecurityPatch string `json:"security_patch"`
}

// deviceTemplate is one known real device spec.
type deviceTemplate struct {
	Model         string
	Brand         string
	Manufacturer  string
	Device        string
	Product       string
	Hardware      string
	Chipset       string
	FingerprintFn func(buildID string) string
}

var knownDevices = []deviceTemplate{
	{
		Model: "Pixel 7", Brand: "google", Manufacturer: "Google",
		Device: "panther", Product: "panther", Hardware: "tensor",
		Chipset: "Google Tensor G2",
		FingerprintFn: func(id string) string {
			return fmt.Sprintf("google/panther/panther:%s/TQ3A.230901.001/%s:user/release-keys", androidVersion(), id)
		},
	},
	{
		Model: "Pixel 7 Pro", Brand: "google", Manufacturer: "Google",
		Device: "cheetah", Product: "cheetah", Hardware: "tensor",
		Chipset: "Google Tensor G2",
		FingerprintFn: func(id string) string {
			return fmt.Sprintf("google/cheetah/cheetah:%s/TQ3A.230901.001/%s:user/release-keys", androidVersion(), id)
		},
	},
	{
		Model: "Pixel 8", Brand: "google", Manufacturer: "Google",
		Device: "shiba", Product: "shiba", Hardware: "tensor",
		Chipset: "Google Tensor G3",
		FingerprintFn: func(id string) string {
			return fmt.Sprintf("google/shiba/shiba:%s/UQ1A.240205.002/%s:user/release-keys", androidVersion(), id)
		},
	},
	{
		Model: "SM-S928U", Brand: "samsung", Manufacturer: "samsung",
		Device: "e3q", Product: "e3qsqx", Hardware: "qcom",
		Chipset: "Qualcomm SM8650",
		FingerprintFn: func(id string) string {
			return fmt.Sprintf("samsung/e3qsqx/e3q:%s/UP1A.231005.007/%s:user/release-keys", androidVersion(), id)
		},
	},
	{
		Model: "SM-S926B", Brand: "samsung", Manufacturer: "samsung",
		Device: "e2s", Product: "e2sxxx", Hardware: "samsungexynos2400",
		Chipset: "Samsung Exynos 2400",
		FingerprintFn: func(id string) string {
			return fmt.Sprintf("samsung/e2sxxx/e2s:%s/UP1A.231005.007/%s:user/release-keys", androidVersion(), id)
		},
	},
	{
		Model: "SM-A546B", Brand: "samsung", Manufacturer: "samsung",
		Device: "a54x", Product: "a54xnsxx", Hardware: "samsungexynos1380",
		Chipset: "Samsung Exynos 1380",
		FingerprintFn: func(id string) string {
			return fmt.Sprintf("samsung/a54xnsxx/a54x:%s/UP1A.231005.007/%s:user/release-keys", androidVersion(), id)
		},
	},
	{
		Model: "CPH2585", Brand: "OnePlus", Manufacturer: "OnePlus",
		Device: "OP5913L1", Product: "CPH2585", Hardware: "qcom",
		Chipset: "Qualcomm SM8650",
		FingerprintFn: func(id string) string {
			return fmt.Sprintf("OnePlus/CPH2585/OP5913L1:%s/UP1A.231005.007/%s:user/release-keys", androidVersion(), id)
		},
	},
	{
		Model: "23127PN0CG", Brand: "Xiaomi", Manufacturer: "Xiaomi",
		Device: "shennong", Product: "shennong", Hardware: "qcom",
		Chipset: "Qualcomm SM8650-AC",
		FingerprintFn: func(id string) string {
			return fmt.Sprintf("Xiaomi/shennong/shennong:%s/UKQ1.230917.001/%s:user/release-keys", androidVersion(), id)
		},
	},
	{
		Model: "Pixel 6a", Brand: "google", Manufacturer: "Google",
		Device: "bluejay", Product: "bluejay", Hardware: "tensor",
		Chipset: "Google Tensor",
		FingerprintFn: func(id string) string {
			return fmt.Sprintf("google/bluejay/bluejay:%s/TQ3A.230901.001/%s:user/release-keys", androidVersion(), id)
		},
	},
	{
		Model: "RMX3771", Brand: "realme", Manufacturer: "realme",
		Device: "RE58B2L1", Product: "RMX3771", Hardware: "mt6893",
		Chipset: "MediaTek Dimensity 1080",
		FingerprintFn: func(id string) string {
			return fmt.Sprintf("realme/RMX3771/RE58B2L1:%s/TP1A.220905.001/%s:user/release-keys", androidVersion(), id)
		},
	},
}

func androidVersion() string {
	versions := []string{"13", "14", "15"}
	return versions[cryptoRandIntn(len(versions))]
}

// RandomDeviceProfile picks a random real device and generates
// unique identifiers for it.
func RandomDeviceProfile() DeviceProfile {
	tmpl := knownDevices[cryptoRandIntn(len(knownDevices))]
	buildID := randomBuildID()
	return DeviceProfile{
		Model:         tmpl.Model,
		Brand:         tmpl.Brand,
		Manufacturer:  tmpl.Manufacturer,
		Device:        tmpl.Device,
		Product:       tmpl.Product,
		Hardware:      tmpl.Hardware,
		Chipset:       tmpl.Chipset,
		Fingerprint:   tmpl.FingerprintFn(buildID),
		BuildID:       buildID,
		SecurityPatch: randomSecurityPatch(),
	}
}

// DeviceProfileByModel returns a profile for a specific model, or random
// if not found.
func DeviceProfileByModel(model string) DeviceProfile {
	lower := strings.ToLower(model)
	for _, tmpl := range knownDevices {
		if strings.ToLower(tmpl.Model) == lower ||
			strings.ToLower(tmpl.Device) == lower ||
			strings.ToLower(tmpl.Product) == lower {
			buildID := randomBuildID()
			return DeviceProfile{
				Model:         tmpl.Model,
				Brand:         tmpl.Brand,
				Manufacturer:  tmpl.Manufacturer,
				Device:        tmpl.Device,
				Product:       tmpl.Product,
				Hardware:      tmpl.Hardware,
				Chipset:       tmpl.Chipset,
				Fingerprint:   tmpl.FingerprintFn(buildID),
				BuildID:       buildID,
				SecurityPatch: randomSecurityPatch(),
			}
		}
	}
	return RandomDeviceProfile()
}

// ── IMEI Generation ──────────────────────────────────────────

// RandomIMEI generates a valid 15-digit IMEI with correct Luhn check digit.
// Uses real TAC (Type Allocation Code) prefixes from known manufacturers.
func RandomIMEI() string {
	tacs := []string{
		"35332510", // Samsung
		"35391610", // Samsung
		"35465206", // Google Pixel
		"35425208", // Google Pixel
		"86749604", // OnePlus
		"86388103", // Xiaomi
		"35850010", // Huawei
		"01154400", // Apple (used for camouflage)
		"35976009", // Motorola
		"35260910", // LG
	}
	tac := tacs[cryptoRandIntn(len(tacs))]

	// Generate 6 random digits for serial.
	serial := randomDigits(6)

	// 14 digits so far.
	partial := tac + serial

	// Calculate Luhn check digit.
	checkDigit := luhnCheckDigit(partial)
	return partial + fmt.Sprintf("%d", checkDigit)
}

// luhnCheckDigit calculates the check digit for a partial number.
func luhnCheckDigit(partial string) int {
	sum := 0
	nDigits := len(partial)
	parity := (nDigits + 1) % 2

	for i := 0; i < nDigits; i++ {
		digit := int(partial[i] - '0')
		if i%2 == parity {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}
		sum += digit
	}
	return (10 - (sum % 10)) % 10
}

// ValidateIMEI checks that an IMEI has a valid Luhn check digit.
func ValidateIMEI(imei string) bool {
	if len(imei) != 15 {
		return false
	}
	for _, r := range imei {
		if r < '0' || r > '9' {
			return false
		}
	}
	partial := imei[:14]
	expected := luhnCheckDigit(partial)
	actual := int(imei[14] - '0')
	return expected == actual
}

// ── Serial Number Generation ─────────────────────────────────

// RandomSerial generates a realistic Android device serial number.
func RandomSerial() string {
	// Format: 8-12 hex characters, uppercase.
	length := 8 + cryptoRandIntn(5) // 8..12
	const hexChars = "0123456789ABCDEF"
	b := make([]byte, length)
	for i := range b {
		b[i] = hexChars[cryptoRandIntn(len(hexChars))]
	}
	return string(b)
}

// ── MAC Address Generation ───────────────────────────────────

// RandomMAC generates a realistic unicast MAC address with a real OUI
// from known Android device manufacturers.
func RandomMAC() string {
	ouis := []string{
		"3C:5A:B4", // Google
		"F4:F5:D8", // Google
		"A4:77:33", // Google
		"00:1A:11", // Google Chromecast/devices
		"F8:E4:E3", // Samsung
		"C0:BD:D1", // Samsung
		"94:35:0A", // Samsung
		"38:01:46", // OnePlus
		"C0:EE:FB", // OnePlus
		"94:65:2D", // OnePlus
		"DC:D9:AE", // Xiaomi
		"64:CC:2E", // Xiaomi
		"28:6C:07", // Xiaomi
	}
	oui := ouis[cryptoRandIntn(len(ouis))]

	// Generate 3 random octets for NIC.
	nic := fmt.Sprintf("%02X:%02X:%02X",
		cryptoRandIntn(256),
		cryptoRandIntn(256),
		cryptoRandIntn(256),
	)
	return oui + ":" + nic
}

// ── WiFi SSID Generation ─────────────────────────────────────

// RandomSSID generates a realistic home WiFi SSID.
func RandomSSID() string {
	prefixes := []string{
		"NETGEAR", "TP-Link", "ASUS", "Linksys", "HUAWEI", "Dlink",
		"Rostelecom", "Beeline", "MTS", "Tele2", "Megafon",
		"HOME", "MyWiFi", "FamilyNet", "Keenetic",
	}
	suffixes := []string{
		"_5G", "-5G", "_2.4G", "", "",
	}
	prefix := prefixes[cryptoRandIntn(len(prefixes))]
	suffix := suffixes[cryptoRandIntn(len(suffixes))]

	// Add hex identifier.
	hexID := fmt.Sprintf("_%s", randomHex(4))
	return prefix + hexID + suffix
}

// ── Operator Names ───────────────────────────────────────────

// RandomOperator returns a realistic mobile operator name.
func RandomOperator() (name, numeric string) {
	type op struct {
		name    string
		numeric string
	}
	operators := []op{
		{"T-Mobile", "310260"},
		{"AT&T", "310410"},
		{"Verizon", "311480"},
		{"Vodafone", "26202"},
		{"Orange", "20801"},
		{"MegaFon", "25002"},
		{"MTS", "25001"},
		{"Beeline", "25099"},
		{"Tele2", "25020"},
		{"O2", "23410"},
		{"Three", "23420"},
		{"Telekom", "26201"},
	}
	o := operators[cryptoRandIntn(len(operators))]
	return o.name, o.numeric
}

// ── Battery ──────────────────────────────────────────────────

// RandomBatteryLevel returns a realistic battery level (40-87%).
func RandomBatteryLevel() int {
	return 40 + cryptoRandIntn(48) // 40..87
}

// ── Sensor Noise ─────────────────────────────────────────────

// AccelerometerNoise generates realistic accelerometer readings.
// Real devices show gravity (~9.81 m/s²) plus noise on all axes.
func AccelerometerNoise() (x, y, z float64) {
	// Phone face-up on a table: mostly gravity on Z.
	x = randomFloat(-0.3, 0.3)
	y = randomFloat(-0.2, 0.2)
	z = 9.81 + randomFloat(-0.15, 0.15)
	return
}

// GyroscopeNoise generates realistic gyroscope micro-vibrations.
func GyroscopeNoise() (x, y, z float64) {
	x = randomFloat(-0.02, 0.02)
	y = randomFloat(-0.02, 0.02)
	z = randomFloat(-0.01, 0.01)
	return
}

// ── Helpers ──────────────────────────────────────────────────

func randomBuildID() string {
	prefixes := []string{"TQ3A", "UP1A", "UQ1A", "AP2A", "TP1A", "SP1A", "RQ3A"}
	p := prefixes[cryptoRandIntn(len(prefixes))]
	suffix := randomDigits(6)
	return fmt.Sprintf("%s.%s.%s", p, randomDate(), suffix)
}

func randomDate() string {
	year := 2024 + cryptoRandIntn(2)
	month := 1 + cryptoRandIntn(12)
	day := 1 + cryptoRandIntn(28)
	return fmt.Sprintf("%d%02d%02d", year, month, day)
}

func randomSecurityPatch() string {
	year := 2024 + cryptoRandIntn(2)
	month := 1 + cryptoRandIntn(12)
	return fmt.Sprintf("%d-%02d-01", year, month)
}

func randomDigits(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte('0' + cryptoRandIntn(10))
	}
	return string(b)
}

func randomHex(n int) string {
	const hexChars = "0123456789ABCDEF"
	b := make([]byte, n)
	for i := range b {
		b[i] = hexChars[cryptoRandIntn(len(hexChars))]
	}
	return string(b)
}

func randomFloat(min, max float64) float64 {
	n, _ := rand.Int(rand.Reader, big.NewInt(10000))
	ratio := float64(n.Int64()) / 10000.0
	return min + ratio*(max-min)
}

func cryptoRandIntn(n int) int {
	if n <= 0 {
		return 0
	}
	max := big.NewInt(int64(n))
	val, err := rand.Int(rand.Reader, max)
	if err != nil {
		// Fallback: use current nano time.
		return int(time.Now().UnixNano() % int64(n))
	}
	return int(val.Int64())
}
