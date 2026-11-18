package profile

import "fmt"

// androidRelease ties together the values that must stay mutually consistent:
// API level, marketing version, and the build-ID prefix Google ships for that
// release. The validator uses this table too, so generation and validation
// agree by construction.
type androidRelease struct {
	API         int
	Version     string
	BuildPrefix string // leading token of a stock build ID, e.g. "UP1A"
}

var androidReleases = []androidRelease{
	{33, "13", "TQ3A"},
	{34, "14", "UP1A"},
	{35, "15", "AP3A"},
	{36, "16", "BP1A"},
}

// releaseByAPI returns the release row for an API level.
func releaseByAPI(api int) (androidRelease, bool) {
	if api == 28 {
		return androidRelease{28, "9", "PQ3A"}, true
	}
	for _, r := range androidReleases {
		if r.API == api {
			return r, true
		}
	}
	return androidRelease{}, false
}

// GenMode selects how a profile is produced.
type GenMode int

const (
	// ModeFixed instantiates a specific catalogue device deterministically,
	// using stable placeholder identifiers (no randomness).
	ModeFixed GenMode = iota
	// ModeSeeded produces a fully reproducible profile for a given seed.
	ModeSeeded
	// ModeRandom produces a fresh non-reproducible profile from crypto/rand.
	ModeRandom
)

// GenSpec parameterises Generate.
type GenSpec struct {
	Mode  GenMode
	Model string // required for ModeFixed; optional hint otherwise
	API   int    // desired API level; 0 means pick one
	Seed  uint64 // used only in ModeSeeded
}

// Generate builds a DeviceProfile according to spec. The result is always
// internally consistent — Validate on the output must pass.
func Generate(spec GenSpec) (DeviceProfile, error) {
	var r rng
	switch spec.Mode {
	case ModeSeeded:
		r = newSeededRNG(spec.Seed)
	case ModeRandom:
		r = cryptoRNG{}
	case ModeFixed:
		r = fixedRNG{} // deterministic, always 0
	default:
		return DeviceProfile{}, fmt.Errorf("unknown generation mode %d", spec.Mode)
	}

	// Pick the catalogue device.
	entry, ok := findCatalog(spec.Model)
	if !ok {
		if spec.Mode == ModeFixed && spec.Model != "" {
			return DeviceProfile{}, fmt.Errorf("unknown model %q for fixed mode", spec.Model)
		}
		entry = catalog[r.intn(len(catalog))]
	}

	// Pick the Android release (API level).
	rel := androidReleases[r.intn(len(androidReleases))]
	if spec.API != 0 {
		found, ok := releaseByAPI(spec.API)
		if !ok {
			return DeviceProfile{}, fmt.Errorf("unsupported API level %d", spec.API)
		}
		rel = found
	}

	buildID := fmt.Sprintf("%s.%s.%s", rel.BuildPrefix, genBuildDate(r), genDigits(r, 3))
	fingerprint := fmt.Sprintf(entry.fingerprintFmt, rel.Version+"/"+buildID, genDigits(r, 6))

	mcc, mnc, opName, opNumeric := genOperator(r)

	return DeviceProfile{
		Name:           fmt.Sprintf("%s-api-%d", entry.Device, rel.API),
		Model:          entry.Model,
		Brand:          entry.Brand,
		Manufacturer:   entry.Manufacturer,
		Device:         entry.Device,
		Product:        entry.Product,
		AndroidVersion: rel.Version,
		APILevel:       rel.API,
		ABI:            entry.ABI,
		BuildID:        buildID,
		Fingerprint:    fingerprint,
		SecurityPatch:  genSecurityPatch(r),
		Locale:         "en-US",
		Timezone:       "UTC",
		Resolution:     "1080x2400",
		Density:        420,
		Network: NetworkProfile{
			MACAddress: genMAC(r),
			WiFiSSID:   genSSID(r),
			IMEI:       genIMEI(r),
			Serial:     genSerial(r),
		},
		Battery: BatteryProfile{
			Level:       40 + r.intn(48), // 40..87
			Status:      "discharging",
			Temperature: 250 + r.intn(120), // 25.0..37.0 °C
			Health:      "good",
			Plugged:     "none",
		},
		Sensor: SensorProfile{
			Enabled:       true,
			Accelerometer: true,
			Gyroscope:     true,
		},
		Operator: OperatorProfile{
			Name:    opName,
			Numeric: opNumeric,
			MCC:     mcc,
			MNC:     mnc,
		},
	}, nil
}

// fixedRNG always returns 0, giving deterministic "first catalogue entry"
// selection for ModeFixed. Field generators still run but yield stable values.
type fixedRNG struct{}

func (fixedRNG) intn(int) int { return 0 }

func genBuildDate(r rng) string {
	// YYMMDD-ish token; day pinned to keep it valid.
	year := 24 + r.intn(3) // 24..26
	month := 1 + r.intn(12)
	return fmt.Sprintf("%02d%02d01", year, month)
}

func genSecurityPatch(r rng) string {
	year := 2024 + r.intn(3)
	month := 1 + r.intn(12)
	return fmt.Sprintf("%d-%02d-01", year, month)
}

// genOperator returns a consistent (mcc, mnc, name, numeric) tuple where
// numeric == mcc+mnc.
func genOperator(r rng) (mcc, mnc, name, numeric string) {
	type op struct{ name, mcc, mnc string }
	ops := []op{
		{"T-Mobile", "310", "260"},
		{"AT&T", "310", "410"},
		{"Verizon", "311", "480"},
		{"Vodafone", "262", "02"},
		{"Orange", "208", "01"},
		{"MegaFon", "250", "02"},
		{"MTS", "250", "01"},
		{"O2", "234", "10"},
		{"Three", "234", "20"},
		{"Telekom", "262", "01"},
	}
	o := ops[r.intn(len(ops))]
	return o.mcc, o.mnc, o.name, o.mcc + o.mnc
}
