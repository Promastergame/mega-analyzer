package profile

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ValidationError is a single consistency failure. Field names the offending
// profile field; Detail explains the inconsistency.
type ValidationError struct {
	Field  string
	Detail string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Detail)
}

// ValidationResult aggregates all problems found in one pass so the caller sees
// every inconsistency at once, not just the first.
type ValidationResult struct {
	Errors []ValidationError
}

// OK reports whether the profile passed validation.
func (r ValidationResult) OK() bool { return len(r.Errors) == 0 }

// Err returns a single joined error, or nil if valid.
func (r ValidationResult) Err() error {
	if r.OK() {
		return nil
	}
	msgs := make([]error, len(r.Errors))
	for i, e := range r.Errors {
		msgs[i] = e
	}
	return errors.Join(msgs...)
}

var (
	reResolution = regexp.MustCompile(`^\d{3,4}x\d{3,4}$`)
	reSecPatch   = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	reMAC        = regexp.MustCompile(`^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$`)
)

// Normalize canonicalises formatting (trimming, MAC/locale casing) without
// changing semantics. It is idempotent and should be run before Validate.
func Normalize(p *DeviceProfile) {
	p.Name = strings.TrimSpace(p.Name)
	p.Model = strings.TrimSpace(p.Model)
	p.Brand = strings.TrimSpace(p.Brand)
	p.Device = strings.TrimSpace(p.Device)
	p.Product = strings.TrimSpace(p.Product)
	p.AndroidVersion = strings.TrimSpace(p.AndroidVersion)
	p.Network.MACAddress = strings.ToUpper(strings.TrimSpace(p.Network.MACAddress))
	p.Battery.Status = strings.ToLower(strings.TrimSpace(p.Battery.Status))
	p.Battery.Plugged = strings.ToLower(strings.TrimSpace(p.Battery.Plugged))
	p.Operator.Numeric = strings.TrimSpace(p.Operator.Numeric)
	p.Operator.MCC = strings.TrimSpace(p.Operator.MCC)
	p.Operator.MNC = strings.TrimSpace(p.Operator.MNC)
}

// Validate checks that every field group is internally consistent. A profile
// that fails Validate must not be started. All problems are collected.
func Validate(p DeviceProfile) ValidationResult {
	var res ValidationResult
	add := func(field, detail string) {
		res.Errors = append(res.Errors, ValidationError{field, detail})
	}

	// Identity: model ↔ device ↔ product must agree with the catalogue when the
	// model is known. Unknown models are allowed (custom devices) but then
	// device/product must at least be non-empty.
	if entry, ok := findCatalog(p.Model); ok {
		if !strings.EqualFold(entry.Device, p.Device) {
			add("device", fmt.Sprintf("model %q expects device %q, got %q", p.Model, entry.Device, p.Device))
		}
		if !strings.EqualFold(entry.Product, p.Product) {
			add("product", fmt.Sprintf("model %q expects product %q, got %q", p.Model, entry.Product, p.Product))
		}
	} else {
		if p.Model == "" {
			add("model", "must not be empty")
		}
		if p.Device == "" {
			add("device", "must not be empty for a custom model")
		}
	}

	// Build: android version ↔ API level ↔ build-ID prefix.
	rel, ok := releaseByAPI(p.APILevel)
	if !ok {
		add("api_level", fmt.Sprintf("unsupported API level %d", p.APILevel))
	} else {
		if p.AndroidVersion != rel.Version {
			add("android_version", fmt.Sprintf("API %d expects Android %q, got %q", p.APILevel, rel.Version, p.AndroidVersion))
		}
		if !strings.HasPrefix(p.BuildID, rel.BuildPrefix+".") {
			add("build_id", fmt.Sprintf("API %d expects build ID prefix %q, got %q", p.APILevel, rel.BuildPrefix, p.BuildID))
		}
	}

	// Build: fingerprint should reference the same build ID and be free of
	// emulator markers.
	if p.Fingerprint != "" {
		if p.BuildID != "" && !strings.Contains(p.Fingerprint, p.BuildID) {
			add("fingerprint", "does not contain the build ID")
		}
		low := strings.ToLower(p.Fingerprint)
		for _, marker := range []string{"generic", "goldfish", "ranchu", "sdk", "emulator", "test-keys"} {
			if strings.Contains(low, marker) {
				add("fingerprint", fmt.Sprintf("contains emulator marker %q", marker))
			}
		}
	}

	// Build: security patch ↔ format and not older than the release.
	if !reSecPatch.MatchString(p.SecurityPatch) {
		add("security_patch", "must be YYYY-MM-DD")
	}

	// ABI: must be a known Android ABI.
	switch p.ABI {
	case "arm64-v8a", "armeabi-v7a", "x86", "x86_64":
	default:
		add("abi", fmt.Sprintf("unknown ABI %q", p.ABI))
	}

	// Display: resolution ↔ density sanity.
	if !reResolution.MatchString(p.Resolution) {
		add("resolution", "must be WIDTHxHEIGHT, e.g. 1080x2400")
	}
	if p.Density < 120 || p.Density > 640 {
		add("density", fmt.Sprintf("dpi %d out of realistic range [120,640]", p.Density))
	}

	// Network: MAC and IMEI validity.
	if p.Network.MACAddress != "" && !reMAC.MatchString(p.Network.MACAddress) {
		add("network.mac_address", "invalid MAC format")
	}
	if p.Network.IMEI != "" && !ValidIMEI(p.Network.IMEI) {
		add("network.imei", "fails Luhn / not 15 digits")
	}

	// Battery: level range and status vocabulary.
	if p.Battery.Level < 0 || p.Battery.Level > 100 {
		add("battery.level", fmt.Sprintf("%d out of [0,100]", p.Battery.Level))
	}
	switch p.Battery.Status {
	case "charging", "discharging", "full", "not-charging", "unknown", "":
	default:
		add("battery.status", fmt.Sprintf("unknown status %q", p.Battery.Status))
	}

	// Operator: numeric == MCC+MNC, and digit-shaped.
	if p.Operator.Numeric != "" {
		if !isDigits(p.Operator.Numeric) {
			add("operator.numeric", "must be digits (MCC+MNC)")
		}
		if p.Operator.MCC != "" && p.Operator.MNC != "" {
			if p.Operator.MCC+p.Operator.MNC != p.Operator.Numeric {
				add("operator.numeric", fmt.Sprintf("numeric %q != mcc+mnc %q", p.Operator.Numeric, p.Operator.MCC+p.Operator.MNC))
			}
		}
		if len(p.Operator.MCC) != 0 && len(p.Operator.MCC) != 3 {
			add("operator.mcc", "MCC must be 3 digits")
		}
	}

	return res
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	_, err := strconv.Atoi(s)
	return err == nil
}
