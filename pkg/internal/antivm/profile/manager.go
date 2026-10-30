package profile

import (
	"encoding/json"
	"fmt"
	"os"
)

// Load reads and unmarshals a profile from a JSON file, normalises it, and
// returns it. It does not validate — call Validate separately so the caller
// controls whether an inconsistent file is a hard error.
func Load(path string) (DeviceProfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return DeviceProfile{}, fmt.Errorf("read profile %s: %w", path, err)
	}
	var p DeviceProfile
	if err := json.Unmarshal(data, &p); err != nil {
		return DeviceProfile{}, fmt.Errorf("parse profile %s: %w", path, err)
	}
	Normalize(&p)
	return p, nil
}

// LoadValid reads a profile and fails if it is inconsistent.
func LoadValid(path string) (DeviceProfile, error) {
	p, err := Load(path)
	if err != nil {
		return DeviceProfile{}, err
	}
	if res := Validate(p); !res.OK() {
		return DeviceProfile{}, fmt.Errorf("invalid profile %s: %w", path, res.Err())
	}
	return p, nil
}

// Save writes a profile as indented JSON.
func Save(p DeviceProfile, path string) error {
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal profile: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write profile %s: %w", path, err)
	}
	return nil
}

// Merge overlays non-zero fields of over onto base and returns the result. It
// is used to apply partial overrides (e.g. CLI flags) on top of a loaded
// profile. Only scalar identity/build/display fields and whole sub-profiles
// are overlaid; empty strings and zero ints in over are treated as "unset".
func Merge(base, over DeviceProfile) DeviceProfile {
	out := base
	setStr := func(dst *string, v string) {
		if v != "" {
			*dst = v
		}
	}
	setInt := func(dst *int, v int) {
		if v != 0 {
			*dst = v
		}
	}
	setStr(&out.Name, over.Name)
	setStr(&out.Model, over.Model)
	setStr(&out.Brand, over.Brand)
	setStr(&out.Manufacturer, over.Manufacturer)
	setStr(&out.Device, over.Device)
	setStr(&out.Product, over.Product)
	setStr(&out.AndroidVersion, over.AndroidVersion)
	setInt(&out.APILevel, over.APILevel)
	setStr(&out.ABI, over.ABI)
	setStr(&out.BuildID, over.BuildID)
	setStr(&out.Fingerprint, over.Fingerprint)
	setStr(&out.SecurityPatch, over.SecurityPatch)
	setStr(&out.Locale, over.Locale)
	setStr(&out.Timezone, over.Timezone)
	setStr(&out.Resolution, over.Resolution)
	setInt(&out.Density, over.Density)

	if over.Network != (NetworkProfile{}) {
		out.Network = over.Network
	}
	if over.Battery != (BatteryProfile{}) {
		out.Battery = over.Battery
	}
	if over.Operator != (OperatorProfile{}) {
		out.Operator = over.Operator
	}
	if over.Sensor != (SensorProfile{}) {
		out.Sensor = over.Sensor
	}
	return out
}
