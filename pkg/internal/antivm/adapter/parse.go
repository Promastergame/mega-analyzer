package adapter

import (
	"regexp"
	"strings"
)

var (
	reWMSize    = regexp.MustCompile(`(\d{3,4}x\d{3,4})`)
	reWMDensity = regexp.MustCompile(`(\d{2,4})`)
)

// parseWMSize extracts "1080x2400" from `wm size` output such as
// "Physical size: 1080x2400" or "Override size: 1080x2400".
func parseWMSize(out string) string {
	// Prefer an override line if present (that reflects the current size).
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(strings.ToLower(line), "override") {
			if m := reWMSize.FindString(line); m != "" {
				return m
			}
		}
	}
	return reWMSize.FindString(out)
}

// parseWMDensity extracts the dpi from `wm density` output such as
// "Physical density: 420" or "Override density: 480".
func parseWMDensity(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(strings.ToLower(line), "override") {
			if m := reWMDensity.FindString(line); m != "" {
				return m
			}
		}
	}
	return reWMDensity.FindString(out)
}

// parseDumpsysBattery turns `dumpsys battery` output into a normalised map with
// stable keys: level, status, temperature, health, plugged.
func parseDumpsysBattery(out string) map[string]string {
	res := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(strings.ToLower(key))
		val = strings.TrimSpace(val)
		switch key {
		case "level":
			res["level"] = val
		case "temperature":
			res["temperature"] = val
		case "status":
			res["status"] = normalizeBatteryStatus(val)
		case "health":
			res["health"] = val
		case "ac powered", "usb powered", "wireless powered":
			if val == "true" {
				res["plugged"] = strings.TrimSuffix(key, " powered")
			}
		}
	}
	if _, ok := res["plugged"]; !ok {
		res["plugged"] = "none"
	}
	return res
}

// normalizeBatteryStatus maps Android's numeric/string status to our vocabulary.
func normalizeBatteryStatus(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "2", "charging":
		return "charging"
	case "3", "discharging":
		return "discharging"
	case "4", "not charging", "not-charging":
		return "not-charging"
	case "5", "full":
		return "full"
	default:
		return "unknown"
	}
}
