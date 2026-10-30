package axml

import (
	"fmt"
	"strings"
)

// resConfig captures the qualifiers of one <type> chunk. We only
// stringify the subset that real-world APKs actually populate; the
// rest pass through as raw bytes so we don't lose them.
//
// Format note: ResTable_config is variable-length — the leading u32
// `size` declares how many bytes follow. Older APKs ship ~32-byte
// configs; modern ones reach 64+ as new qualifiers were added (UI
// mode, color mode, screen-layout v2, locale script…).
type resConfig struct {
	size uint32

	// MCC/MNC for telephony-aware resources.
	mcc uint16
	mnc uint16

	// Locale: the on-disk encoding packs 2-letter codes as bytes and
	// 3-letter codes via the high-bit trick described by Android's
	// resource framework.
	language [2]byte
	region   [2]byte

	orientation uint8
	touchscreen uint8
	density     uint16

	keyboard    uint8
	navigation  uint8
	inputFlags  uint8
	grammatical uint8

	screenWidth  uint16
	screenHeight uint16
	sdkVersion   uint16
	minorVersion uint16

	screenLayout   uint8
	uiMode         uint8
	smallestSwDp   uint16
	screenWidthDp  uint16
	screenHeightDp uint16

	localeScript  [4]byte
	localeVariant [8]byte

	screenLayout2 uint8
	colorMode     uint8
}

// parseResConfig reads a ResTable_config tuple from buf. The on-disk
// layout is forward-compatible: trailing fields are absent when `size`
// is small, present otherwise.
func parseResConfig(buf []byte) (resConfig, int, error) {
	if len(buf) < 4 {
		return resConfig{}, 0, fmt.Errorf("config: too small")
	}
	size := uint32(buf[0]) | uint32(buf[1])<<8 | uint32(buf[2])<<16 | uint32(buf[3])<<24
	if size < 8 || uint64(size) > uint64(len(buf)) {
		return resConfig{}, 0, fmt.Errorf("config: bad size %d", size)
	}
	cfg := resConfig{size: size}

	// Read fields, defending against truncation at every checkpoint.
	if size >= 12 {
		cfg.mcc = u16(buf, 4)
		cfg.mnc = u16(buf, 6)
		cfg.language = [2]byte{buf[8], buf[9]}
		cfg.region = [2]byte{buf[10], buf[11]}
	}
	if size >= 14 {
		cfg.orientation = buf[12]
		cfg.touchscreen = buf[13]
	}
	if size >= 16 {
		cfg.density = u16(buf, 14)
	}
	if size >= 20 {
		cfg.keyboard = buf[16]
		cfg.navigation = buf[17]
		cfg.inputFlags = buf[18]
		cfg.grammatical = buf[19]
	}
	if size >= 28 {
		cfg.screenWidth = u16(buf, 20)
		cfg.screenHeight = u16(buf, 22)
		cfg.sdkVersion = u16(buf, 24)
		cfg.minorVersion = u16(buf, 26)
	}
	if size >= 32 {
		cfg.screenLayout = buf[28]
		cfg.uiMode = buf[29]
		cfg.smallestSwDp = u16(buf, 30)
	}
	if size >= 36 {
		cfg.screenWidthDp = u16(buf, 32)
		cfg.screenHeightDp = u16(buf, 34)
	}
	if size >= 48 {
		copy(cfg.localeScript[:], buf[36:40])
		copy(cfg.localeVariant[:], buf[40:48])
	}
	if size >= 52 {
		cfg.screenLayout2 = buf[48]
		cfg.colorMode = buf[49]
		// buf[50:52] = screenConfigPad2, ignored
	}

	return cfg, int(size), nil
}

// String produces the canonical aapt-style qualifier name for this
// config, e.g. "ru", "xxhdpi-v26", "default".
//
// Order matches the alphabetical convention aapt uses, which keeps
// resource directory names stable across builds.
func (c resConfig) String() string {
	var parts []string

	if c.mcc != 0 {
		parts = append(parts, fmt.Sprintf("mcc%d", c.mcc))
	}
	if c.mnc != 0 {
		parts = append(parts, fmt.Sprintf("mnc%d", c.mnc))
	}

	if lang := unpackLocaleField(c.language, 'a'); lang != "" {
		parts = append(parts, lang)
		if reg := unpackLocaleField(c.region, '0'); reg != "" {
			parts[len(parts)-1] = lang + "-r" + strings.ToUpper(reg)
		}
	}

	if c.orientation != 0 {
		switch c.orientation {
		case 1:
			parts = append(parts, "port")
		case 2:
			parts = append(parts, "land")
		case 3:
			parts = append(parts, "square")
		}
	}

	if c.density != 0 {
		switch c.density {
		case 0xffff:
			parts = append(parts, "anydpi")
		case 120:
			parts = append(parts, "ldpi")
		case 160:
			parts = append(parts, "mdpi")
		case 213:
			parts = append(parts, "tvdpi")
		case 240:
			parts = append(parts, "hdpi")
		case 320:
			parts = append(parts, "xhdpi")
		case 480:
			parts = append(parts, "xxhdpi")
		case 640:
			parts = append(parts, "xxxhdpi")
		default:
			parts = append(parts, fmt.Sprintf("%ddpi", c.density))
		}
	}

	if c.sdkVersion != 0 {
		parts = append(parts, fmt.Sprintf("v%d", c.sdkVersion))
	}

	if len(parts) == 0 {
		return "default"
	}
	return strings.Join(parts, "-")
}

// unpackLocaleField reverses the byte-packing scheme used for 2- and
// 3-letter ISO codes in ResTable_config.
//
// Two-letter form: bytes are stored as plain ASCII.
// Three-letter form: high bit set on byte 0; bits encode the offsets
// from `base` ('a' for language, '0' for region).
func unpackLocaleField(in [2]byte, base byte) string {
	if in[0] == 0 {
		return ""
	}
	if in[0]&0x80 == 0 {
		return string([]byte{in[0], in[1]})
	}
	out := [3]byte{
		base + (in[1] & 0x1F),
		base + ((in[1] & 0xE0) >> 5) | ((in[0] & 0x03) << 3),
		base + ((in[0] & 0x7C) >> 2),
	}
	return string(out[:])
}

func u16(buf []byte, off int) uint16 {
	return uint16(buf[off]) | uint16(buf[off+1])<<8
}
