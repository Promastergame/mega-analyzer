package axml

// Reference resolution and typed-value parsing for the overlay encoder.

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// lookupResID maps a known android attribute to its resource ID.
func lookupResID(ns, name string) uint32 {
	if ns != androidNS {
		return 0
	}
	if spec, ok := nativeAndroidAttrs[name]; ok {
		return spec.ID
	}
	for id, n := range resourceID {
		if n == name {
			return id
		}
	}
	return 0
}

// isKnownIntAttr gates decimal inference for brand-new attributes so a
// string like "007" is not miscompiled into an integer.
func isKnownIntAttr(name string) bool {
	switch name {
	case "versionCode", "revisionCode", "minSdkVersion", "targetSdkVersion",
		"compileSdkVersion", "maxSdkVersion", "rotationConfig",
		"configChanges", "screenOrientation", "launchMode", "priority",
		"level", "max", "progress", "version":
		return true
	}
	return false
}

// resolveReference resolves @... to a resource ID. table may be nil only
// when the text is already numeric.
func resolveReference(text string, table *ResourceTable) (uint32, error) {
	id, _, err := resolveReferenceFull(text, table)
	return id, err
}

func resolveReferenceFull(text string, table *ResourceTable) (uint32, bool, error) {
	t := strings.TrimSpace(text)
	isAttr := strings.HasPrefix(t, "?")
	if !strings.HasPrefix(t, "@") && !isAttr {
		return 0, false, fmt.Errorf("not a reference: %q", text)
	}
	body := t[1:]
	if strings.HasPrefix(body, "+") {
		body = body[1:]
	}
	if strings.HasPrefix(body, "0x") || strings.HasPrefix(body, "0X") {
		v, err := strconv.ParseUint(body, 0, 32)
		if err != nil {
			return 0, false, fmt.Errorf("bad reference %q", text)
		}
		return uint32(v), isAttr, nil
	}
	if table == nil {
		return 0, false, fmt.Errorf("cannot resolve %q without a resource table (run with resources.arsc present)", text)
	}
	// package:type/name, type/name, android:type/name
	pkg := ""
	rest := body
	if i := strings.Index(rest, ":"); i >= 0 {
		pkg = rest[:i]
		rest = rest[i+1:]
	}
	tn := strings.SplitN(rest, "/", 2)
	if len(tn) != 2 {
		return 0, false, fmt.Errorf("bad reference %q", text)
	}
	for pi := range table.Packages {
		p := &table.Packages[pi]
		if pkg != "" && pkg != "android" && !strings.EqualFold(p.Name, pkg) {
			continue
		}
		if pkg == "android" && p.ID != 1 {
			continue
		}
		for ti := range p.Types {
			if p.Types[ti].Name != tn[0] {
				continue
			}
			for _, e := range p.Types[ti].Entries {
				if e.Name == tn[1] {
					return (p.ID << 24) | (p.Types[ti].ID << 16) | e.ID, isAttr, nil
				}
			}
		}
	}
	return 0, false, fmt.Errorf("reference %q not found in resource table", text)
}

// renderTypedValue renders binary (type, data) for overlay comparison.
func renderTypedValue(t uint8, data uint32, str string) string {
	switch t {
	case typeNull:
		return ""
	case typeReference, typeDynamicRef:
		return fmt.Sprintf("@0x%08x", data)
	case typeAttribute, typeDynamicAttr:
		return fmt.Sprintf("?0x%08x", data)
	case typeString:
		return str
	case typeFloat:
		return strconv.FormatFloat(float64(math.Float32frombits(data)), 'g', -1, 32)
	case typeIntDec:
		return strconv.FormatInt(int64(int32(data)), 10)
	case typeIntHex:
		return fmt.Sprintf("0x%08x", data)
	case typeIntBoolean:
		if data == 0 {
			return "false"
		}
		return "true"
	case typeIntColorARGB8, typeIntColorRGB8, typeIntColorARGB4, typeIntColorRGB4:
		return fmt.Sprintf("#%08x", data)
	case typeDimension, typeFraction:
		// Match Decoder.formatAttrValue: unedited native XML carries the
		// packed complex value as hex, which must compare equal to its twin.
		return fmt.Sprintf("0x%x", data)
	default:
		return fmt.Sprintf("0x%x", data)
	}
}

func parseColor(s string) (uint32, error) {
	t := strings.TrimSpace(s)
	if !strings.HasPrefix(t, "#") {
		return 0, fmt.Errorf("not a color: %q", s)
	}
	h := t[1:]
	var a, r, g, b uint64
	var err error
	hex := func(x string) (uint64, error) { return strconv.ParseUint(x, 16, 32) }
	switch len(h) {
	case 3:
		var e2, e3 error
		r, err = hex(strings.Repeat(string(h[0]), 2))
		g, e2 = hex(strings.Repeat(string(h[1]), 2))
		b, e3 = hex(strings.Repeat(string(h[2]), 2))
		if err != nil || e2 != nil || e3 != nil {
			return 0, fmt.Errorf("bad color %q", s)
		}
		a = 0xFF
	case 4:
		var e2, e3, e4 error
		a, err = hex(strings.Repeat(string(h[0]), 2))
		r, e2 = hex(strings.Repeat(string(h[1]), 2))
		g, e3 = hex(strings.Repeat(string(h[2]), 2))
		b, e4 = hex(strings.Repeat(string(h[3]), 2))
		if err != nil || e2 != nil || e3 != nil || e4 != nil {
			return 0, fmt.Errorf("bad color %q", s)
		}
	case 6:
		a = 0xFF
		if r, err = hex(h[0:2]); err != nil {
			return 0, fmt.Errorf("bad color %q", s)
		}
		if g, err = hex(h[2:4]); err != nil {
			return 0, fmt.Errorf("bad color %q", s)
		}
		if b, err = hex(h[4:6]); err != nil {
			return 0, fmt.Errorf("bad color %q", s)
		}
	case 8:
		for i, dst := range []*uint64{&a, &r, &g, &b} {
			if *dst, err = hex(h[i*2 : i*2+2]); err != nil {
				return 0, fmt.Errorf("bad color %q", s)
			}
		}
	default:
		return 0, fmt.Errorf("bad color %q", s)
	}
	return uint32(a<<24 | r<<16 | g<<8 | b), nil
}

// Complex (dimension/fraction) encoding per the Android Res_value layout:
// bits [31:8] mantissa, [7:4] radix, [3:0] unit.
func parseComplex(s, kind string) (uint32, error) {
	t := strings.TrimSpace(s)
	// Split numeric prefix from unit suffix.
	i := 0
	for i < len(t) && (t[i] == '+' || t[i] == '-' || t[i] == '.' || (t[i] >= '0' && t[i] <= '9') || t[i] == 'e' || t[i] == 'E') {
		i++
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(t[:i]), 64)
	if err != nil {
		return 0, fmt.Errorf("bad %s %q", kind, s)
	}
	unit := strings.TrimSpace(t[i:])
	var unitBits uint32
	if kind == "fraction" {
		switch unit {
		case "%":
			unitBits = 0
		case "%p":
			unitBits = 1
		default:
			return 0, fmt.Errorf("bad fraction unit %q", unit)
		}
	} else {
		switch unit {
		case "px":
			unitBits = 0
		case "dip", "dp":
			unitBits = 1
		case "sp":
			unitBits = 2
		case "pt":
			unitBits = 3
		case "in":
			unitBits = 4
		case "mm":
			unitBits = 5
		default:
			return 0, fmt.Errorf("bad dimension unit %q", unit)
		}
	}
	// Try radixes 23.0, 16.7, 8.15, 0.23 (aapt order: exact fit first).
	mults := [4]float64{1 << 23, 1 << 16 / 100, 1 << 8 / 100, 1.0 / 100}
	_ = mults
	for radix := 0; radix < 4; radix++ {
		var m float64
		switch radix {
		case 0:
			m = f * (1 << 23)
		case 1:
			m = f * (1 << 16) / 100
		case 2:
			m = f * (1 << 8) / 100
		case 3:
			m = f / 100
		}
		if m == math.Trunc(m) && m >= -8388608 && m <= 8388607 {
			mant := uint32(int32(m)) & 0xFFFFFF
			return (mant << 8) | (uint32(radix) << 4) | unitBits, nil
		}
	}
	return 0, fmt.Errorf("%s %q is not exactly representable", kind, s)
}

func formatComplex(data uint32) string {
	mant := int32(data>>8) << 8 >> 8 // sign-extend 24 bits
	radix := (data >> 4) & 3
	unit := data & 0xF
	var f float64
	switch radix {
	case 0:
		f = float64(mant) / (1 << 23)
	case 1:
		f = float64(mant) * 100 / (1 << 16)
	case 2:
		f = float64(mant) * 100 / (1 << 8)
	default:
		f = float64(mant) * 100
	}
	return strconv.FormatFloat(f, 'g', -1, 64) + complexUnit(unit)
}

func complexUnit(u uint32) string {
	// Ambiguous between dimension/fraction units; dimension names win for
	// overlay comparison (both parse back to the same bits).
	switch u {
	case 0:
		return "px"
	case 1:
		return "dip"
	case 2:
		return "sp"
	case 3:
		return "pt"
	case 4:
		return "in"
	case 5:
		return "mm"
	}
	return ""
}
