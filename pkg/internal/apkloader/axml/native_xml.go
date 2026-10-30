package axml

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

type nativeAttrSpec struct {
	ID     uint32
	Format string
	Flags  bool
	Values map[string]uint32
}

// CompileTextAXML compiles a new XML document without an original binary,
// aapt2 or android.jar. Unsupported attributes/values are errors: inventing a
// string value for an unknown framework enum produces XML Android cannot use.
func CompileTextAXML(text []byte, table *ResourceTable) ([]byte, error) {
	doc, err := ParseTextAXML(text)
	if err != nil {
		return nil, err
	}
	var compile func(*DomElem) error
	compile = func(el *DomElem) error {
		seen := map[string]bool{}
		for i, a := range el.Attrs {
			key := a.NS + "\x00" + a.Name
			if seen[key] {
				return fmt.Errorf("axml: duplicate attribute %s on <%s>", a.Name, el.Name)
			}
			seen[key] = true
			if a.NS == "http://schemas.android.com/tools" {
				return fmt.Errorf("axml: build-time tools:%s attributes must be removed before native compilation", a.Name)
			}
			var spec nativeAttrSpec
			if a.NS == androidNS {
				var ok bool
				spec, ok = nativeAndroidAttrs[a.Name]
				if !ok {
					return fmt.Errorf("axml: unsupported Android attribute %s on <%s>", a.Name, el.Name)
				}
			} else if a.NS != "" {
				return fmt.Errorf("axml: custom attribute %s on <%s> needs a resource attribute definition; native custom attributes are not supported", a.Name, el.Name)
			} else {
				spec.Format = "string"
				if a.Name == "style" {
					spec.Format = "reference"
				}
			}
			v, err := nativeAttributeValue(a.Str, spec, table)
			if err != nil {
				return fmt.Errorf("axml: <%s> %s: %w", el.Name, a.Name, err)
			}
			v.Name, v.NS, v.ResID = a.Name, a.NS, spec.ID
			el.Attrs[i] = v
		}
		// Android's resource-ID lookup relies on attributes being sorted.
		sort.SliceStable(el.Attrs, func(i, j int) bool { return el.Attrs[i].ResID < el.Attrs[j].ResID })
		for _, k := range el.Kids {
			if err := compile(k); err != nil {
				return err
			}
		}
		return nil
	}
	if err := compile(doc.Root); err != nil {
		return nil, err
	}
	return EncodeDomAXML(doc)
}

func nativeReference(text string, table *ResourceTable) (DomAttr, error) {
	v := DomAttr{Type: typeReference}
	if text == "@null" {
		return v, nil
	}
	if text == "@empty" {
		return DomAttr{Type: typeNull, Data: 1}, nil
	}
	body := strings.TrimPrefix(strings.TrimPrefix(text, "@"), "?")
	if strings.HasPrefix(text, "?") {
		v.Type = typeAttribute
	}
	if strings.HasPrefix(body, "android:") {
		key := strings.TrimPrefix(body, "android:")
		if !strings.Contains(key, "/") && v.Type == typeAttribute {
			key = "attr/" + key
		}
		if strings.HasPrefix(key, "attr/") {
			if s, ok := nativeAndroidAttrs[strings.TrimPrefix(key, "attr/")]; ok {
				v.Data = s.ID
				return v, nil
			}
		}
		if id, ok := nativeFrameworkRefs[key]; ok {
			v.Data = id
			return v, nil
		}
		return v, fmt.Errorf("framework reference %q is not in the embedded public catalog; use its numeric @0x... ID", text)
	}
	id, attr, err := resolveReferenceFull(text, table)
	if err != nil {
		return v, err
	}
	v.Data = id
	if attr {
		v.Type = typeAttribute
	}
	return v, nil
}

func nativeAttributeValue(text string, spec nativeAttrSpec, table *ResourceTable) (DomAttr, error) {
	t := strings.TrimSpace(text)
	if strings.HasPrefix(t, "@") || strings.HasPrefix(t, "?") {
		return nativeReference(t, table)
	}
	if len(spec.Values) > 0 {
		var value uint32
		parts := strings.Split(t, "|")
		if len(parts) == 1 || spec.Flags {
			valid := true
			for _, p := range parts {
				n, ok := spec.Values[strings.TrimSpace(p)]
				if !ok {
					valid = false
					break
				}
				value |= n
			}
			if valid {
				return DomAttr{Type: typeIntHex, Data: value}, nil
			}
		}
	}
	formats := "|" + spec.Format + "|"
	has := func(f string) bool { return strings.Contains(formats, "|"+f+"|") }
	if has("boolean") && (t == "true" || t == "false") {
		v := DomAttr{Type: typeIntBoolean}
		if t == "true" {
			v.Data = 0xffffffff
		}
		return v, nil
	}
	if has("integer") || len(spec.Values) > 0 {
		base := 10
		if strings.HasPrefix(t, "0x") || strings.HasPrefix(t, "-0x") {
			base = 0
		}
		if n, err := strconv.ParseInt(t, base, 32); err == nil {
			return DomAttr{Type: typeIntDec, Data: uint32(n)}, nil
		}
		if n, err := strconv.ParseUint(t, base, 32); err == nil {
			return DomAttr{Type: typeIntHex, Data: uint32(n)}, nil
		}
	}
	if has("color") && strings.HasPrefix(t, "#") {
		if n, err := parseColor(t); err == nil {
			return DomAttr{Type: typeIntColorARGB8, Data: n}, nil
		}
	}
	if has("dimension") {
		if n, err := nativeComplex(t, false); err == nil {
			return DomAttr{Type: typeDimension, Data: n}, nil
		}
	}
	if has("fraction") {
		if n, err := nativeComplex(t, true); err == nil {
			return DomAttr{Type: typeFraction, Data: n}, nil
		}
	}
	if has("float") {
		if n, err := strconv.ParseFloat(t, 32); err == nil && !math.IsNaN(n) && !math.IsInf(n, 0) {
			return DomAttr{Type: typeFloat, Data: math.Float32bits(float32(n))}, nil
		}
	}
	if has("string") {
		if strings.HasPrefix(text, `\@`) || strings.HasPrefix(text, `\?`) {
			text = text[1:]
		}
		return DomAttr{Type: typeString, Str: text}, nil
	}
	return DomAttr{}, fmt.Errorf("unsupported value %q (expected %s or a reference)", text, spec.Format)
}

// Android complex values use a signed 24-bit mantissa and radix 23.0,
// 16.7, 8.15 or 0.23. Fractions store the ratio, rather than the percentage.
func nativeComplex(text string, fraction bool) (uint32, error) {
	units := []string{"px", "dp", "sp", "pt", "in", "mm"}
	if fraction {
		units = []string{"%", "%p"}
	}
	text = strings.TrimSpace(text)
	if strings.HasSuffix(text, "dip") {
		text = strings.TrimSuffix(text, "dip") + "dp"
	}
	for unit, suffix := range units {
		if !strings.HasSuffix(text, suffix) {
			continue
		}
		n, err := strconv.ParseFloat(strings.TrimSuffix(text, suffix), 64)
		if err != nil || math.IsNaN(n) || math.IsInf(n, 0) {
			break
		}
		if fraction {
			n /= 100
		}
		if n < -8388608 || n >= 8388608 {
			break
		}
		for _, radix := range []int{0, 3, 2, 1} {
			shift := []uint{0, 7, 15, 23}[radix]
			m := n * float64(uint64(1)<<shift)
			if m < -8388608 || m > 8388607 {
				continue
			}
			if radix == 0 && m != math.Trunc(m) {
				continue
			}
			return ((uint32(int32(math.Round(m))) & 0xffffff) << 8) | uint32(radix<<4) | uint32(unit), nil
		}
	}
	return 0, fmt.Errorf("invalid complex resource %q", text)
}
