package apkloader

// Native DEX writer: assembled classes + pools → valid .dex bytes.
//
// Layout follows the DEX file format (header, ids, class data, code, data,
// map list) with spec-required sort orders, ULEB128/SLEB128 coding, MUTF-8
// strings, adler32 checksum and SHA-1 signature. All code is pure Go.

import (
	"fmt"
	"math"
	"sort"
	"unicode/utf16"
)

// ── Low-level writers ────────────────────────────────────────────────────────

func dexPutUleb(buf *[]byte, v uint32) {
	for {
		b := byte(v & 0x7F)
		v >>= 7
		if v != 0 {
			*buf = append(*buf, b|0x80)
		} else {
			*buf = append(*buf, b)
			return
		}
	}
}

func dexPutSleb(buf *[]byte, v int32) {
	more := true
	for more {
		b := byte(v & 0x7F)
		v >>= 7
		sign := (b & 0x40) != 0
		if (v == 0 && !sign) || (v == -1 && sign) {
			more = false
		} else {
			b |= 0x80
		}
		*buf = append(*buf, b)
	}
}

func dexPutU16(buf *[]byte, v uint16) {
	*buf = append(*buf, byte(v), byte(v>>8))
}

func dexPutU32(buf *[]byte, v uint32) {
	*buf = append(*buf, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

// encodeMUTF8 encodes s as Modified UTF-8.
func encodeMUTF8(s string) []byte {
	var out []byte
	for _, r := range s {
		switch {
		case r == 0:
			out = append(out, 0xC0, 0x80)
		case r < 0x80:
			out = append(out, byte(r))
		case r < 0x800:
			out = append(out, byte(0xC0|(r>>6)), byte(0x80|(r&0x3F)))
		default:
			if r > 0xFFFF {
				r1, r2 := utf16.EncodeRune(r)
				for _, sr := range []rune{r1, r2} {
					out = append(out, byte(0xE0|(sr>>12)), byte(0x80|((sr>>6)&0x3F)), byte(0x80|(sr&0x3F)))
				}
			} else {
				out = append(out, byte(0xE0|(r>>12)), byte(0x80|((r>>6)&0x3F)), byte(0x80|(r&0x3F)))
			}
		}
	}
	return out
}

func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		if r > 0xFFFF {
			n += 2
		} else {
			n++
		}
	}
	return n
}

// ── Pool finalization ────────────────────────────────────────────────────────

// freeze sorts tables per DEX requirements and rebuilds index maps.
// After freeze, typ/proto/field/method/handle/callsite must already contain
// every entry (assembly only looks them up); new strings are still appended.
func (p *asmPools) freeze() {
	// Types sorted by descriptor (byte order ≈ MUTF-8 order for ASCII).
	sortedTypes := append([]string(nil), p.types...)
	sort.Strings(sortedTypes)
	typeSet := map[string]bool{}
	for _, t := range sortedTypes {
		typeSet[t] = true
	}
	// Strings: type descriptors first (in type order), then the rest sorted.
	rest := []string{}
	restSet := map[string]bool{}
	for _, s := range p.strings {
		if !typeSet[s] && !restSet[s] {
			restSet[s] = true
			rest = append(rest, s)
		}
	}
	sort.Strings(rest)
	p.strings = append(append([]string(nil), sortedTypes...), rest...)
	p.strIndex = map[string]uint32{}
	for i, s := range p.strings {
		p.strIndex[s] = uint32(i)
	}
	p.typeIndex = map[string]uint32{}
	for i, t := range sortedTypes {
		p.typeIndex[t] = uint32(i)
	}
	p.types = sortedTypes
	// Protos sorted by (return type idx, params).
	sort.Slice(p.protos, func(i, j int) bool {
		a, b := p.protos[i], p.protos[j]
		ra, rb := p.typeIndex[a.ret], p.typeIndex[b.ret]
		if ra != rb {
			return ra < rb
		}
		for k := 0; k < len(a.params) && k < len(b.params); k++ {
			ia, ib := p.typeIndex[a.params[k]], p.typeIndex[b.params[k]]
			if ia != ib {
				return ia < ib
			}
		}
		return len(a.params) < len(b.params)
	})
	p.protoIndex = map[string]uint32{}
	for i, pr := range p.protos {
		p.protoIndex[protoKey(pr.ret, pr.params)] = uint32(i)
	}
	// Fields sorted by (class, name, type).
	sort.Slice(p.fields, func(i, j int) bool {
		a, b := p.fields[i], p.fields[j]
		if a.cls != b.cls {
			return p.typeIndex[a.cls] < p.typeIndex[b.cls]
		}
		if a.name != b.name {
			return p.strIndex[a.name] < p.strIndex[b.name]
		}
		return p.typeIndex[a.typ] < p.typeIndex[b.typ]
	})
	p.fieldIndex = map[string]uint32{}
	for i, f := range p.fields {
		p.fieldIndex[f.cls+"\x00"+f.name+"\x00"+f.typ] = uint32(i)
	}
	// Methods sorted by (class, name, proto).
	sort.Slice(p.methods, func(i, j int) bool {
		a, b := p.methods[i], p.methods[j]
		if a.cls != b.cls {
			return p.typeIndex[a.cls] < p.typeIndex[b.cls]
		}
		if a.name != b.name {
			return p.strIndex[a.name] < p.strIndex[b.name]
		}
		return p.protoIndex[protoKey(a.ret, a.params)] < p.protoIndex[protoKey(b.ret, b.params)]
	})
	p.methodIndex = map[string]uint32{}
	for i, m := range p.methods {
		p.methodIndex[m.cls+"\x00"+m.name+"\x00"+protoKey(m.ret, m.params)] = uint32(i)
	}
	p.frozen = true
}

// ── Encoded values ───────────────────────────────────────────────────────────

// writeEncodedValue writes one DEXValue in encoded_value form.
func writeEncodedValue(buf *[]byte, pools *asmPools, v DEXValue) error {
	switch v.Kind {
	case 0x00, 0x02, 0x03, 0x04, 0x06: // byte short char int long
		var width, max int
		var raw uint64
		switch v.Kind {
		case 0x00:
			width, max, raw = 1, 1, uint64(int8(v.Bits))
		case 0x02:
			{
				sv := int64(int16(v.Bits))
				width = 1
				if sv < -128 || sv > 127 {
					width = 2
				}
				max, raw = 2, uint64(uint16(sv))
			}
		case 0x03:
			width, max, raw = 2, 2, v.Bits&0xFFFF
			if v.Bits <= 0xFF {
				width = 1
			}
		case 0x04:
			{
				sv := int64(int32(v.Bits))
				switch {
				case sv >= -128 && sv <= 127:
					width = 1
				case sv >= -32768 && sv <= 32767:
					width = 2
				case sv >= -8388608 && sv <= 8388607:
					width = 3
				default:
					width = 4
				}
				max, raw = 4, uint64(uint32(sv))
			}
		case 0x06:
			{
				sv := int64(v.Bits)
				switch {
				case sv >= -128 && sv <= 127:
					width = 1
				case sv >= -32768 && sv <= 32767:
					width = 2
				case sv >= -8388608 && sv <= 8388607:
					width = 3
				case sv >= -2147483648 && sv <= 2147483647:
					width = 4
				case sv >= -140737488355328 && sv <= 140737488355327:
					width = 6
					if sv < -549755813888 || sv > 549755813887 {
						// 6 bytes covers ±2^47; use 7/8 as needed.
						width = 8
						if sv >= -2147483648*128 && sv <= 2147483647*128 {
							width = 7
						}
					}
				default:
					width = 8
				}
				max, raw = 8, uint64(sv)
			}
		}
		if width > max {
			width = max
		}
		*buf = append(*buf, byte((width-1)<<5)|v.Kind)
		for i := 0; i < width; i++ {
			*buf = append(*buf, byte(raw>>(8*i)))
		}
	case 0x10:
		*buf = append(*buf, byte(3<<5)|0x10)
		b := uint32(v.Bits)
		*buf = append(*buf, byte(b), byte(b>>8), byte(b>>16), byte(b>>24))
	case 0x11:
		*buf = append(*buf, byte(7<<5)|0x11)
		b := v.Bits
		for i := 0; i < 8; i++ {
			*buf = append(*buf, byte(b>>(8*i)))
		}
	case 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b:
		{
			idx := uint32(v.Bits)
			w := 1
			switch {
			case idx > 0xFFFFFF:
				w = 4
			case idx > 0xFFFF:
				w = 3
			case idx > 0xFF:
				w = 2
			}
			*buf = append(*buf, byte((w-1)<<5)|v.Kind)
			for i := 0; i < w; i++ {
				*buf = append(*buf, byte(idx>>(8*i)))
			}
			_ = pools
		}
	case 0x1c:
		*buf = append(*buf, 0x1c)
		dexPutUleb(buf, uint32(len(v.Elements)))
		for _, e := range v.Elements {
			if err := writeEncodedValue(buf, pools, e); err != nil {
				return err
			}
		}
	case 0x1d:
		*buf = append(*buf, 0x1d)
		if v.Annotation == nil {
			return fmt.Errorf("empty annotation value")
		}
		writeEncodedAnnotation(buf, pools, v.Annotation)
	case 0x1e:
		*buf = append(*buf, 0x1e)
	case 0x1f:
		arg := byte(0)
		if v.Bits != 0 {
			arg = 1
		}
		*buf = append(*buf, arg<<5|0x1f)
	default:
		return fmt.Errorf("unsupported encoded value 0x%x", v.Kind)
	}
	return nil
}

func writeEncodedAnnotation(buf *[]byte, pools *asmPools, a *DEXAnnotation) {
	dexPutUleb(buf, pools.typeIndex[a.Type])
	dexPutUleb(buf, uint32(len(a.Elements)))
	idx := append([]DEXAnnotationElement(nil), a.Elements...)
	sort.Slice(idx, func(i, j int) bool { return pools.strIndex[idx[i].Name] < pools.strIndex[idx[j].Name] })
	for _, e := range idx {
		dexPutUleb(buf, pools.strIndex[e.Name])
		_ = writeEncodedValue(buf, pools, e.Value)
	}
}

// ── Assembly driver ──────────────────────────────────────────────────────────

func hasFieldSets(c *asmClass) bool {
	for _, f := range c.staticF {
		if f.setOff != 0 {
			return true
		}
	}
	for _, f := range c.instanceF {
		if f.setOff != 0 {
			return true
		}
	}
	return false
}

func hasMethodSets(c *asmClass) bool {
	for _, m := range c.directM {
		if m.setOff != 0 {
			return true
		}
	}
	for _, m := range c.virtualM {
		if m.setOff != 0 {
			return true
		}
	}
	return false
}

func hasParamSets(c *asmClass) bool {
	for _, m := range c.directM {
		if m.paramListOff != 0 {
			return true
		}
	}
	for _, m := range c.virtualM {
		if m.paramListOff != 0 {
			return true
		}
	}
	return false
}

// asmClass is a fully collected class ready for writing.
type asmClass struct {
	file          *SmaliFile
	typeIdx       uint32
	superIdx      uint32
	ifaces        []uint32
	sourceIdx     uint32
	hasSource     bool
	classDataOff  uint32
	annoDirOff    uint32
	staticValsOff uint32
	classSetOff   uint32
	staticF       []*asmFieldOut
	instanceF     []*asmFieldOut
	directM       []*asmMethodOut
	virtualM      []*asmMethodOut
	classAnn      []DEXAnnotation
	staticVals    []DEXValue
}

type asmFieldOut struct {
	idx    uint32
	acc    uint32
	ann    []DEXAnnotation
	setOff uint32
}

type paramOffs []uint32

func (p *paramOffs) ensure(i int) *uint32 {
	for len(*p) <= i {
		*p = append(*p, 0)
	}
	return &(*p)[i]
}

type asmMethodOut struct {
	idx          uint32
	acc          uint32
	code         *asmMethodCode
	ann          []DEXAnnotation
	params       [][]DEXAnnotation
	setOff       uint32
	paramSetOffs paramOffs
	paramListOff uint32
}

// nativeUnsupportedError identifies constructs the native writer cannot represent.
type nativeUnsupportedError struct{ msg string }

func (e *nativeUnsupportedError) Error() string { return e.msg }

func unsupported(format string, args ...interface{}) error {
	return &nativeUnsupportedError{msg: fmt.Sprintf(format, args...)}
}

func isUnsupported(err error) bool {
	_, ok := err.(*nativeUnsupportedError)
	return ok
}

// prescanMethod parses and interns every reference of a method.
func prescanMethod(pools *asmPools, cls string, m *SmaliMethod) error {
	for _, ln := range m.Lines {
		if ln.Kind == LineCatch && ln.Catch != nil && ln.Catch.Type != "" {
			pools.typ(ln.Catch.Type)
			continue
		}
		if ln.Kind != LineInsn {
			continue
		}
		ai, err := parseMethodInsnOperands(ln, m)
		if err != nil {
			return err
		}
		ln.parsed = ai
		if err := internInsnRefs(pools, ai); err != nil {
			if isUnsupported(err) {
				return err
			}
			return fmt.Errorf("%s: %v", ln.Raw, err)
		}
	}
	return nil
}

// prescanClass interns class-level references.
func prescanClass(pools *asmPools, f *SmaliFile) error {
	pools.typ(f.Class)
	if f.Super != "" {
		pools.typ(f.Super)
	}
	for _, it := range f.Interfaces {
		pools.typ(it)
	}
	if f.Source != "" {
		pools.str(f.Source)
	}
	for _, a := range f.Annotations {
		if _, err := pools.internAnnotation(a); err != nil {
			return err
		}
	}
	for _, fld := range f.Fields {
		pools.typ(fld.Type)
		pools.str(fld.Name)
		pools.field(f.Class, fld.Name, fld.Type)
		for _, a := range fld.Annotations {
			if _, err := pools.internAnnotation(a); err != nil {
				return err
			}
		}
		if fld.Initializer != nil {
			if _, err := pools.internDEXValue(fld.Initializer); err != nil {
				return err
			}
		}
	}
	for _, m := range f.Methods {
		pools.str(m.Name)
		pools.proto(m.Return, m.Params)
		pools.method(f.Class, m.Name, m.Params, m.Return)
		for _, a := range m.Annotations {
			if _, err := pools.internAnnotation(a); err != nil {
				return err
			}
		}
		for _, list := range m.ParamAnnots {
			for _, a := range list {
				if _, err := pools.internAnnotation(a); err != nil {
					return err
				}
			}
		}
		if err := prescanMethod(pools, f.Class, m); err != nil {
			return err
		}
	}
	return nil
}

// defaultStaticDEXValue builds the runtime default for a gap in static values.
func defaultStaticDEXValue(typ string) DEXValue {
	switch typ {
	case "Z", "B", "S", "C", "I":
		return DEXValue{Kind: 0x04, Bits: 0}
	case "J":
		return DEXValue{Kind: 0x06, Bits: 0}
	case "F":
		return DEXValue{Kind: 0x10, Bits: 0}
	case "D":
		return DEXValue{Kind: 0x11, Bits: 0}
	default:
		return DEXValue{Kind: 0x1e}
	}
}

// smaliValueToDEX converts a field initializer with type context.
func smaliValueToDEX(pools *asmPools, typ string, v *SmaliValue) (DEXValue, error) {
	if v.Kind == "int" && (typ == "F" || typ == "D") {
		if typ == "F" {
			return DEXValue{Kind: 0x10, Bits: uint64(math.Float32bits(float32(v.Int)))}, nil
		}
		return DEXValue{Kind: 0x11, Bits: math.Float64bits(float64(v.Int))}, nil
	}
	return pools.internDEXValue(v)
}

// collectClasses builds writer classes from parsed files.
func collectClasses(pools *asmPools, files []*SmaliFile) ([]*asmClass, error) {
	seen := map[string]string{}
	var out []*asmClass
	for _, f := range files {
		if prev, dup := seen[f.Class]; dup {
			return nil, fmt.Errorf("duplicate class %s (%s and %s)", f.Class, prev, f.Path)
		}
		seen[f.Class] = f.Path
		c := &asmClass{file: f}
		out = append(out, c)
	}
	for _, c := range out {
		f := c.file
		c.typeIdx = pools.typeIndex[f.Class]
		if f.Super != "" {
			c.superIdx = pools.typeIndex[f.Super]
		} else {
			c.superIdx = pools.typeIndex["Ljava/lang/Object;"]
		}
		for _, it := range f.Interfaces {
			c.ifaces = append(c.ifaces, pools.typeIndex[it])
		}
		if f.Source != "" {
			c.sourceIdx = pools.strIndex[f.Source]
			c.hasSource = true
		}
		for _, a := range f.Annotations {
			da, err := pools.internAnnotation(a)
			if err != nil {
				return nil, err
			}
			c.classAnn = append(c.classAnn, da)
		}
		type staticInfo struct {
			fo   *asmFieldOut
			typ  string
			init *SmaliValue
			name string
		}
		var statics []staticInfo
		for _, fld := range f.Fields {
			fo := &asmFieldOut{idx: pools.field(f.Class, fld.Name, fld.Type), acc: fld.Access}
			for _, a := range fld.Annotations {
				da, err := pools.internAnnotation(a)
				if err != nil {
					return nil, err
				}
				fo.ann = append(fo.ann, da)
			}
			if fld.Access&0x0008 != 0 {
				c.staticF = append(c.staticF, fo)
				statics = append(statics, staticInfo{fo: fo, typ: fld.Type, init: fld.Initializer, name: fld.Name})
			} else {
				c.instanceF = append(c.instanceF, fo)
			}
		}
		// static_values follow the sorted static-field order; trailing
		// defaults are omitted, middle gaps get type defaults.
		sort.Slice(statics, func(i, j int) bool { return statics[i].fo.idx < statics[j].fo.idx })
		c.staticF = c.staticF[:0]
		lastInit := -1
		for i, s := range statics {
			c.staticF = append(c.staticF, s.fo)
			if s.init != nil {
				lastInit = i
			}
		}
		for i := 0; i <= lastInit; i++ {
			s := statics[i]
			if s.init != nil {
				dv, err := smaliValueToDEX(pools, s.typ, s.init)
				if err != nil {
					return nil, fmt.Errorf("%s: field %s: %v", f.Path, s.name, err)
				}
				c.staticVals = append(c.staticVals, dv)
			} else {
				c.staticVals = append(c.staticVals, defaultStaticDEXValue(s.typ))
			}
		}
		for _, m := range f.Methods {
			idx := pools.method(f.Class, m.Name, m.Params, m.Return)
			mo := &asmMethodOut{idx: idx, acc: m.Access}
			for _, a := range m.Annotations {
				da, err := pools.internAnnotation(a)
				if err != nil {
					return nil, err
				}
				mo.ann = append(mo.ann, da)
			}
			if len(m.ParamAnnots) > 0 {
				mo.params = make([][]DEXAnnotation, len(m.Params))
				for k, list := range m.ParamAnnots {
					if k < 0 || k >= len(m.Params) {
						return nil, fmt.Errorf("%s: method %s: parameter annotation index %d out of range", f.Path, m.Name, k)
					}
					for _, a := range list {
						da, err := pools.internAnnotation(a)
						if err != nil {
							return nil, err
						}
						mo.params[k] = append(mo.params[k], da)
					}
				}
			}
			abstractOrNative := m.Access&0x0400 != 0 || m.Access&0x0100 != 0
			if !abstractOrNative {
				code, err := assembleMethod(pools, m, f.Class)
				if err != nil {
					if isUnsupported(err) {
						return nil, err
					}
					return nil, fmt.Errorf("%s: method %s: %v", f.Path, m.Name, err)
				}
				mo.code = code
			} else if len(m.Lines) > 0 || m.Registers >= 0 {
				return nil, fmt.Errorf("%s: method %s: abstract/native method cannot contain code", f.Path, m.Name)
			}
			if m.Access&0x0008 != 0 || m.Access&0x0002 != 0 || m.Access&0x10000 != 0 {
				c.directM = append(c.directM, mo)
			} else {
				c.virtualM = append(c.virtualM, mo)
			}
		}
		sort.Slice(c.staticF, func(i, j int) bool { return c.staticF[i].idx < c.staticF[j].idx })
		sort.Slice(c.instanceF, func(i, j int) bool { return c.instanceF[i].idx < c.instanceF[j].idx })
		sort.Slice(c.directM, func(i, j int) bool { return c.directM[i].idx < c.directM[j].idx })
		sort.Slice(c.virtualM, func(i, j int) bool { return c.virtualM[i].idx < c.virtualM[j].idx })
	}
	sort.Slice(out, func(i, j int) bool { return out[i].typeIdx < out[j].typeIdx })
	return out, nil
}
