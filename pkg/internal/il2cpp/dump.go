package il2cpp

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"strings"
)

// Analyzed is the combined metadata + binary view of one IL2CPP build.
type Analyzed struct {
	Meta *Metadata
	Bin  *Binary // nil when the native image is missing or unusable
	nr   *nameResolver
}

// Analyze parses metadata bytes and (optionally) attaches the native binary.
func Analyze(metaData []byte, binData []byte, unityVersion string) (*Analyzed, error) {
	m, err := ParseMetadata(metaData, unityVersion)
	if err != nil {
		return nil, err
	}
	a := &Analyzed{Meta: m}
	a.nr = newNameResolver(m, nil)
	if len(binData) > 0 {
		if b, berr := AttachBinary(m, binData); berr == nil {
			a.Bin = b
			a.nr = newNameResolver(m, b)
		} else if m.Unity == "" {
			// keep metadata-only results; the binary may simply be stripped
			// or packed in a way we cannot scan
			m.Unity = ""
		}
	}
	return a, nil
}

// Diagnostics forwards binary-side scan notes (possibly empty).
func (a *Analyzed) Diagnostics() []string {
	if a.Bin != nil {
		return a.Bin.Diagnostics
	}
	return nil
}

// WriteDump emits an Il2CppDumper-style C# declaration dump.
func (a *Analyzed) WriteDump(w io.Writer) {
	bw := bufio.NewWriterSize(w, 1<<20)
	defer bw.Flush()

	m := a.Meta
	fmt.Fprintf(bw, "// Unity metadata version: %d (%.2f)\n", m.RawVersion, m.Version)
	if m.Unity != "" {
		fmt.Fprintf(bw, "// Unity engine version: %s\n", m.Unity)
	}
	if a.Bin != nil {
		for _, d := range a.Bin.Diagnostics {
			fmt.Fprintf(bw, "// Binary: %s\n", d)
		}
	} else {
		fmt.Fprintf(bw, "// Binary: libil2cpp not attached; signatures and RVAs are unavailable\n")
	}
	fmt.Fprintf(bw, "\n")

	for i, img := range m.Images {
		fmt.Fprintf(bw, "// Image %d: %s - %d\n", i, m.Str.Get(img.NameIdx), img.TypeCount)
	}
	for i, asm := range m.Assemblies {
		fmt.Fprintf(bw, "// Assembly %d: %s - %d.%d.%d.%d\n", i, m.Str.Get(asm.NameIdx), asm.Major, asm.Minor, asm.Build, asm.Revision)
	}
	fmt.Fprintf(bw, "\n")

	nested := a.nestedOwners()
	lastNamespace := "\x00"
	for imgIdx := range m.Images {
		img := &m.Images[imgIdx]
		fmt.Fprintf(bw, "// Image %d: %s\n\n", imgIdx, m.Str.Get(img.NameIdx))
		for ti := int64(0); ti < int64(img.TypeCount); ti++ {
			idx := img.FirstType + ti
			if idx < 0 || idx >= int64(len(m.TypeDefs)) {
				continue
			}
			td := &m.TypeDefs[idx]
			if _, isNested := nested[int32(idx)]; isNested {
				continue // emitted inside the declaring type
			}
			if ns := m.Str.Get(td.NamespaceIdx); ns != lastNamespace {
				fmt.Fprintf(bw, "// Namespace: %s\n", ns)
				lastNamespace = ns
			}
			a.writeType(bw, td, 0)
		}
	}
}

// nestedOwners maps typedef index -> declaring typedef index.
func (a *Analyzed) nestedOwners() map[int32]int32 {
	m := a.Meta
	owners := make(map[int32]int32)
	for i := range m.TypeDefs {
		td := &m.TypeDefs[i]
		if td.DeclaringType >= 0 {
			if m.Version < Ver27 || m.Version >= Ver38 {
				// pre-27 and v38+ store a type index
				if a.Bin != nil && m.Version >= Ver38 {
					if parent := a.Bin.TypeDefOfCType(a.Bin.Type(td.DeclaringType)); parent != nil {
						owners[int32(i)] = parent.index
						continue
					}
				} else if int(td.DeclaringType) < len(m.TypeDefs) {
					owners[int32(i)] = td.DeclaringType
					continue
				}
			}
		}
		// fallback: nested type lists
		for p := range m.TypeDefs {
			for _, n := range m.NestedTypeLists[p] {
				if int(n) == i {
					owners[int32(i)] = int32(p)
				}
			}
		}
	}
	// Keep the list-based result when the field was unusable.
	for i := range m.TypeDefs {
		for _, n := range m.NestedTypeLists[i] {
			if _, ok := owners[n]; !ok {
				owners[n] = int32(i)
			}
		}
	}
	return owners
}

func (a *Analyzed) writeType(bw *bufio.Writer, td *TypeDefinition, depth int) {
	m := a.Meta
	indent := strings.Repeat("\t", depth)
	name := a.nr.typeDisplayName(td)
	kind := "class"
	switch {
	case td.IsEnum():
		kind = "enum"
	case isInterface(td):
		kind = "interface"
	case td.IsValueType():
		kind = "struct"
	}
	var hdr []string
	if vis := typeVisibility(td); vis != "" && vis != "public " {
		hdr = append(hdr, vis)
	} else if vis == "public " || (td.Flags&0x1) == 1 {
		hdr = append(hdr, "public ")
	}
	if isAbstract(td) && !isInterface(td) && !td.IsEnum() {
		hdr = append(hdr, "abstract ")
	}
	if isSealed(td) && !td.IsValueType() && !a.nr.IsDelegate(td) {
		hdr = append(hdr, "sealed ")
	}
	head := strings.Join(hdr, "") + kind + " " + name

	if td.IsEnum() {
		head += " : " + a.enumUnderlyingName(td)
	} else if parent := a.nr.parentTypeDef(td); parent != nil && !td.IsValueType() {
		if pn := m.Str.Get(parent.NameIdx); pn != "Object" && pn != "ValueType" && pn != "Enum" {
			head += " : " + a.nr.typeDisplayName(parent)
		}
	}
	// Interfaces are appended through the metadata interface lists.
	ifaces := a.typeInterfaceNames(td)
	for _, in := range ifaces {
		head += ", " + in
	}
	fmt.Fprintf(bw, "%s%s // TypeDefIndex: %d - Image: %s\n", indent, head, td.index, m.Str.Get(m.Image(td.index).NameIdx))
	fmt.Fprintf(bw, "%s{\n", indent)

	a.writeFields(bw, td, indent)
	a.writeProperties(bw, td, indent)
	a.writeEvents(bw, td, indent)
	a.writeMethods(bw, td, indent)

	// Nested types render inside their declaring type.
	for _, child := range a.childrenOf(td) {
		fmt.Fprintf(bw, "\n")
		a.writeType(bw, &m.TypeDefs[child], depth+1)
	}
	fmt.Fprintf(bw, "%s}\n\n", indent)
}

func (a *Analyzed) childrenOf(td *TypeDefinition) []int32 {
	m := a.Meta
	if td.NestedCount == 0 {
		return nil
	}
	return m.NestedTypeLists[td.index]
}

func (a *Analyzed) typeInterfaceNames(td *TypeDefinition) []string {
	m := a.Meta
	list := m.InterfaceLists[td.index]
	if len(list) == 0 {
		return nil
	}
	var out []string
	for _, typeIdx := range list {
		if a.Bin == nil {
			continue
		}
		t := a.Bin.Type(typeIdx)
		if def := a.nr.typeDefOf(t); def != nil {
			n := m.Str.Get(def.NameIdx)
			if n != "" {
				out = append(out, a.nr.typeDisplayName(def))
			}
		}
	}
	return out
}

func (a *Analyzed) enumUnderlyingName(td *TypeDefinition) string {
	if t := a.nr.parentCType(td); t != nil {
		if n, ok := primitiveNames[t.Ty()]; ok {
			return n
		}
		if def := a.nr.typeDefOf(t); def != nil {
			return a.nr.typeDisplayName(def)
		}
	}
	return "int"
}

// enumUnderlyingKind returns the primitive ELEMENT_TYPE of an enum's
// underlying type (defaulting to I4 when unresolvable).
func (a *Analyzed) enumUnderlyingKind(td *TypeDefinition) byte {
	if t := a.nr.parentCType(td); t != nil {
		if _, ok := primitiveNames[t.Ty()]; ok {
			return t.Ty()
		}
	}
	return tyI4
}

func (a *Analyzed) writeFields(bw *bufio.Writer, td *TypeDefinition, indent string) {
	m := a.Meta
	if td.FieldCount == 0 {
		return
	}
	var offsets []int32
	if a.Bin != nil {
		offsets = a.Bin.FieldOffsets(td.index, int(td.FieldCount))
	}
	fmt.Fprintf(bw, "%s\t// Fields\n", indent)
	for i := int64(0); i < int64(td.FieldCount); i++ {
		fi := td.FirstField + i
		if fi < 0 || fi >= int64(len(m.Fields)) {
			break
		}
		f := &m.Fields[fi]
		fname := m.Str.Get(f.NameIdx)
		var ftype *CType
		var attrs uint16
		if a.Bin != nil {
			ftype = a.Bin.Type(f.TypeIdx)
			if ftype != nil {
				attrs = ftype.Attrs()
			}
		}
		offStr := ""
		if fieldIsStatic(attrs) {
			offStr = " // 0x0"
		} else if len(offsets) > int(i) {
			offStr = fmt.Sprintf(" // 0x%X", offsets[i])
		}
		if td.IsEnum() {
			if fname == "value__" {
				fmt.Fprintf(bw, "%s\tpublic %s value__; // 0x0\n", indent, a.nr.bareTypeName(td))
				continue
			}
			if fieldIsLiteral(attrs) && a.Bin != nil {
				if dv, ok := m.FieldDefaultByIdx[fi]; ok {
					fmt.Fprintf(bw, "%s\tpublic const %s %s = %s;\n", indent, a.nr.typeDisplayName(td), fname, a.formatDefault(dv.TypeIdx, dv.DataIdx, td))
					continue
				}
			}
			fmt.Fprintf(bw, "%s\tpublic const %s %s;\n", indent, a.nr.typeDisplayName(td), fname)
			continue
		}
		typeName := a.fieldTypeName(ftype, f)
		if fieldIsLiteral(attrs) && a.Bin != nil {
			if dv, ok := m.FieldDefaultByIdx[fi]; ok {
				fmt.Fprintf(bw, "%s\tpublic const %s %s = %s;\n", indent, typeName, fname, a.formatDefault(dv.TypeIdx, dv.DataIdx, nil))
				continue
			}
		}
		fmt.Fprintf(bw, "%s\t%s%s %s;%s\n", indent, fieldModifiers(attrs), typeName, fname, offStr)
	}
	fmt.Fprintf(bw, "%s\n", indent)
}

func (a *Analyzed) fieldTypeName(t *CType, f *FieldDefinition) string {
	if t == nil {
		return fmt.Sprintf("/*type#%d*/", f.TypeIdx)
	}
	return a.nr.TypeName(t)
}

func (a *Analyzed) writeProperties(bw *bufio.Writer, td *TypeDefinition, indent string) {
	m := a.Meta
	if td.PropCount == 0 {
		return
	}
	fmt.Fprintf(bw, "%s\t// Properties\n", indent)
	for i := int64(0); i < int64(td.PropCount); i++ {
		pi := td.FirstProperty + i
		if pi < 0 || pi >= int64(len(m.Properties)) {
			break
		}
		p := &m.Properties[pi]
		getter := a.methodAtRel(td, p.Get)
		setter := a.methodAtRel(td, p.Set)
		ptype, mods := a.propertySignature(getter, setter)
		accessors := ""
		if getter != nil {
			accessors += "get; "
		}
		if setter != nil {
			accessors += "set; "
		}
		fmt.Fprintf(bw, "%s\t%s%s %s { %s} // 0x%08X\n", indent, mods, ptype, m.Str.Get(p.NameIdx), accessors, p.Token&0xFFFFFF)
	}
	fmt.Fprintf(bw, "%s\n", indent)
}

func (a *Analyzed) propertySignature(getter, setter *MethodDefinition) (string, string) {
	if getter != nil {
		t := a.methodReturnType(getter)
		return a.nr.TypeName(t), methodModifiers(getter.Flags)
	}
	if setter != nil {
		if pt := a.methodParamType(setter, 0); pt != nil {
			return a.nr.TypeName(pt), methodModifiers(setter.Flags)
		}
	}
	return "object", "public "
}

func (a *Analyzed) writeEvents(bw *bufio.Writer, td *TypeDefinition, indent string) {
	m := a.Meta
	if td.EventCount == 0 {
		return
	}
	fmt.Fprintf(bw, "%s\t// Events\n", indent)
	for i := int64(0); i < int64(td.EventCount); i++ {
		ei := td.FirstEvent + i
		if ei < 0 || ei >= int64(len(m.Events)) {
			break
		}
		e := &m.Events[ei]
		etype := "EventHandler"
		if a.Bin != nil {
			if t := a.Bin.Type(e.TypeIdx); t != nil {
				etype = a.nr.TypeName(t)
			}
		}
		fmt.Fprintf(bw, "%s\tpublic event %s %s; // 0x%08X\n", indent, etype, m.Str.Get(e.NameIdx), e.Token&0xFFFFFF)
	}
	fmt.Fprintf(bw, "%s\n", indent)
}

func (a *Analyzed) writeMethods(bw *bufio.Writer, td *TypeDefinition, indent string) {
	m := a.Meta
	if td.MethodCount == 0 {
		return
	}
	fmt.Fprintf(bw, "%s\t// Methods\n", indent)
	for i := int64(0); i < int64(td.MethodCount); i++ {
		mi := td.FirstMethod + i
		if mi < 0 || mi >= int64(len(m.Methods)) {
			break
		}
		md := &m.Methods[mi]
		name := m.Str.Get(md.NameIdx)
		if md.GenericCont >= 0 && int(md.GenericCont) < len(m.GenericConts) {
			name += a.genericParamsSuffix(&m.GenericConts[md.GenericCont])
		}
		retType := a.nr.TypeName(a.methodReturnType(md))
		params := a.methodParams(md)

		var ptr uint64
		if a.Bin != nil {
			if imgIdx := m.ImageByType[md.DeclaringIdx]; imgIdx >= 0 {
				ptr = a.Bin.MethodPointer(imgIdx, md.RID())
			}
		}
		if ptr != 0 {
			fmt.Fprintf(bw, "%s\t// RVA: 0x%X VA: 0x%X", indent, ptr, ptr)
			if md.Slot != 0 && md.Slot != 0xFFFF {
				fmt.Fprintf(bw, " Slot: %d", md.Slot)
			}
			fmt.Fprintf(bw, "\n")
		}
		fmt.Fprintf(bw, "%s\t%s%s %s(%s) { }\n", indent, methodModifiers(md.Flags), retType, name, params)
	}
}

func (a *Analyzed) genericParamsSuffix(gc *GenericContainer) string {
	if gc.ParamCount <= 0 {
		return ""
	}
	m := a.Meta
	var parts []string
	for i := int64(0); i < int64(gc.ParamCount); i++ {
		pi := gc.ParamStart + i
		if pi >= 0 && pi < int64(len(m.GenericParams)) {
			parts = append(parts, m.Str.Get(m.GenericParams[pi].NameIdx))
		}
	}
	return "<" + strings.Join(parts, ", ") + ">"
}

func (a *Analyzed) methodReturnType(md *MethodDefinition) *CType {
	if a.Bin == nil {
		return nil
	}
	return a.Bin.Type(md.ReturnType)
}

func (a *Analyzed) methodParamType(md *MethodDefinition, i int64) *CType {
	if a.Bin == nil || md.ParamStart < 0 || md.ParamCount == 0 {
		return nil
	}
	pi := md.ParamStart + i
	if pi < 0 || pi >= int64(len(a.Meta.Params)) {
		return nil
	}
	return a.Bin.Type(a.Meta.Params[pi].TypeIdx)
}

func (a *Analyzed) methodParams(md *MethodDefinition) string {
	m := a.Meta
	if md.ParamCount == 0 || md.ParamStart < 0 {
		return ""
	}
	var parts []string
	for i := int64(0); i < int64(md.ParamCount); i++ {
		pi := md.ParamStart + i
		if pi < 0 || pi >= int64(len(m.Params)) {
			break
		}
		p := &m.Params[pi]
		ptype := "object"
		var attrs uint16
		if a.Bin != nil {
			if t := a.Bin.Type(p.TypeIdx); t != nil {
				attrs = t.Attrs()
				ptype = a.nr.TypeName(t)
			} else {
				ptype = fmt.Sprintf("/*type#%d*/", p.TypeIdx)
			}
		}
		suffix := ""
		if attrs&0x2 != 0 {
			suffix = " out"
		} else if attrs&0x1 != 0 && attrs&0x2 == 0 {
			suffix = ""
		}
		def := ""
		if a.Bin != nil && attrs&0x1000 != 0 {
			if dv, ok := m.ParamDefaultByIdx[pi]; ok {
				def = " = " + a.formatDefault(dv.TypeIdx, dv.DataIdx, nil)
			}
		}
		parts = append(parts, ptype+suffix+" "+m.Str.Get(p.NameIdx)+def)
	}
	return strings.Join(parts, ", ")
}

// methodAtRel resolves a method list-relative index (properties/events).
func (a *Analyzed) methodAtRel(td *TypeDefinition, rel int64) *MethodDefinition {
	if rel < 0 {
		return nil
	}
	mi := td.FirstMethod + rel
	if mi < 0 || mi >= int64(len(a.Meta.Methods)) {
		return nil
	}
	return &a.Meta.Methods[mi]
}

// formatDefault renders a constant from the default value data blob. Enum
// constants are stored at their underlying primitive width.
func (a *Analyzed) formatDefault(typeIdx int32, dataIdx int64, enumOwner *TypeDefinition) string {
	m := a.Meta
	if dataIdx < 0 {
		return "null"
	}
	var t *CType
	if a.Bin != nil {
		t = a.Bin.Type(typeIdx)
	}
	data := m.defaultData(dataIdx)
	kind := byte(0xFF)
	if t != nil {
		kind = t.Ty()
		// Resolve enums to their underlying primitive so the value width
		// matches the packed blob layout.
		if kind == tyValueType {
			if td := a.nr.typeDefOf(t); td != nil && td.IsEnum() {
				if m.Version < Ver35 && td.Element >= 0 && a.Bin != nil {
					if et := a.Bin.Type(td.Element); et != nil {
						kind = et.Ty()
					}
				} else {
					kind = a.enumUnderlyingKind(td)
				}
			}
		}
	}
	readU8 := func() uint8 {
		if len(data) < 1 {
			return 0
		}
		return data[0]
	}
	readI32 := func() int32 {
		if len(data) < 4 {
			return 0
		}
		return int32(binary.LittleEndian.Uint32(data))
	}
	readI64 := func() int64 {
		if len(data) < 8 {
			return 0
		}
		return int64(binary.LittleEndian.Uint64(data))
	}
	switch kind {
	case tyBoolean:
		if readU8() != 0 {
			return "true"
		}
		return "false"
	case tyChar:
		return fmt.Sprintf("'%c'", rune(readI32()))
	case tyI1:
		return fmt.Sprintf("%d", int8(readU8()))
	case tyU1:
		return fmt.Sprintf("%du", readU8())
	case tyI2:
		if len(data) < 2 {
			return "0"
		}
		return fmt.Sprintf("%d", int16(binary.LittleEndian.Uint16(data)))
	case tyU2:
		if len(data) < 2 {
			return "0"
		}
		return fmt.Sprintf("%du", binary.LittleEndian.Uint16(data))
	case tyI4:
		return fmt.Sprintf("%d", readI32())
	case tyU4:
		return fmt.Sprintf("%du", uint32(readI32()))
	case tyI8:
		return fmt.Sprintf("%dL", readI64())
	case tyU8:
		return fmt.Sprintf("%dul", uint64(readI64()))
	case tyR4:
		return fmt.Sprintf("%gf", math.Float32frombits(uint32(readI32())))
	case tyR8:
		return fmt.Sprintf("%g", math.Float64frombits(uint64(readI64())))
	case tyString:
		// string constants reference the metadata string table by index;
		// older formats inline a NUL-terminated copy in the data blob.
		if len(data) >= 4 {
			if idx := readI32(); idx >= 0 && idx < 1<<24 {
				if s := m.Str.Get(idx); s != "" {
					return fmt.Sprintf("%q", s)
				}
			}
		}
		for i, c := range data {
			if c == 0 {
				return fmt.Sprintf("%q", string(data[:i]))
			}
		}
		return "null"
	case tyClass:
		return "null"
	}
	if len(data) > 0 {
		return fmt.Sprintf("/*%d bytes*/", len(data))
	}
	return "null"
}

// DefaultDataRaw exposes raw constant bytes (debug/tests).
func (m *Metadata) DefaultDataRaw(idx int64) []byte { return m.defaultData(idx) }

func (m *Metadata) defaultData(idx int64) []byte {
	return m.sliceAt2(section{Off: m.secAt(m.sec.fieldAndParameterDefaultValueData).Off + idx, Size: 16})
}

// WriteStrings emits every managed string literal, one per line, with its
// metadata index. Useful for IOC extraction: URLs, keys, hidden switches.
func (a *Analyzed) WriteStrings(w io.Writer) {
	bw := bufio.NewWriterSize(w, 1<<20)
	defer bw.Flush()
	for _, lit := range a.Meta.StringLiterals {
		fmt.Fprintf(bw, "%d\t%s\n", lit.Idx, escapeCSharp(lit.Data))
	}
}

func escapeCSharp(b []byte) string {
	var sb strings.Builder
	const max = 4096
	for i, c := range b {
		if i >= max {
			sb.WriteString("...")
			break
		}
		switch c {
		case '\\':
			sb.WriteString("\\\\")
		case '\n':
			sb.WriteString("\\n")
		case '\r':
			sb.WriteString("\\r")
		case '\t':
			sb.WriteString("\\t")
		default:
			if c < 0x20 || c == 0x7F {
				fmt.Fprintf(&sb, "\\x%02X", c)
			} else {
				sb.WriteByte(c)
			}
		}
	}
	return sb.String()
}
