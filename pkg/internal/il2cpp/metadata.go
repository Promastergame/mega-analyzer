// Package il2cpp recovers C# type information from Unity IL2CPP builds by
// parsing global-metadata.dat together with the native libil2cpp binary.
// The metadata file carries every managed type, method, field and string
// literal name; the binary carries the Il2CppType table, method pointers and
// codegen module structures. Layout knowledge follows LibCpp2IL/Il2CppDumper
// and covers metadata versions 24 through 39 (Unity 2017.2 .. Unity 6.3).
package il2cpp

import (
	"encoding/binary"
	"fmt"
	"sort"
)

// MetadataVersion is a float32 following LibCpp2IL's synthetic sub-version
// scheme (24.15 = the 2018.4.34 hotfix layout, 29.1 = 2022.1b7, ...).
type MetadataVersion float32

const (
	Ver24   MetadataVersion = 24
	Ver24_1 MetadataVersion = 24.1
	Ver2415 MetadataVersion = 24.15
	Ver24_2 MetadataVersion = 24.2
	Ver24_3 MetadataVersion = 24.3
	Ver24_4 MetadataVersion = 24.4
	Ver24_5 MetadataVersion = 24.5
	Ver27   MetadataVersion = 27
	Ver27_1 MetadataVersion = 27.1
	Ver27_2 MetadataVersion = 27.2
	Ver29   MetadataVersion = 29
	Ver29_1 MetadataVersion = 29.1
	Ver31   MetadataVersion = 31
	Ver31_1 MetadataVersion = 31.1
	Ver35   MetadataVersion = 35
	Ver38   MetadataVersion = 38
	Ver39   MetadataVersion = 39
)

const metadataMagic = 0xFAB11BAF

// section describes one table inside global-metadata.dat.
type section struct {
	Off   int64
	Size  int64
	Count int64 // element count; 0 on versions < 38 (derive from Size)
}

type metadataHeader struct {
	rawVersion int32
	sections   []section
}

// Index of well-known sections, resolved once per version layout.
type sectionIndex struct {
	stringLiteral                        int
	stringLiteralData                    int
	str                                  int
	events                               int
	properties                           int
	methods                              int
	parameterDefaultValues               int
	fieldDefaultValues                   int
	fieldAndParameterDefaultValueData    int
	parameters                           int
	fields                               int
	genericParameters                    int
	genericParameterConstraints          int
	genericContainers                    int
	nestedTypes                          int
	interfaces                           int
	vtableMethods                        int
	interfaceOffsets                     int
	typeDefinitions                      int
	images                               int
	assemblies                           int
	fieldRefs                            int
	referencedAssemblies                 int
	attributeData                        int
	unresolvedVirtualCallParameterTypes  int
	unresolvedVirtualCallParameterRanges int
	exportedTypeDefinitions              int
}

// indexWidths holds the on-disk byte width of every variable-width index
// family. Legacy versions (< 38) keep everything at 4 bytes.
type indexWidths struct {
	typeDef          int // index into typeDefinitions
	genericContainer int // index into genericContainers
	typ              int // index into the binary's Il2CppType table
	parameter        int // index into parameters
	event            int // index into events
	property         int // index into properties
	nested           int // entries of the nestedTypes table
	method           int // index into methods
	field            int // index into fields
	genericParam     int // index into genericParameters
	defaultValueData int // index into fieldAndParameterDefaultValueData
	ifaceOffset      int // index into interfaceOffsets
}

func indexWidth(count int64) int {
	switch {
	case count <= 0xFF:
		return 1
	case count <= 0xFFFF:
		return 2
	default:
		return 4
	}
}

// TypeDefinition mirrors Il2CppTypeDefinition.
type TypeDefinition struct {
	NameIdx       int32
	NamespaceIdx  int32
	ByvalType     int32 // index into binary Il2CppType table (variable width on disk)
	DeclaringType int32 // type index on v38+, typedef index before
	Parent        int32 // type index on v38+, typedef index before
	Element       int32 // enum underlying type; removed in v35
	GenericCont   int32
	Flags         uint32
	FirstField    int64
	FirstMethod   int64
	FirstEvent    int64
	FirstProperty int64
	NestedStart   int64
	InterfacesSt  int64
	VtableStart   int64
	IfaceOffSt    int64
	MethodCount   uint16
	PropCount     uint16
	FieldCount    uint16
	EventCount    uint16
	NestedCount   uint16
	VtableCount   uint16
	IfaceCount    uint16
	IfaceOffCount uint16
	Bitfield      uint32
	Token         uint32

	index int32
}

func (t *TypeDefinition) IsValueType() bool { return t.Bitfield&1 == 1 }
func (t *TypeDefinition) IsEnum() bool      { return t.Bitfield>>1&1 == 1 }

// MethodDefinition mirrors Il2CppMethodDefinition.
type MethodDefinition struct {
	NameIdx      int32
	DeclaringIdx int32 // typedef index
	ReturnType   int32 // type index
	ParamStart   int64
	GenericCont  int32
	Token        uint32
	Flags        uint16
	IFlags       uint16
	Slot         uint16
	ParamCount   uint16
}

func (m *MethodDefinition) RID() uint32 { return m.Token & 0xFFFFFF }

// FieldDefinition mirrors Il2CppFieldDefinition.
type FieldDefinition struct {
	NameIdx int32
	TypeIdx int32
	Token   uint32
}

// ParameterDefinition mirrors Il2CppParameterDefinition.
type ParameterDefinition struct {
	NameIdx int32
	Token   uint32
	TypeIdx int32
}

// PropertyDefinition mirrors Il2CppPropertyDefinition.
type PropertyDefinition struct {
	NameIdx int32
	Get     int64
	Set     int64
	Attrs   uint32
	Token   uint32
}

// EventDefinition mirrors Il2CppEventDefinition.
type EventDefinition struct {
	NameIdx int32
	TypeIdx int32
	Add     int64
	Remove  int64
	Raise   int64
	Token   uint32
}

// ImageDefinition mirrors Il2CppImageDefinition (one managed assembly image).
type ImageDefinition struct {
	NameIdx      int32
	AssemblyIdx  int32
	FirstType    int64
	TypeCount    uint32
	EntryPoint   int64
	Token        uint32
	CustomAttrSt int32

	index        int32
	MethodRidMax uint32 // highest method RID in the image (codegen table size)
}

func (i *ImageDefinition) RID() uint32 { return i.Token & 0xFFFFFF }

// AssemblyDefinition mirrors Il2CppAssemblyDefinition.
type AssemblyDefinition struct {
	ImageIdx    int32
	RefStart    int32
	RefCount    int32
	NameIdx     int32
	CultureIdx  int32
	PublicKeyIx int32
	Major       int32
	Minor       int32
	Build       int32
	Revision    int32
	Token       uint64
}

// GenericContainer mirrors Il2CppGenericContainer.
type GenericContainer struct {
	OwnerIdx   int32
	ParamCount int32
	IsMethod   bool
	ParamStart int64
}

// GenericParameter mirrors Il2CppGenericParameter.
type GenericParameter struct {
	OwnerIdx int32
	NameIdx  int32
	Num      uint16
	Flags    uint16
}

// FieldDefaultValue mirrors Il2CppFieldDefaultValue.
type FieldDefaultValue struct {
	FieldIdx int64
	TypeIdx  int32
	DataIdx  int64
}

// ParameterDefaultValue mirrors Il2CppParameterDefaultValue.
type ParameterDefaultValue struct {
	ParamIdx int64
	TypeIdx  int32
	DataIdx  int64
}

// StringLiteral is one managed string constant; Data are raw UTF-8 bytes.
type StringLiteral struct {
	Idx  int32
	Data []byte
}

// Metadata is the parsed global-metadata.dat.
type Metadata struct {
	Version    MetadataVersion
	RawVersion int32
	Unity      string // best-effort engine version ("2022.3.10f1"), may be empty

	data   []byte
	header metadataHeader
	sec    sectionIndex
	widths indexWidths

	Str StringTable

	Images            []ImageDefinition
	Assemblies        []AssemblyDefinition
	TypeDefs          []TypeDefinition
	Methods           []MethodDefinition
	Fields            []FieldDefinition
	Params            []ParameterDefinition
	Properties        []PropertyDefinition
	Events            []EventDefinition
	GenericConts      []GenericContainer
	GenericParams     []GenericParameter
	FieldDefaults     []FieldDefaultValue
	ParamDefaults     []ParameterDefaultValue
	StringLiterals    []StringLiteral
	NestedTypeLists   [][]int32 // per typedef: nested typedef indices
	InterfaceLists    [][]int32 // per typedef: interface type indices
	ConstraintLists   [][]int32 // per generic param: constraint type indices
	FieldDefaultByIdx map[int64]FieldDefaultValue
	ParamDefaultByIdx map[int64]ParameterDefaultValue
	ImageByType       []int32 // typedef index -> image index
}

// StringTable reads null-terminated strings from the metadata string blob.
type StringTable struct {
	blob []byte
}

func (s StringTable) Get(idx int32) string {
	if idx < 0 || int64(idx) >= int64(len(s.blob)) {
		return ""
	}
	b := s.blob[idx:]
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// reader is a bounds-checked little-endian cursor over a byte slice.
type reader struct {
	b   []byte
	pos int
	err error
}

func (r *reader) u8() uint8 {
	if r.err != nil || r.pos+1 > len(r.b) {
		r.err = fmt.Errorf("metadata read out of bounds at %d", r.pos)
		return 0
	}
	v := r.b[r.pos]
	r.pos++
	return v
}

func (r *reader) u16() uint16 {
	if r.err != nil || r.pos+2 > len(r.b) {
		r.err = fmt.Errorf("metadata read out of bounds at %d", r.pos)
		return 0
	}
	v := binary.LittleEndian.Uint16(r.b[r.pos:])
	r.pos += 2
	return v
}

func (r *reader) u32() uint32 {
	if r.err != nil || r.pos+4 > len(r.b) {
		r.err = fmt.Errorf("metadata read out of bounds at %d", r.pos)
		return 0
	}
	v := binary.LittleEndian.Uint32(r.b[r.pos:])
	r.pos += 4
	return v
}

func (r *reader) i32() int32 { return int32(r.u32()) }

func (r *reader) u64() uint64 {
	if r.err != nil || r.pos+8 > len(r.b) {
		r.err = fmt.Errorf("metadata read out of bounds at %d", r.pos)
		return 0
	}
	v := binary.LittleEndian.Uint64(r.b[r.pos:])
	r.pos += 8
	return v
}

// varInt reads a variable-width index; -1 encodes null at every width.
func (r *reader) varInt(w int) int64 {
	switch w {
	case 1:
		v := r.u8()
		if v == 0xFF {
			return -1
		}
		return int64(v)
	case 2:
		v := r.u16()
		if v == 0xFFFF {
			return -1
		}
		return int64(v)
	default:
		return int64(r.i32())
	}
}

// ParseMetadata parses global-metadata.dat. unityVersion (optional, e.g.
// "2022.3.10f1") disambiguates sub-layouts for raw versions 24/27/29/31;
// without it the parser tries candidates and keeps the first that validates.
func ParseMetadata(data []byte, unityVersion string) (*Metadata, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("global-metadata.dat too small (%d bytes)", len(data))
	}
	if binary.LittleEndian.Uint32(data) != metadataMagic {
		return nil, fmt.Errorf("invalid metadata magic (file may be encrypted or protected); expected 0x%08X", metadataMagic)
	}
	raw := int32(binary.LittleEndian.Uint32(data[4:]))
	candidates := subVersions(raw, unityVersion)
	if candidates == nil {
		return nil, fmt.Errorf("unsupported metadata version %d (supported: 24..31, 35, 38, 39)", raw)
	}
	var lastErr error
	for _, v := range candidates {
		m, err := parseMetadataVersion(data, v, raw, unityVersion)
		if err == nil {
			return m, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("metadata version %d failed to parse", raw)
	}
	return nil, lastErr
}

func subVersions(raw int32, unity string) []MetadataVersion {
	switch raw {
	case 24:
		if u := unitySub(unity); u != 0 {
			return []MetadataVersion{u}
		}
		return []MetadataVersion{Ver24_5, Ver24_4, Ver24_3, Ver24_2, Ver2415, Ver24_1, Ver24}
	case 27:
		if u := unitySub(unity); u != 0 {
			return []MetadataVersion{u}
		}
		return []MetadataVersion{Ver27_2, Ver27_1, Ver27}
	case 29:
		if u := unitySub(unity); u != 0 {
			return []MetadataVersion{u}
		}
		return []MetadataVersion{Ver29_1, Ver29}
	case 31:
		if u := unitySub(unity); u != 0 {
			return []MetadataVersion{u}
		}
		return []MetadataVersion{Ver31_1, Ver31}
	case 23, 25, 26, 28, 30:
		return nil // not seen in the wild on Android
	case 35, 38, 39:
		return []MetadataVersion{MetadataVersion(raw)}
	default:
		if raw > 39 && raw <= 108 {
			return nil // newer Unity 6 layouts are not mapped yet
		}
		return nil
	}
}

// unitySub maps an engine version string to the exact metadata sub-layout.
func unitySub(unity string) MetadataVersion {
	mj, mn, pt, ok := parseUnityVersion(unity)
	if !ok {
		return 0
	}
	ge := func(major, minor, patch int) bool {
		return mj > major || (mj == major && (mn > minor || (mn == minor && pt >= patch)))
	}
	switch {
	case ge(2022, 3, 33):
		return Ver31_1
	case ge(2022, 1, 0):
		return Ver29_1
	case ge(2021, 1, 0):
		return Ver27_2
	case ge(2020, 2, 4):
		return Ver27_1
	case ge(2020, 2, 0):
		return Ver27
	case ge(2020, 1, 11):
		return Ver24_4
	case ge(2020, 1, 0):
		return Ver24_3
	case ge(2019, 4, 21):
		return Ver24_5
	case ge(2019, 4, 15):
		return Ver24_4
	case ge(2019, 3, 7):
		return Ver24_3
	case ge(2019, 1, 0):
		return Ver24_2
	case ge(2018, 4, 34):
		return Ver2415
	case ge(2018, 3, 0):
		return Ver24_1
	default:
		return Ver24
	}
}

// parseUnityVersion extracts the leading "major.minor.patch" from strings
// like "2022.3.33f1" or "6000.0.20f1".
func parseUnityVersion(s string) (major, minor, patch int, ok bool) {
	parts := [3]int{}
	p := 0
	acc := 0
	digits := 0
	for i := 0; i <= len(s) && p < 3; i++ {
		if i < len(s) && s[i] >= '0' && s[i] <= '9' {
			acc = acc*10 + int(s[i]-'0')
			digits++
			continue
		}
		if digits == 0 {
			return 0, 0, 0, false
		}
		parts[p] = acc
		p++
		acc, digits = 0, 0
		if i >= len(s) || s[i] != '.' {
			break
		}
	}
	if p < 3 {
		return 0, 0, 0, false
	}
	return parts[0], parts[1], parts[2], true
}

func parseMetadataVersion(data []byte, v MetadataVersion, raw int32, unity string) (*Metadata, error) {
	m := &Metadata{Version: v, RawVersion: raw, Unity: unity, data: data}
	if err := m.parseHeader(); err != nil {
		return nil, err
	}
	m.computeWidths()
	if err := m.parseTables(); err != nil {
		return nil, err
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	return m, nil
}

// parseHeader reads the section table, whose layout is version dependent.
func (m *Metadata) parseHeader() error {
	v := m.Version
	triples := v >= Ver38
	r := &reader{b: m.data, pos: 8}
	var read = func() section {
		s := section{Off: int64(r.i32()), Size: int64(r.i32())}
		if triples {
			s.Count = int64(r.i32())
		}
		return s
	}
	h := &m.header
	h.rawVersion = m.RawVersion
	sec := &m.sec
	add := func(dst *int) section {
		s := read()
		h.sections = append(h.sections, s)
		*dst = len(h.sections) - 1
		return s
	}
	add(&sec.stringLiteral)
	add(&sec.stringLiteralData)
	add(&sec.str)
	add(&sec.events)
	add(&sec.properties)
	add(&sec.methods)
	add(&sec.parameterDefaultValues)
	add(&sec.fieldDefaultValues)
	add(&sec.fieldAndParameterDefaultValueData)
	read() // fieldMarshaledSizes (unused)
	add(&sec.parameters)
	add(&sec.fields)
	add(&sec.genericParameters)
	add(&sec.genericParameterConstraints)
	add(&sec.genericContainers)
	add(&sec.nestedTypes)
	add(&sec.interfaces)
	read() // vtableMethods (unused)
	add(&sec.interfaceOffsets)
	add(&sec.typeDefinitions)
	if v <= Ver2415 {
		read() // rgctxEntries (<= 24.15)
	}
	add(&sec.images)
	add(&sec.assemblies)
	if v < Ver27 {
		read() // metadataUsageLists
		read() // metadataUsagePairs
	}
	add(&sec.fieldRefs)
	read() // referencedAssemblies (unused)
	if v < Ver29 {
		read() // attributesInfo
		read() // attributeTypes
	} else {
		read() // attributeData (raw blobs, not decoded)
		read() // attributeDataRange
	}
	read() // unresolvedVirtualCallParameterTypes
	read() // unresolvedVirtualCallParameterRanges
	read() // windowsRuntimeTypeNames
	if v >= Ver27 {
		read() // windowsRuntimeStrings
	}
	add(&sec.exportedTypeDefinitions)
	// v104+ adds typeInlineArrays and method-spec sections; the supported
	// new-version range ends at 39, so anything beyond is rejected earlier.
	if r.err != nil {
		return r.err
	}
	return nil
}

func (m *Metadata) secAt(i int) section { return m.header.sections[i] }

func (m *Metadata) computeWidths() {
	w := &m.widths
	if m.Version < Ver38 {
		*w = indexWidths{
			typeDef: 4, genericContainer: 4, typ: 4, parameter: 4, event: 4,
			property: 4, nested: 4, method: 4, field: 4, genericParam: 4,
			defaultValueData: 4, ifaceOffset: 4,
		}
		return
	}
	w.typeDef = indexWidth(m.secAt(m.sec.typeDefinitions).Count)
	w.genericContainer = indexWidth(m.secAt(m.sec.genericContainers).Count)
	iface := m.secAt(m.sec.interfaceOffsets)
	if iface.Count > 0 {
		w.typ = int(iface.Size/iface.Count) - 4
		if w.typ != 1 && w.typ != 2 && w.typ != 4 {
			w.typ = 4
		}
	} else {
		w.typ = 4
	}
	if m.Version >= Ver39 {
		w.parameter = indexWidth(m.secAt(m.sec.parameters).Count)
	}
	w.event, w.property, w.nested, w.method = 4, 4, 4, 4
	w.field, w.genericParam, w.defaultValueData = 4, 4, 4
	w.ifaceOffset = 4
}

func (m *Metadata) parseTables() error {
	v := m.Version
	w := m.widths

	m.Str = StringTable{blob: m.sliceAt(m.sec.str)}

	// Images & assemblies first: they anchor validation and type->image map.
	{
		r := &reader{b: m.entries(m.sec.images, m.imageDefSize())}
		for i := 0; r.err == nil && r.pos < len(r.b); i++ {
			img := ImageDefinition{index: int32(i)}
			img.NameIdx = r.i32()
			img.AssemblyIdx = r.i32()
			img.FirstType = r.varInt(w.typeDef)
			img.TypeCount = r.u32()
			if v >= Ver24 {
				_ = r.varInt(w.typeDef) // exportedTypeStart
				_ = r.u32()             // exportedTypeCount
			}
			img.EntryPoint = r.varInt(w.method)
			img.Token = r.u32()
			if v >= Ver24_1 {
				img.CustomAttrSt = r.i32()
				_ = r.u32() // customAttributeCount
			}
			m.Images = append(m.Images, img)
		}
		if r.err != nil {
			return fmt.Errorf("images table: %w", r.err)
		}
	}
	{
		asmSize := m.assemblyDefSize()
		r := &reader{b: m.entries(m.sec.assemblies, asmSize)}
		for r.err == nil && r.pos < len(r.b) {
			a := AssemblyDefinition{}
			a.ImageIdx = r.i32()
			if v >= Ver24_1 {
				_ = r.u32() // token
			}
			if v >= Ver38 {
				_ = r.u32() // moduleToken
			}
			if v < Ver24 {
				_ = r.i32() // customAttributeIndex
			}
			a.RefStart = r.i32()
			a.RefCount = r.i32()
			a.NameIdx = r.i32()
			a.CultureIdx = r.i32()
			if (v >= Ver24 && v <= Ver24_1) || (v >= Ver24_2 && v <= Ver24_3) {
				_ = r.i32() // hashValueIndex
			}
			a.PublicKeyIx = r.i32()
			_ = r.u32() // hash_alg
			_ = r.i32() // hash_len
			_ = r.u32() // flags
			a.Major = r.i32()
			a.Minor = r.i32()
			a.Build = r.i32()
			a.Revision = r.i32()
			a.Token = r.u64()
			m.Assemblies = append(m.Assemblies, a)
		}
		if r.err != nil {
			return fmt.Errorf("assemblies table: %w", r.err)
		}
	}

	// Type definitions.
	{
		b := m.entries(m.sec.typeDefinitions, m.typeDefSize())
		typeDefSize := m.typeDefSize()
		if typeDefSize <= 0 {
			return fmt.Errorf("typeDefinitions table: element size %d", typeDefSize)
		}
		count := len(b) / typeDefSize
		m.TypeDefs = make([]TypeDefinition, 0, count)
		r := &reader{b: b}
		for i := 0; i < count; i++ {
			t := TypeDefinition{index: int32(i)}
			t.NameIdx = r.i32()
			t.NamespaceIdx = r.i32()
			if v < Ver24 {
				_ = r.i32() // customAttributeIndex
			}
			t.ByvalType = int32(r.varInt(w.typ))
			if v < Ver27 {
				_ = r.i32() // byrefTypeIndex
			}
			t.DeclaringType = int32(r.varInt(w.typ))
			t.Parent = int32(r.varInt(w.typ))
			if v < Ver35 {
				t.Element = r.i32()
			}
			if v <= Ver2415 {
				_ = r.i32() // rgctxStart
				_ = r.i32() // rgctxCount
			}
			t.GenericCont = int32(r.varInt(w.genericContainer))
			t.Flags = r.u32()
			t.FirstField = r.varInt(w.field)
			t.FirstMethod = r.varInt(w.method)
			t.FirstEvent = r.varInt(w.event)
			t.FirstProperty = r.varInt(w.property)
			t.NestedStart = r.varInt(w.nested)
			t.InterfacesSt = r.varInt(w.typ)
			t.VtableStart = int64(r.i32())
			t.IfaceOffSt = r.varInt(w.ifaceOffset)
			t.MethodCount = r.u16()
			t.PropCount = r.u16()
			t.FieldCount = r.u16()
			t.EventCount = r.u16()
			t.NestedCount = r.u16()
			t.VtableCount = r.u16()
			t.IfaceCount = r.u16()
			t.IfaceOffCount = r.u16()
			t.Bitfield = r.u32()
			t.Token = r.u32()
			m.TypeDefs = append(m.TypeDefs, t)
		}
		if r.err != nil {
			return fmt.Errorf("typeDefinitions table: %w", r.err)
		}
	}

	// Methods.
	{
		b := m.entries(m.sec.methods, m.methodDefSize())
		size := m.methodDefSize()
		if size <= 0 {
			return fmt.Errorf("methods table: element size %d", size)
		}
		count := len(b) / size
		m.Methods = make([]MethodDefinition, 0, count)
		r := &reader{b: b}
		for i := 0; i < count; i++ {
			md := MethodDefinition{}
			md.NameIdx = r.i32()
			md.DeclaringIdx = int32(r.varInt(w.typeDef))
			md.ReturnType = int32(r.varInt(w.typ))
			if v >= Ver31 {
				_ = r.u32() // returnParameterToken
			}
			md.ParamStart = r.varInt(w.parameter)
			if v < Ver24 {
				_ = r.i32() // customAttributeIndex
			}
			md.GenericCont = int32(r.varInt(w.genericContainer))
			if v <= Ver2415 {
				_ = r.i32() // methodIndex
				_ = r.i32() // invokerIndex
				_ = r.i32() // delegateWrapperIndex
				_ = r.i32() // rgctxStart
				_ = r.i32() // rgctxCount
			}
			md.Token = r.u32()
			md.Flags = r.u16()
			md.IFlags = r.u16()
			md.Slot = r.u16()
			md.ParamCount = r.u16()
			m.Methods = append(m.Methods, md)
		}
		if r.err != nil {
			return fmt.Errorf("methods table: %w", r.err)
		}
	}

	// Fields.
	{
		fieldSize := 8 + w.typ
		if v < Ver24 {
			fieldSize += 4
		}
		r := &reader{b: m.entries(m.sec.fields, fieldSize)}
		for r.err == nil && r.pos < len(r.b) {
			f := FieldDefinition{}
			f.NameIdx = r.i32()
			f.TypeIdx = int32(r.varInt(w.typ))
			if v < Ver24 {
				_ = r.i32() // customAttributeIndex
			}
			f.Token = r.u32()
			m.Fields = append(m.Fields, f)
		}
		if r.err != nil {
			return fmt.Errorf("fields table: %w", r.err)
		}
	}

	// Parameters.
	{
		paramSize := 8 + w.typ
		if v < Ver24 {
			paramSize += 4
		}
		r := &reader{b: m.entries(m.sec.parameters, paramSize)}
		for r.err == nil && r.pos < len(r.b) {
			p := ParameterDefinition{}
			p.NameIdx = r.i32()
			p.Token = r.u32()
			if v < Ver24 {
				_ = r.i32() // customAttributeIndex
			}
			p.TypeIdx = int32(r.varInt(w.typ))
			m.Params = append(m.Params, p)
		}
		if r.err != nil {
			return fmt.Errorf("parameters table: %w", r.err)
		}
	}

	// Properties.
	{
		propSize := 12 + w.method*2
		if v < Ver24 {
			propSize += 4
		}
		r := &reader{b: m.entries(m.sec.properties, propSize)}
		for r.err == nil && r.pos < len(r.b) {
			p := PropertyDefinition{}
			p.NameIdx = r.i32()
			p.Get = r.varInt(w.method)
			p.Set = r.varInt(w.method)
			p.Attrs = r.u32()
			if v < Ver24 {
				_ = r.i32() // customAttributeIndex
			}
			p.Token = r.u32()
			m.Properties = append(m.Properties, p)
		}
		if r.err != nil {
			return fmt.Errorf("properties table: %w", r.err)
		}
	}

	// Events.
	{
		eventSize := 8 + w.typ + w.method*3
		if v < Ver24 {
			eventSize += 4
		}
		r := &reader{b: m.entries(m.sec.events, eventSize)}
		for r.err == nil && r.pos < len(r.b) {
			e := EventDefinition{}
			e.NameIdx = r.i32()
			e.TypeIdx = int32(r.varInt(w.typ))
			e.Add = r.varInt(w.method)
			e.Remove = r.varInt(w.method)
			e.Raise = r.varInt(w.method)
			if v < Ver24 {
				_ = r.i32() // customAttributeIndex
			}
			e.Token = r.u32()
			m.Events = append(m.Events, e)
		}
		if r.err != nil {
			return fmt.Errorf("events table: %w", r.err)
		}
	}

	// Generic containers & parameters.
	{
		r := &reader{b: m.entries(m.sec.genericContainers, 12+w.genericParam)}
		for r.err == nil && r.pos < len(r.b) {
			g := GenericContainer{}
			g.OwnerIdx = r.i32()
			g.ParamCount = r.i32()
			g.IsMethod = r.i32() != 0
			g.ParamStart = r.varInt(w.genericParam)
			m.GenericConts = append(m.GenericConts, g)
		}
		if r.err != nil {
			return fmt.Errorf("genericContainers table: %w", r.err)
		}
	}
	{
		r := &reader{b: m.entries(m.sec.genericParameters, w.genericContainer+12)}
		for r.err == nil && r.pos < len(r.b) {
			g := GenericParameter{}
			g.OwnerIdx = int32(r.varInt(w.genericContainer))
			g.NameIdx = r.i32()
			_ = r.u16() // constraintsStart
			_ = r.u16() // constraintsCount
			g.Num = r.u16()
			g.Flags = r.u16()
			m.GenericParams = append(m.GenericParams, g)
		}
		if r.err != nil {
			return fmt.Errorf("genericParameters table: %w", r.err)
		}
	}

	// Default values (field & parameter constants).
	{
		dvSize := w.field + w.typ + w.defaultValueData
		r := &reader{b: m.entries(m.sec.fieldDefaultValues, dvSize)}
		for r.err == nil && r.pos < len(r.b) {
			d := FieldDefaultValue{}
			d.FieldIdx = r.varInt(w.field)
			d.TypeIdx = int32(r.varInt(w.typ))
			d.DataIdx = r.varInt(w.defaultValueData)
			m.FieldDefaults = append(m.FieldDefaults, d)
		}
		if r.err != nil {
			return fmt.Errorf("fieldDefaultValues table: %w", r.err)
		}
		m.FieldDefaultByIdx = make(map[int64]FieldDefaultValue, len(m.FieldDefaults))
		for _, d := range m.FieldDefaults {
			m.FieldDefaultByIdx[d.FieldIdx] = d
		}
	}
	{
		dvSize := w.parameter + w.typ + w.defaultValueData
		r := &reader{b: m.entries(m.sec.parameterDefaultValues, dvSize)}
		for r.err == nil && r.pos < len(r.b) {
			d := ParameterDefaultValue{}
			d.ParamIdx = r.varInt(w.parameter)
			d.TypeIdx = int32(r.varInt(w.typ))
			d.DataIdx = r.varInt(w.defaultValueData)
			m.ParamDefaults = append(m.ParamDefaults, d)
		}
		if r.err != nil {
			return fmt.Errorf("parameterDefaultValues table: %w", r.err)
		}
		m.ParamDefaultByIdx = make(map[int64]ParameterDefaultValue, len(m.ParamDefaults))
		for _, d := range m.ParamDefaults {
			m.ParamDefaultByIdx[d.ParamIdx] = d
		}
	}

	// Nested type lists and interface lists (variable-width entries on v38+).
	m.NestedTypeLists = make([][]int32, len(m.TypeDefs))
	m.InterfaceLists = make([][]int32, len(m.TypeDefs))
	{
		r := &reader{b: m.entries(m.sec.nestedTypes, w.nested)}
		var flat []int32
		for r.err == nil && r.pos < len(r.b) {
			flat = append(flat, int32(r.varInt(w.nested)))
		}
		for i := range m.TypeDefs {
			t := &m.TypeDefs[i]
			if t.NestedCount == 0 || t.NestedStart < 0 || int64(t.NestedStart)+int64(t.NestedCount) > int64(len(flat)) {
				continue
			}
			m.NestedTypeLists[i] = flat[t.NestedStart : int64(t.NestedStart)+int64(t.NestedCount)]
		}
	}
	{
		r := &reader{b: m.entries(m.sec.interfaces, w.typ)}
		var flat []int32
		for r.err == nil && r.pos < len(r.b) {
			flat = append(flat, int32(r.varInt(w.typ)))
		}
		for i := range m.TypeDefs {
			t := &m.TypeDefs[i]
			if t.IfaceCount == 0 || t.InterfacesSt < 0 || int64(t.InterfacesSt)+int64(t.IfaceCount) > int64(len(flat)) {
				continue
			}
			m.InterfaceLists[i] = flat[t.InterfacesSt : int64(t.InterfacesSt)+int64(t.IfaceCount)]
		}
	}

	// String literals.
	if err := m.parseStringLiterals(); err != nil {
		return err
	}

	// type -> image map + per-image method RID maximum (used to validate the
	// codegen module scan inside the binary).
	m.ImageByType = make([]int32, len(m.TypeDefs))
	for i := range m.ImageByType {
		m.ImageByType[i] = -1
	}
	for imgIdx := range m.Images {
		img := &m.Images[imgIdx]
		for i := int64(0); i < int64(img.TypeCount); i++ {
			ti := img.FirstType + i
			if ti >= 0 && ti < int64(len(m.TypeDefs)) {
				m.ImageByType[ti] = int32(imgIdx)
			}
		}
	}
	for i := range m.Methods {
		md := &m.Methods[i]
		if md.DeclaringIdx < 0 || int(md.DeclaringIdx) >= len(m.ImageByType) {
			continue
		}
		if imgIdx := m.ImageByType[md.DeclaringIdx]; imgIdx >= 0 {
			if rid := md.RID(); rid > m.Images[imgIdx].MethodRidMax {
				m.Images[imgIdx].MethodRidMax = rid
			}
		}
	}
	return nil
}

// assemblyDefSize computes the on-disk size of one Il2CppAssemblyDefinition
// including its trailing Il2CppAssemblyNameDefinition.
func (m *Metadata) assemblyDefSize() int {
	v := m.Version
	n := 4 // imageIndex
	if v >= Ver24_1 {
		n += 4 // token
	}
	if v >= Ver38 {
		n += 4 // moduleToken
	}
	if v < Ver24 {
		n += 4 // customAttributeIndex
	}
	n += 8 // referencedAssemblyStart + count
	// AssemblyNameDefinition
	n += 4 + 4 // nameIndex + cultureIndex
	if (v >= Ver24 && v <= Ver24_1) || (v >= Ver24_2 && v <= Ver24_3) {
		n += 4 // hashValueIndex
	}
	n += 4         // publicKeyIndex
	n += 4 + 4 + 4 // hash_alg + hash_len + flags
	n += 16        // major..revision
	n += 8         // publicKeyToken
	return n
}

// imageDefSize computes the on-disk size of one Il2CppImageDefinition.
func (m *Metadata) imageDefSize() int {
	v, w := m.Version, m.widths
	n := 8 // nameIndex + assemblyIndex
	n += w.typeDef
	n += 4 // typeCount
	if v >= Ver24 {
		n += w.typeDef + 4 // exportedTypeStart + count
	}
	n += w.method
	n += 4 // token
	if v >= Ver24_1 {
		n += 8 // customAttributeStart + count
	}
	return n
}

// typeDefSize computes the on-disk size of one Il2CppTypeDefinition.
func (m *Metadata) typeDefSize() int {
	v, w := m.Version, m.widths
	n := 4 + 4 // nameIndex + namespaceIndex
	if v < Ver24 {
		n += 4 // customAttributeIndex
	}
	n += w.typ // byval
	if v < Ver27 {
		n += 4 // byref
	}
	n += w.typ // declaring
	n += w.typ // parent
	if v < Ver35 {
		n += 4 // elementType
	}
	if v <= Ver2415 {
		n += 8 // rgctx start+count
	}
	n += w.genericContainer
	n += 4 // flags
	n += w.field + w.method + w.event + w.property
	n += w.nested + w.typ + 4 + w.ifaceOffset
	n += 16 // eight u16 counts
	n += 8  // bitfield + token
	return n
}

// methodDefSize computes the on-disk size of one Il2CppMethodDefinition.
func (m *Metadata) methodDefSize() int {
	v, w := m.Version, m.widths
	n := 4 // nameIndex
	n += w.typeDef
	n += w.typ
	if v >= Ver31 {
		n += 4 // returnParameterToken
	}
	n += w.parameter
	if v < Ver24 {
		n += 4 // customAttributeIndex
	}
	n += w.genericContainer
	if v <= Ver2415 {
		n += 5 * 4
	}
	n += 4 // token
	n += 8 // flags, iflags, slot, parameterCount
	return n
}

func (m *Metadata) parseStringLiterals() error {
	v := m.Version
	b := m.entries(m.sec.stringLiteral, 8) // 8 pre-v35, 4 after; trimmed below
	if v >= Ver35 {
		b = m.entries(m.sec.stringLiteral, 4)
	}
	dataSec := m.sliceAt(m.sec.stringLiteralData)
	if v < Ver35 {
		r := &reader{b: b}
		for r.err == nil && r.pos+8 <= len(r.b) {
			length := r.u32()
			idx := r.i32()
			if idx < 0 || int64(idx)+int64(length) > int64(len(dataSec)) {
				continue
			}
			m.StringLiterals = append(m.StringLiterals, StringLiteral{Idx: idx, Data: dataSec[idx : int64(idx)+int64(length)]})
		}
		return r.err
	}
	// v35+: entries store only the data offset; lengths come from the sorted
	// offsets so the packed blob can be sliced exactly.
	r := &reader{b: b}
	var offs []int32
	for r.err == nil && r.pos+4 <= len(r.b) {
		if idx := r.i32(); idx >= 0 {
			offs = append(offs, idx)
		}
	}
	if r.err != nil {
		return fmt.Errorf("stringLiteral table: %w", r.err)
	}
	sorted := make([]int32, len(offs))
	copy(sorted, offs)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	lengths := make(map[int32]int64, len(sorted))
	for i, off := range sorted {
		var end int64 = int64(len(dataSec))
		if i+1 < len(sorted) {
			end = int64(sorted[i+1])
		}
		if end > int64(len(dataSec)) {
			end = int64(len(dataSec))
		}
		if d := end - int64(off); d >= 0 {
			lengths[off] = d
		}
	}
	for _, off := range offs {
		l, ok := lengths[off]
		if !ok || l < 0 || int64(off)+l > int64(len(dataSec)) {
			continue
		}
		m.StringLiterals = append(m.StringLiterals, StringLiteral{Idx: off, Data: dataSec[off : int64(off)+l]})
	}
	return nil
}

func (m *Metadata) sliceAt(i int) []byte {
	s := m.secAt(i)
	return m.sliceAt2(s)
}

// sliceAt2 is sliceAt with a clearer name at call sites where the section is
// being consumed as a whole table.
func (m *Metadata) sliceAt2(s section) []byte {
	if s.Off < 0 || s.Size < 0 || s.Off+s.Size > int64(len(m.data)) {
		return nil
	}
	return m.data[s.Off : s.Off+s.Size]
}

// entries trims a table to exactly the declared element count on v38+ so
// trailing section padding does not materialise as a bogus record.
func (m *Metadata) entries(i, elemSize int) []byte {
	b := m.sliceAt(i)
	if b == nil || m.Version < Ver38 {
		return b
	}
	s := m.secAt(i)
	if s.Count <= 0 || elemSize <= 0 {
		return b
	}
	n := int64(elemSize) * s.Count
	if n > int64(len(b)) {
		return b
	}
	return b[:n]
}

// validate catches wrong sub-layout picks and lightly corrupted files before
// the binary side builds on top of the parsed tables.
func (m *Metadata) validate() error {
	if len(m.Images) == 0 || len(m.Assemblies) == 0 {
		return fmt.Errorf("no assembly images parsed")
	}
	if len(m.TypeDefs) < 2 {
		return fmt.Errorf("only %d type definitions parsed", len(m.TypeDefs))
	}
	dllNames := 0
	for _, img := range m.Images {
		name := m.Str.Get(img.NameIdx)
		if len(name) >= 4 && name[len(name)-4:] == ".dll" {
			dllNames++
		}
	}
	if dllNames*2 < len(m.Images) {
		return fmt.Errorf("only %d/%d image names look like assemblies", dllNames, len(m.Images))
	}
	badNames := 0
	for i, t := range m.TypeDefs {
		if i > 2000 {
			break
		}
		name := m.Str.Get(t.NameIdx)
		if name == "" && t.Token != 0 {
			badNames++
		}
	}
	if badNames > len(m.TypeDefs)/10 && badNames > 50 {
		return fmt.Errorf("%d of first typedefs have unresolvable names", badNames)
	}
	return nil
}

// Image returns the image a typedef belongs to, or nil.
func (m *Metadata) Image(typeIdx int32) *ImageDefinition {
	if typeIdx < 0 || int(typeIdx) >= len(m.ImageByType) {
		return nil
	}
	imgIdx := m.ImageByType[typeIdx]
	if imgIdx < 0 || int(imgIdx) >= len(m.Images) {
		return nil
	}
	return &m.Images[imgIdx]
}

// TypeFullName renders namespace.name for a typedef without generic info.
func (m *Metadata) TypeFullName(t *TypeDefinition) string {
	name := m.Str.Get(t.NameIdx)
	if ns := m.Str.Get(t.NamespaceIdx); ns != "" {
		return ns + "." + name
	}
	return name
}
