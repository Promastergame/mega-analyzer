package il2cpp

import (
	"bytes"
	"fmt"
	"sort"
)

// Il2CppTypeEnum values (ELEMENT_TYPE_*).
const (
	tyEnd        = 0x00
	tyVoid       = 0x01
	tyBoolean    = 0x02
	tyChar       = 0x03
	tyI1         = 0x04
	tyU1         = 0x05
	tyI2         = 0x06
	tyU2         = 0x07
	tyI4         = 0x08
	tyU4         = 0x09
	tyI8         = 0x0A
	tyU8         = 0x0B
	tyR4         = 0x0C
	tyR8         = 0x0D
	tyString     = 0x0E
	tyPtr        = 0x0F
	tyByref      = 0x10
	tyValueType  = 0x11
	tyClass      = 0x12
	tyVar        = 0x13
	tyArray      = 0x14
	tyGenericIn  = 0x15
	tyTypedByRef = 0x16
	tyI          = 0x18
	tyU          = 0x19
	tyFnPtr      = 0x1B
	tyObject     = 0x1C
	tySzArray    = 0x1D
	tyMVar       = 0x1E
	tyInternal   = 0x21
)

var knownTypeKinds = map[byte]bool{
	tyVoid: true, tyBoolean: true, tyChar: true, tyI1: true, tyU1: true,
	tyI2: true, tyU2: true, tyI4: true, tyU4: true, tyI8: true, tyU8: true,
	tyR4: true, tyR8: true, tyString: true, tyPtr: true, tyByref: true,
	tyValueType: true, tyClass: true, tyVar: true, tyArray: true,
	tyGenericIn: true, tyTypedByRef: true, tyI: true, tyU: true, tyFnPtr: true,
	tyObject: true, tySzArray: true, tyMVar: true, tyInternal: true,
}

// CType is one Il2CppType record resolved from the binary.
type CType struct {
	Data uint64
	Bits uint32
	b    *Binary
}

// Ty returns the ELEMENT_TYPE byte.
func (t *CType) Ty() byte { return byte(t.Bits >> 16 & 0xFF) }

// Attrs returns the 16 attribute bits (field/parameter modifiers).
func (t *CType) Attrs() uint16 { return uint16(t.Bits & 0xFFFF) }

// Byref reports the by-ref flag (27.2+ bit layout).
func (t *CType) Byref() bool { return t.Bits>>29&1 == 1 }

func (t *CType) isClassKind() bool { ty := t.Ty(); return ty == tyClass || ty == tyValueType }

// Binary couples the parsed metadata with the native libil2cpp image and
// recovers everything the metadata alone cannot express: full type
// signatures, generic instantiations and per-method code addresses.
type Binary struct {
	Metadata *Metadata
	elf      *ELF
	ptrSize  int

	typesPtr uint64 // vaddr of the Il2CppType* pointer array (or flat records pre-v38)
	numTypes int64
	flat     bool // pre-v38: typesPtr addresses records directly
	metareg  *metadataRegistration
	modules  []*codegenModule // parallel to Metadata.Images (nil if missing)

	typeCache map[int32]*CType
	gcCache   map[uint64]*genericClass

	Diagnostics []string
}

type metadataRegistration struct {
	base            uint64
	genericClasses  uint64
	genericInsts    uint64
	numTypes        int64
	typesPtr        uint64
	fieldOffsets    uint64
	fieldOffsetsCnt int64
}

type codegenModule struct {
	imageIdx     int32
	name         string
	methodPtrs   uint64
	methodPtrCnt uint64
	invokerIdx   uint64
}

type genericClass struct {
	typePtr uint64 // Il2CppType* of the generic type definition
	inst    uint64 // Il2CppGenericInst* (__generic_inst)
}

// AttachBinary links a native libil2cpp image to parsed metadata.
func AttachBinary(m *Metadata, elfData []byte) (*Binary, error) {
	elf, err := ParseELF(elfData)
	if err != nil {
		return nil, err
	}
	b := &Binary{
		Metadata:  m,
		elf:       elf,
		ptrSize:   8,
		typeCache: make(map[int32]*CType, 1<<16),
		gcCache:   make(map[uint64]*genericClass, 1<<15),
	}
	if !elf.Is64 {
		b.ptrSize = 4
	}
	b.locateTypesPointerArray()
	b.locateMetadataRegistration()
	b.locateCodegenModules()
	return b, nil
}

// maxTypeIndex scans the metadata for the highest referenced type index.
func (b *Binary) maxTypeIndex() int64 {
	m := b.Metadata
	max := int64(-1)
	note := func(idx int32) {
		if int64(idx) > max {
			max = int64(idx)
		}
	}
	for i := range m.TypeDefs {
		note(m.TypeDefs[i].ByvalType)
		note(m.TypeDefs[i].Parent)
		if m.Version < Ver27 {
			note(m.TypeDefs[i].DeclaringType)
		}
	}
	for i := range m.Fields {
		note(m.Fields[i].TypeIdx)
	}
	for i := range m.Methods {
		note(m.Methods[i].ReturnType)
	}
	for i := range m.Params {
		note(m.Params[i].TypeIdx)
	}
	for i := range m.Events {
		note(m.Events[i].TypeIdx)
	}
	for _, l := range m.InterfaceLists {
		for _, idx := range l {
			note(idx)
		}
	}
	return max
}

// looksLikeCType validates 12 bytes at va as an Il2CppType record under the
// metadata's constraints (typedef indices in range, primitives carry no data).
func (b *Binary) looksLikeCType(va uint64) bool {
	raw := b.elf.ReadBytes(va, 12)
	if raw == nil {
		return false
	}
	bits := leU32(raw[8:])
	ty := byte(bits >> 16 & 0xFF)
	if !knownTypeKinds[ty] {
		return false
	}
	var data uint64
	if v, ok := b.elf.RelocValue(va); ok {
		data = v
	} else {
		data = leU64(raw)
	}
	switch ty {
	case tyValueType, tyClass:
		return int64(data) < int64(len(b.Metadata.TypeDefs))
	case tyVar, tyMVar:
		return int64(data) < int64(len(b.Metadata.GenericParams))
	default:
		// v38+ primitive records may carry auxiliary data, so the ELEMENT_TYPE
		// byte alone gates acceptance; run length filters the noise.
		return true
	}
}

// locateTypesPointerArray scans alloc data sections for the type table.
// v38+ stores an array of pointers to scattered Il2CppType records; older
// versions keep one flat records array. Both are found by validating long
// runs: pointer slots must relocate to record-looking targets, flat records
// must validate in place.
func (b *Binary) locateTypesPointerArray() {
	minRun := 128
	if need := b.maxTypeIndex() + 1; need > int64(minRun) {
		minRun = int(need)
	}
	// Mode A: v38+ pointer array.
	bestStart, bestLen := uint64(0), 0
	for _, sec := range b.elf.Sections() {
		if !sec.IsAllocData() || sec.Size < uint64(minRun)*8 || sec.Off+sec.Size > uint64(len(b.elf.Data)) {
			continue
		}
		run := 0
		runStart := uint64(0)
		for off := uint64(0); off+8 <= sec.Size; off += 8 {
			slotVA := sec.Addr + off
			target, ok := b.elf.RelocValue(slotVA)
			valid := ok && b.looksLikeCType(target)
			if valid {
				if run == 0 {
					runStart = slotVA
				}
				run++
			} else {
				if run > bestLen {
					bestLen, bestStart = run, runStart
				}
				run = 0
			}
		}
		if run > bestLen {
			bestLen, bestStart = run, runStart
		}
	}
	if bestLen >= minRun {
		b.typesPtr = bestStart
		b.numTypes = int64(bestLen)
		b.Diagnostics = append(b.Diagnostics,
			fmt.Sprintf("types: pointer array at 0x%X with %d entries", bestStart, bestLen))
		return
	}
	// Mode B: flat records array (pre-v38 layout).
	entry := 16
	if b.ptrSize == 4 {
		entry = 8
	}
	bestStart, bestLen = uint64(0), 0
	for _, sec := range b.elf.Sections() {
		if !sec.IsAllocData() || sec.Size < uint64(minRun)*uint64(entry) || sec.Off+sec.Size > uint64(len(b.elf.Data)) {
			continue
		}
		for phase := uint64(0); phase < uint64(entry); phase += 8 {
			run := 0
			runStart := uint64(0)
			for off := phase; off+uint64(entry) <= sec.Size; off += uint64(entry) {
				rec := sec.Addr + off
				if b.looksLikeCType(rec) {
					if run == 0 {
						runStart = rec
					}
					run++
				} else {
					if run > bestLen {
						bestLen, bestStart = run, runStart
					}
					run = 0
				}
			}
			if run > bestLen {
				bestLen, bestStart = run, runStart
			}
		}
	}
	if bestLen >= minRun {
		b.typesPtr = bestStart
		b.numTypes = int64(bestLen)
		b.flat = true
		b.Diagnostics = append(b.Diagnostics,
			fmt.Sprintf("types: flat records at 0x%X with %d entries", bestStart, bestLen))
		return
	}
	b.Diagnostics = append(b.Diagnostics,
		fmt.Sprintf("types: no table found (best run %d < required %d)", bestLen, minRun))
}

// locateMetadataRegistration finds the registration struct through a slot
// pointing at the types array: metareg.typesPtr sits at struct offset +56.
func (b *Binary) locateMetadataRegistration() {
	if b.typesPtr == 0 {
		return
	}
	for _, slot := range b.elf.SlotsWithValue(b.typesPtr) {
		base := slot - 7*8
		if base == 0 {
			continue
		}
		numTypes := int64(b.elf.Qword(base + 6*8))
		if numTypes != b.numTypes {
			continue
		}
		fieldOffCnt := int64(b.elf.Qword(base + 10*8))
		if fieldOffCnt != int64(len(b.Metadata.TypeDefs)) && fieldOffCnt > 0 {
			// Some builds keep per-image offsets; accept any sane count.
			if fieldOffCnt < 0 || fieldOffCnt > 8*int64(len(b.Metadata.TypeDefs)) {
				continue
			}
		}
		reg := &metadataRegistration{
			base:            base,
			genericClasses:  b.elf.Qword(base + 1*8),
			genericInsts:    b.elf.Qword(base + 3*8),
			numTypes:        numTypes,
			typesPtr:        b.elf.Qword(base + 7*8),
			fieldOffsets:    b.elf.Qword(base + 11*8),
			fieldOffsetsCnt: fieldOffCnt,
		}
		b.metareg = reg
		b.Diagnostics = append(b.Diagnostics,
			fmt.Sprintf("metadata registration at 0x%X (types=0x%X genericClasses=0x%X genericInsts=0x%X fieldOffsets=0x%X/%d)",
				base, reg.typesPtr, reg.genericClasses, reg.genericInsts, reg.fieldOffsets, reg.fieldOffsetsCnt))
		return
	}
	b.Diagnostics = append(b.Diagnostics, "metadata registration: not located (generic instantiations will render without arguments)")
}

// locateCodegenModules matches every metadata image to its Il2CppCodeGenModule
// in the binary. The scan anchors on the module name string and validates the
// method pointer count against the image's highest method RID.
func (b *Binary) locateCodegenModules() {
	m := b.Metadata
	b.modules = make([]*codegenModule, len(m.Images))
	for imgIdx := range m.Images {
		img := &m.Images[imgIdx]
		name := m.Str.Get(img.NameIdx)
		if name == "" {
			continue
		}
		for _, strVA := range b.findCString(name) {
			for _, slot := range b.elf.SlotsWithValue(strVA) {
				count := b.elf.Qword(slot + 8) // methodPointerCount (raw value)
				if count == 0 || count > 8_000_000 {
					continue
				}
				if img.MethodRidMax != 0 && count != uint64(img.MethodRidMax) {
					continue
				}
				ptrs, ok := b.elf.RelocValue(slot + 16)
				if !ok {
					continue
				}
				invoker, _ := b.elf.RelocValue(slot + 40)
				b.modules[imgIdx] = &codegenModule{
					imageIdx:     int32(imgIdx),
					name:         name,
					methodPtrCnt: count,
					methodPtrs:   ptrs,
					invokerIdx:   invoker,
				}
				break
			}
			if b.modules[imgIdx] != nil {
				break
			}
		}
	}
	found := 0
	for _, mod := range b.modules {
		if mod != nil {
			found++
		}
	}
	b.Diagnostics = append(b.Diagnostics,
		fmt.Sprintf("codegen modules: %d/%d matched", found, len(m.Images)))
}

// findCString locates NUL-terminated string occurrences in read-only sections.
func (b *Binary) findCString(s string) []uint64 {
	needle := append([]byte(s), 0)
	var out []uint64
	for _, sec := range b.elf.Sections() {
		if !sec.IsAllocData() || sec.Off+sec.Size > uint64(len(b.elf.Data)) {
			continue
		}
		blob := b.elf.Data[sec.Off : sec.Off+sec.Size]
		start := 0
		for {
			i := bytes.Index(blob[start:], needle)
			if i < 0 {
				break
			}
			out = append(out, sec.Addr+uint64(start+i))
			start += i + 1
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Type resolves a type index from the metadata through the binary's table.
// The returned record may be nil when the binary side could not be located.
func (b *Binary) Type(idx int32) *CType {
	if idx < 0 || b.typesPtr == 0 || int64(idx) >= b.numTypes {
		return nil
	}
	if t, ok := b.typeCache[idx]; ok {
		return t
	}
	rec := b.typesPtr + uint64(idx)*uint64(b.typeStride())
	if !b.flat {
		rec = b.elf.Qword(rec) // pointer (relocated) to the scattered record
	}
	if rec == 0 {
		return nil
	}
	raw := b.elf.ReadBytes(rec, 12)
	if raw == nil {
		return nil
	}
	t := &CType{Bits: leU32(raw[8:]), b: b}
	if v, ok := b.elf.RelocValue(rec); ok {
		t.Data = v
	} else {
		t.Data = leU64(raw)
	}
	b.typeCache[idx] = t
	return t
}

func (b *Binary) typeStride() int {
	if b.flat {
		if b.ptrSize == 4 {
			return 8
		}
		return 16
	}
	return 8
}

// TypesResolved reports whether the binary type table was located.
func (b *Binary) TypesResolved() bool { return b.typesPtr != 0 }

// GenericClass resolves an Il2CppGenericClass pointer.
func (b *Binary) GenericClass(ptr uint64) *genericClass {
	if ptr == 0 {
		return nil
	}
	if gc, ok := b.gcCache[ptr]; ok {
		return gc
	}
	raw := b.elf.ReadBytes(ptr, 24)
	if raw == nil {
		return nil
	}
	gc := &genericClass{}
	gc.typePtr = b.elf.Qword(ptr)
	gc.inst = b.elf.Qword(ptr + 8)
	if !b.looksLikeCType(gc.typePtr) {
		return nil
	}
	b.gcCache[ptr] = gc
	return gc
}

// GenericInstTypes expands an Il2CppGenericInst pointer into its type records.
func (b *Binary) GenericInstTypes(inst uint64) []*CType {
	if inst == 0 {
		return nil
	}
	count := int64(b.elf.Qword(inst))
	start := b.elf.Qword(inst + 8)
	if count <= 0 || count > 256 || start == 0 {
		return nil
	}
	out := make([]*CType, 0, count)
	for i := int64(0); i < count; i++ {
		tp := b.elf.Qword(start + uint64(i)*8)
		if tp == 0 {
			return nil
		}
		raw := b.elf.ReadBytes(tp, 12)
		if raw == nil {
			return nil
		}
		t := &CType{Bits: leU32(raw[8:]), b: b}
		if v, ok := b.elf.RelocValue(tp); ok {
			t.Data = v
		} else {
			t.Data = leU64(raw)
		}
		out = append(out, t)
	}
	return out
}

// ArrayShape describes a multidimensional array type (ELEMENT_TYPE_ARRAY).
type ArrayShape struct {
	Rank     uint8
	ElemType *CType
}

// ArrayShape reads the Il2CppArrayType record a CType points at.
func (b *Binary) ArrayShape(t *CType) *ArrayShape {
	if t == nil || t.Ty() != tyArray || t.Data == 0 {
		return nil
	}
	raw := b.elf.ReadBytes(t.Data, 11)
	if raw == nil {
		return nil
	}
	elemPtr := b.elf.Qword(t.Data)
	rank := raw[8]
	if elemPtr == 0 || rank == 0 || rank > 64 {
		return nil
	}
	elemRaw := b.elf.ReadBytes(elemPtr, 12)
	if elemRaw == nil {
		return nil
	}
	elem := &CType{Bits: leU32(elemRaw[8:]), b: b}
	if v, ok := b.elf.RelocValue(elemPtr); ok {
		elem.Data = v
	} else {
		elem.Data = leU64(elemRaw)
	}
	return &ArrayShape{Rank: rank, ElemType: elem}
}

// MethodPointer returns the native code address for a method in the image
// (0 when the module or the pointer is absent).
func (b *Binary) MethodPointer(imageIdx int32, rid uint32) uint64 {
	if imageIdx < 0 || int(imageIdx) >= len(b.modules) {
		return 0
	}
	mod := b.modules[imageIdx]
	if mod == nil || mod.methodPtrs == 0 || rid == 0 || uint64(rid) > mod.methodPtrCnt {
		return 0
	}
	return b.elf.Qword(mod.methodPtrs + uint64(rid-1)*8)
}

// MethodPointerCount returns the located method pointer table size for the image.
func (b *Binary) MethodPointerCount(imageIdx int32) uint64 {
	if imageIdx < 0 || int(imageIdx) >= len(b.modules) || b.modules[imageIdx] == nil {
		return 0
	}
	return b.modules[imageIdx].methodPtrCnt
}

// FieldOffsets reads per-typedef field offsets (instance field slots) when the
// metadata registration was located.
func (b *Binary) FieldOffsets(typeIdx int32, fieldCount int) []int32 {
	if b.metareg == nil || b.metareg.fieldOffsets == 0 || fieldCount <= 0 {
		return nil
	}
	if typeIdx < 0 || int64(typeIdx) >= b.metareg.fieldOffsetsCnt {
		return nil
	}
	arr := b.elf.Qword(b.metareg.fieldOffsets + uint64(typeIdx)*8)
	if arr == 0 {
		return nil
	}
	raw := b.elf.ReadBytes(arr, fieldCount*4)
	if raw == nil {
		return nil
	}
	out := make([]int32, fieldCount)
	for i := range out {
		out[i] = int32(leU32(raw[i*4:]))
	}
	return out
}

// TypeDefOfCType maps a CLASS/VALUETYPE record back to its typedef.
func (b *Binary) TypeDefOfCType(t *CType) *TypeDefinition {
	if t == nil || !t.isClassKind() {
		return nil
	}
	idx := int32(t.Data)
	if idx < 0 || int(idx) >= len(b.Metadata.TypeDefs) {
		return nil
	}
	return &b.Metadata.TypeDefs[idx]
}

// BaseCTypeDef returns the typedef a record refers to, unwrapping generic
// instantiations, pointers and arrays.
func (b *Binary) BaseCTypeDef(t *CType) *TypeDefinition {
	for depth := 0; t != nil && depth < 8; depth++ {
		switch t.Ty() {
		case tyClass, tyValueType:
			return b.TypeDefOfCType(t)
		case tyGenericIn:
			if gc := b.GenericClass(t.Data); gc != nil {
				if raw := b.elf.ReadBytes(gc.typePtr, 12); raw != nil {
					inner := &CType{Bits: leU32(raw[8:]), b: b}
					if v, ok := b.elf.RelocValue(gc.typePtr); ok {
						inner.Data = v
					} else {
						inner.Data = leU64(raw)
					}
					t = inner
					continue
				}
			}
			return nil
		case tyPtr, tySzArray:
			innerPtr := t.Data
			if innerPtr == 0 {
				return nil
			}
			raw := b.elf.ReadBytes(innerPtr, 12)
			if raw == nil {
				return nil
			}
			next := &CType{Bits: leU32(raw[8:]), b: b}
			if v, ok := b.elf.RelocValue(innerPtr); ok {
				next.Data = v
			} else {
				next.Data = leU64(raw)
			}
			t = next
		case tyArray:
			if shape := b.ArrayShape(t); shape != nil {
				t = shape.ElemType
				continue
			}
			return nil
		default:
			return nil
		}
	}
	return nil
}

func leU32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func leU64(b []byte) uint64 {
	return uint64(leU32(b)) | uint64(leU32(b[4:]))<<32
}
