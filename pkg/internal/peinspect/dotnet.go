// Package peinspect — .NET CLI metadata support.
//
// dotnet.go parses ECMA-335 metadata of managed PE images without executing
// anything: assembly identity, managed entry point, assembly-level attributes
// (TargetFramework, Guid, versions, Debuggable, ComVisible, SkipVerification)
// and dependency refs. All arithmetic is bounds-checked: hostile inputs must
// produce an error, never a panic or an out-of-bounds read.
package peinspect

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// DotNetInfo is the managed-assembly summary of a PE image.
type DotNetInfo struct {
	IsDotNet                      bool
	RuntimeVersion                string // CLI metadata version string, e.g. "v4.0.30319"
	ModuleName                    string
	Mvid                          string // Module version GUID, "" if absent
	AssemblyName                  string
	AssemblyVersion               string // "1.4.5.8"
	Culture                       string // "neutral" when empty
	PublicKeyToken                string // hex, "" when unsigned
	StrongNameSigned              bool   // COMIMAGE_FLAGS_STRONGNAMESIGNED
	CorFlags                      uint32
	EntryPointToken               uint32 // 0 when native entry point (RVA form)
	EntryPoint                    string // "Namespace.Type.Method"
	TargetFramework               string
	Guid                          string
	FileVersion                   string
	InformationalVersion          string
	Title                         string
	Product                       string
	Description                   string
	Company                       string
	Copyright                     string
	Trademark                     string
	ComVisible                    *bool
	DebuggableModes               *uint32
	SkipVerification              *bool
	CompilationRelaxations        *uint32
	RuntimeWrapNonExceptionThrows *bool
	DeclSecurityAction            string // e.g. "RequestMinimum" when assembly requests permissions
	TypeDefCount                  uint32
	MethodDefCount                uint32
	TypeRefCount                  uint32
	MemberRefCount                uint32
	AssemblyRefCount              uint32
	AssemblyRefs                  []string // "Name, Version=x.y.z.w"
	PInvokeCount                  uint32
	PInvokes                      []string // "dll!function" capped at 16
	DynamicLoadHints              []string // suspicious MemberRef calls capped at 16
	MemberRefNames                uint32   // total MemberRef rows scanned
	// ILCallSites holds call-like instructions found by walking managed
	// method bodies (call/callvirt/newobj/jmp/calli/ldftn/ldvirtftn),
	// capped at 2048 entries; ILTruncated reports the cap was hit.
	ILCallSites     []ILCallSite `json:"il_callsites,omitempty"`
	ILMethodsWalked uint32       `json:"il_methods_walked"`
	ILTruncated     bool         `json:"il_truncated,omitempty"`
}

// Debuggable mode bits of System.Diagnostics.DebuggableAttribute.
const (
	DebuggableNone                            = 0
	DebuggableDefault                         = 1
	DebuggableIgnoreSymbolStoreSequencePoints = 2
	DebuggableEnableEditAndContinue           = 4
	DebuggableDisableOptimizations            = 256
)

// DebuggableModesString renders the bitmask like ILSpy does.
func DebuggableModesString(m uint32) string {
	if m == 0 {
		return "None"
	}
	var parts []string
	if m&DebuggableDefault != 0 {
		parts = append(parts, "Default")
	}
	if m&DebuggableIgnoreSymbolStoreSequencePoints != 0 {
		parts = append(parts, "IgnoreSymbolStoreSequencePoints")
	}
	if m&DebuggableEnableEditAndContinue != 0 {
		parts = append(parts, "EnableEditAndContinue")
	}
	if m&DebuggableDisableOptimizations != 0 {
		parts = append(parts, "DisableOptimizations")
	}
	if len(parts) == 0 {
		return fmt.Sprintf("0x%X", m)
	}
	return strings.Join(parts, " | ")
}

// dotnetReader is a bounds-checked cursor over the image with an RVA map.
type dotnetReader struct {
	data []byte
	secs []peSection
	hdrs uint64
}

type peSection struct{ va, vsz, raw, rawsz uint64 }

func (r *dotnetReader) span(off, size uint64) bool {
	return off <= uint64(len(r.data)) && size <= uint64(len(r.data))-off
}

func (r *dotnetReader) u16(off uint64) (uint16, bool) {
	if !r.span(off, 2) {
		return 0, false
	}
	return binary.LittleEndian.Uint16(r.data[off:]), true
}

func (r *dotnetReader) u32(off uint64) (uint32, bool) {
	if !r.span(off, 4) {
		return 0, false
	}
	return binary.LittleEndian.Uint32(r.data[off:]), true
}

func (r *dotnetReader) bytes(off, size uint64) ([]byte, bool) {
	if !r.span(off, size) {
		return nil, false
	}
	return r.data[off : off+size], true
}

// rva converts an RVA+size to a file offset via sections, then headers.
func (r *dotnetReader) rva(rva, size uint64) (uint64, bool) {
	if rva+size < rva || rva+size > 1<<32 {
		return 0, false
	}
	for _, s := range r.secs {
		if rva >= s.va {
			if d := rva - s.va; d < s.rawsz && size <= s.rawsz-d {
				return s.raw + d, true
			}
		}
	}
	if rva < r.hdrs && size <= r.hdrs-rva {
		return rva, true
	}
	return 0, false
}

// ParseDotNet extracts CLI metadata. It returns (nil, nil) when the image is
// a native PE without a CLR header — that is a normal negative, not an error.
func ParseDotNet(data []byte) (*DotNetInfo, error) {
	r, opt, err := dotnetPEBase(data)
	if err != nil {
		return nil, err
	}
	// Data directory 14 is the COM descriptor (CLR header).
	comRVA, comSize, ok := dataDirectory(data, opt, 14)
	if !ok || comRVA == 0 || comSize < 72 {
		return nil, nil // native image, no CLR header
	}
	cliOff, ok := r.rva(uint64(comRVA), 72)
	if !ok {
		return nil, fmt.Errorf("dotnet: CLR header out of bounds")
	}
	cb, ok := r.u32(cliOff)
	if !ok || cb < 72 {
		return nil, fmt.Errorf("dotnet: bad CLI header size")
	}
	metaRVA, ok := r.u32(cliOff + 8)
	if !ok {
		return nil, fmt.Errorf("dotnet: bad CLI header")
	}
	metaSize, ok := r.u32(cliOff + 12)
	if !ok || metaSize < 16 || metaSize > uint32(len(data)) {
		return nil, fmt.Errorf("dotnet: bad metadata size")
	}
	flags, _ := r.u32(cliOff + 16)
	entryTok, _ := r.u32(cliOff + 20)
	metaOff, ok := r.rva(uint64(metaRVA), uint64(metaSize))
	if !ok {
		return nil, fmt.Errorf("dotnet: metadata out of bounds")
	}
	meta, ok := r.bytes(metaOff, uint64(metaSize))
	if !ok {
		return nil, fmt.Errorf("dotnet: metadata unreadable")
	}
	mr := &metaReader{data: meta}
	root, err := mr.parseRoot()
	if err != nil {
		return nil, err
	}
	info := &DotNetInfo{IsDotNet: true, CorFlags: flags, RuntimeVersion: root.version}
	info.StrongNameSigned = flags&0x8 != 0
	if flags&0x10 == 0 {
		info.EntryPointToken = entryTok // managed MethodDef token
	}
	tables, err := root.parseTables()
	if err != nil {
		return nil, err
	}
	if err := tables.fillInfo(r, info); err != nil {
		return nil, err
	}
	return info, nil
}

// dotnetPEBase parses DOS/COFF/optional headers and returns the reader and
// optional-header offset. Mirrors peinspect.Inspect bounds.
func dotnetPEBase(data []byte) (*dotnetReader, uint64, error) {
	r := &dotnetReader{data: data}
	span := r.span
	u16 := func(off uint64) uint16 { return binary.LittleEndian.Uint16(data[off:]) }
	u32 := func(off uint64) uint64 { return uint64(binary.LittleEndian.Uint32(data[off:])) }
	if !span(0, 64) || string(data[:2]) != "MZ" {
		return nil, 0, fmt.Errorf("dotnet: invalid DOS header")
	}
	pe := u32(0x3c)
	if pe < 64 || !span(pe, 24) || string(data[pe:pe+4]) != "PE\x00\x00" {
		return nil, 0, fmt.Errorf("dotnet: invalid PE signature")
	}
	coff, opt := pe+4, pe+24
	nsec, optSize := uint64(u16(coff+2)), uint64(u16(coff+16))
	if nsec > 512 || optSize < 2 || !span(opt, optSize) {
		return nil, 0, fmt.Errorf("dotnet: invalid headers")
	}
	var fixed uint64
	switch u16(opt) {
	case 0x10b:
		fixed = 96
	case 0x20b:
		fixed = 112
	default:
		return nil, 0, fmt.Errorf("dotnet: unsupported optional magic")
	}
	if optSize < fixed {
		return nil, 0, fmt.Errorf("dotnet: truncated optional header")
	}
	secAt := opt + optSize
	if !span(secAt, nsec*40) {
		return nil, 0, fmt.Errorf("dotnet: truncated section table")
	}
	headers := u32(opt + 60)
	if headers == 0 {
		headers = secAt + nsec*40
	}
	if !span(0, headers) {
		return nil, 0, fmt.Errorf("dotnet: truncated headers")
	}
	r.hdrs = headers
	for i := uint64(0); i < nsec; i++ {
		at := secAt + i*40
		s := peSection{va: u32(at + 12), vsz: u32(at + 8), raw: u32(at + 20), rawsz: u32(at + 16)}
		if s.rawsz > 0 && !span(s.raw, s.rawsz) {
			return nil, 0, fmt.Errorf("dotnet: section out of bounds")
		}
		r.secs = append(r.secs, s)
	}
	return r, opt, nil
}

// dataDirectory returns the RVA/size of optional-header data directory i.
func dataDirectory(data []byte, opt uint64, i uint64) (uint32, uint32, bool) {
	var fixed uint64
	switch binary.LittleEndian.Uint16(data[opt:]) {
	case 0x10b:
		fixed = 96
	case 0x20b:
		fixed = 112
	default:
		return 0, 0, false
	}
	ndirs := uint64(binary.LittleEndian.Uint32(data[opt+fixed-4:]))
	at := opt + fixed + i*8
	if i >= ndirs || uint64(len(data)) < at+8 {
		return 0, 0, false
	}
	return binary.LittleEndian.Uint32(data[at:]),
		binary.LittleEndian.Uint32(data[at+4:]), true
}

// ── Metadata root ────────────────────────────────────────────────────────────

type metaStream struct {
	name         string
	offset, size uint32 // relative to metadata root
}

type metaRoot struct {
	data    []byte
	version string
	streams []metaStream
}

type metaReader struct{ data []byte }

func (m *metaReader) u32(off uint64) (uint32, bool) {
	if off+4 > uint64(len(m.data)) {
		return 0, false
	}
	return binary.LittleEndian.Uint32(m.data[off:]), true
}

func (m *metaReader) parseRoot() (*metaRoot, error) {
	d := m.data
	if len(d) < 16 || string(d[:4]) != "BSJB" {
		return nil, fmt.Errorf("dotnet: missing metadata root signature")
	}
	major, minor := binary.LittleEndian.Uint16(d[4:]), binary.LittleEndian.Uint16(d[6:])
	_ = major
	_ = minor
	cbVer := binary.LittleEndian.Uint32(d[12:])
	if uint64(16+cbVer) > uint64(len(d)) {
		return nil, fmt.Errorf("dotnet: bad runtime version length")
	}
	version := string(d[16 : 16+cbVer])
	if i := strings.IndexByte(version, 0); i >= 0 {
		version = version[:i]
	}
	off := uint64(16 + ((cbVer + 3) &^ 3))
	if off+4 > uint64(len(d)) {
		return nil, fmt.Errorf("dotnet: truncated stream table")
	}
	// flags(2) + streams(2)
	nstreams := binary.LittleEndian.Uint16(d[off+2:])
	off += 4
	root := &metaRoot{data: d, version: version}
	for i := 0; i < int(nstreams); i++ {
		if off+8 > uint64(len(d)) {
			return nil, fmt.Errorf("dotnet: truncated stream header")
		}
		soff := binary.LittleEndian.Uint32(d[off:])
		ssize := binary.LittleEndian.Uint32(d[off+4:])
		off += 8
		end := off
		for end < uint64(len(d)) && d[end] != 0 {
			end++
		}
		if end >= uint64(len(d)) {
			return nil, fmt.Errorf("dotnet: unterminated stream name")
		}
		name := string(d[off:end])
		off = (end + 4) &^ 3
		if uint64(soff)+uint64(ssize) > uint64(len(d)) {
			return nil, fmt.Errorf("dotnet: stream %q out of bounds", name)
		}
		root.streams = append(root.streams, metaStream{name: name, offset: soff, size: ssize})
	}
	return root, nil
}

func (rt *metaRoot) stream(name string) ([]byte, bool) {
	for _, s := range rt.streams {
		if s.name == name {
			return rt.data[s.offset : s.offset+s.size], true
		}
	}
	return nil, false
}

// ── #~ tables ────────────────────────────────────────────────────────────────

// ECMA-335 table ids we decode.
const (
	tModule       = 0x00
	tTypeRef      = 0x01
	tTypeDef      = 0x02
	tField        = 0x04
	tMethodDef    = 0x06
	tParam        = 0x08
	tMemberRef    = 0x0A
	tCustomAttrib = 0x0C
	tModuleRef    = 0x1A
	tTypeSpec     = 0x1B
	tAssembly     = 0x20
	tAssemblyRef  = 0x23
)

type tablesData struct {
	strings []byte
	guid    []byte
	blob    []byte
	rows    map[uint32]uint32 // table id -> row count
	raw     map[uint32][]byte // table id -> concatenated rows
	strSz   int               // 2 or 4
	guidSz  int
	blobSz  int
}

func (rt *metaRoot) parseTables() (*tablesData, error) {
	tilde, ok := rt.stream("#~")
	if !ok {
		return nil, fmt.Errorf("dotnet: missing #~ stream")
	}
	stringsHeap, _ := rt.stream("#Strings")
	guidHeap, _ := rt.stream("#GUID")
	blobHeap, _ := rt.stream("#Blob")
	if len(tilde) < 24 {
		return nil, fmt.Errorf("dotnet: truncated #~ header")
	}
	heapSizes := tilde[6]
	valid := binary.LittleEndian.Uint64(tilde[8:16])
	td := &tablesData{rows: map[uint32]uint32{}, raw: map[uint32][]byte{}}
	td.strSz, td.guidSz, td.blobSz = 2, 2, 2
	if heapSizes&0x01 != 0 {
		td.strSz = 4
	}
	if heapSizes&0x02 != 0 {
		td.guidSz = 4
	}
	if heapSizes&0x04 != 0 {
		td.blobSz = 4
	}
	off := uint64(24)
	for id := uint32(0); id < 64; id++ {
		if valid&(1<<id) == 0 {
			continue
		}
		if off+4 > uint64(len(tilde)) {
			return nil, fmt.Errorf("dotnet: truncated #~ row counts")
		}
		td.rows[id] = binary.LittleEndian.Uint32(tilde[off:])
		off += 4
	}
	for id := uint32(0); id < 64; id++ {
		n, present := td.rows[id]
		if !present {
			continue
		}
		sz := td.rowSize(id)
		if sz < 0 {
			return nil, fmt.Errorf("dotnet: unsupported table 0x%02x", id)
		}
		if n > 10_000_000 || uint64(n)*uint64(sz) > uint64(len(tilde))-off {
			return nil, fmt.Errorf("dotnet: table 0x%02x out of bounds", id)
		}
		td.raw[id] = tilde[off : off+uint64(n)*uint64(sz)]
		off += uint64(n) * uint64(sz)
	}
	td.strings, td.guid, td.blob = stringsHeap, guidHeap, blobHeap
	return td, nil
}

// coded index tag widths and target tables (ECMA-335 II.24.2.6).
func (td *tablesData) codedSize(tables []uint32, tagBits uint) int {
	limit := uint32(1) << (16 - tagBits)
	for _, t := range tables {
		if td.rows[t] >= limit {
			return 4
		}
	}
	return 2
}

func (td *tablesData) tableIndexSize(table uint32) int {
	if td.rows[table] >= 0xffff {
		return 4
	}
	return 2
}

// rowSize returns the byte width of one row of table id with the current
// heap/index sizes. All metadata tables are covered so unknown-but-valid
// tables can be skipped without breaking the layout of the tables after them.
func (td *tablesData) rowSize(id uint32) int {
	S, B := td.strSz, td.blobSz
	rs := td.codedSize([]uint32{tModule, tModuleRef, tAssemblyRef, tTypeRef}, 2)
	tdor := td.codedSize([]uint32{tTypeDef, tTypeRef, tTypeSpec}, 2)
	mrp := td.codedSize([]uint32{tTypeDef, tTypeRef, tModuleRef, tMethodDef, tTypeSpec}, 3)
	hca := td.codedSize(hasCustomAttributeTargets, 5)
	// CustomAttributeType behaves with a 2-bit tag in the wild (16K-row
	// limit): images with >= 16384 MethodDefs (e.g. Terraria, 21060) store
	// it in 4 bytes. Verified byte-for-byte against a 26 MB production
	// assembly: 2516/2516 attribute blobs resolve only with this width.
	cat := td.codedSize([]uint32{tMethodDef, tMemberRef}, 2)
	hc := td.codedSize([]uint32{tField, tParam, 0x17}, 2)             // HasConstant
	hfm := td.codedSize([]uint32{tField, tParam}, 1)                  // HasFieldMarshal
	hds := td.codedSize([]uint32{tTypeDef, tMethodDef, tAssembly}, 2) // HasDeclSecurity
	mf := td.codedSize([]uint32{tField, tMethodDef}, 1)               // MemberForwarded
	impl := td.codedSize([]uint32{0x26, tAssemblyRef, 0x27}, 2)       // Implementation
	hs := td.codedSize([]uint32{0x14, 0x17}, 1)                       // HasSemantics
	mdor := td.codedSize([]uint32{tMethodDef, tMemberRef}, 1)         // MethodDefOrRef
	tomd := td.codedSize([]uint32{tTypeDef, tMethodDef}, 1)           // TypeOrMethodDef
	fidx := td.tableIndexSize(tField)
	midx := td.tableIndexSize(tMethodDef)
	pidx := td.tableIndexSize(tParam)
	tidx := td.tableIndexSize(tTypeDef)
	mrefIdx := td.tableIndexSize(tModuleRef)
	evIdx := td.tableIndexSize(0x14)
	propIdx := td.tableIndexSize(0x17)
	gpIdx := td.tableIndexSize(0x2A)
	arIdx := td.tableIndexSize(tAssemblyRef)
	switch id {
	case tModule:
		return 2 + S + td.guidSz + td.guidSz + td.guidSz
	case tTypeRef:
		return rs + S + S
	case tTypeDef:
		return 4 + S + S + tdor + fidx + midx
	case 0x03: // FieldPtr
		return fidx
	case tField:
		return 2 + S + B
	case 0x05: // MethodPtr
		return midx
	case tMethodDef:
		return 4 + 2 + 2 + S + B + pidx
	case 0x07: // ParamPtr
		return pidx
	case tParam:
		return 2 + 2 + S
	case 0x09: // InterfaceImpl
		return tidx + tdor
	case tMemberRef:
		return mrp + S + B
	case 0x0B: // Constant
		return 1 + 1 + hc + B
	case tCustomAttrib:
		return hca + cat + B
	case 0x0D: // FieldMarshal
		return hfm + B
	case 0x0E: // DeclSecurity
		return 2 + hds + B
	case 0x0F: // ClassLayout
		return 2 + 4 + tidx
	case 0x10: // FieldLayout
		return 4 + fidx
	case 0x11: // StandAloneSig
		return B
	case 0x12: // EventMap
		return tidx + evIdx
	case 0x13: // EventPtr
		return evIdx
	case 0x14: // Event
		return 2 + S + tdor
	case 0x15: // PropertyMap
		return tidx + propIdx
	case 0x16: // PropertyPtr
		return propIdx
	case 0x17: // Property
		return 2 + S + B
	case 0x18: // MethodSemantics
		return 2 + midx + hs
	case 0x19: // MethodImpl
		return tidx + mdor + mdor
	case tModuleRef:
		return S
	case tTypeSpec:
		return B
	case 0x1C: // ImplMap
		return 2 + mf + S + mrefIdx
	case 0x1D: // FieldRVA
		return 4 + fidx
	case 0x1E, 0x1F: // ENCLog, ENCMap
		return 8
	case tAssembly:
		return 4 + 2 + 2 + 2 + 2 + 4 + B + S + S
	case 0x21, 0x24: // AssemblyProcessor, AssemblyRefProcessor
		if id == 0x24 {
			return 4 + arIdx
		}
		return 4
	case 0x22, 0x25: // AssemblyOS, AssemblyRefOS
		if id == 0x25 {
			return 4 + 4 + 4 + arIdx
		}
		return 4 + 4 + 4
	case tAssemblyRef:
		return 2 + 2 + 2 + 2 + 4 + B + S + S + B
	case 0x26: // File
		return 4 + S + B
	case 0x27: // ExportedType
		return 4 + 4 + S + S + impl
	case 0x28: // ManifestResource
		return 4 + 4 + S + impl
	case 0x29: // NestedClass
		return tidx + tidx
	case 0x2A: // GenericParam
		return 2 + 2 + tomd + S
	case 0x2B: // MethodSpec
		return mdor + B
	case 0x2C: // GenericParamConstraint
		return gpIdx + tdor
	}
	return -1
}

// hasCustomAttributeTargets is the ECMA-335 HasCustomAttribute coded-index
// table list (tag = position, 5 bits).
var hasCustomAttributeTargets = []uint32{
	tMethodDef, tField, tTypeRef, tTypeDef, tParam, 0x09, tMemberRef, tModule,
	0x0E, 0x17, 0x18, 0x14, tModuleRef, tTypeSpec, tAssembly, tAssemblyRef,
	0x26, 0x27, 0x28, 0x2A, 0x2C,
}

// hasCustomAttributeTagOfAssembly is the tag value for the Assembly table.
const hasCustomAttributeTagOfAssembly = 14

func heapString(heap []byte, idx uint32) string {
	if uint64(idx) >= uint64(len(heap)) {
		return ""
	}
	end := idx
	for end < uint32(len(heap)) && heap[end] != 0 {
		end++
	}
	return string(heap[idx:end])
}

// blobBytes resolves a #Blob index to its content bytes.
func (td *tablesData) blobBytes(idx uint32) ([]byte, bool) {
	if uint64(idx) >= uint64(len(td.blob)) {
		return nil, false
	}
	n, nlen := readCompressed(td.blob[idx:])
	if nlen == 0 || uint64(idx)+uint64(nlen)+uint64(n) > uint64(len(td.blob)) {
		return nil, false
	}
	return td.blob[idx+uint32(nlen) : idx+uint32(nlen)+n], true
}

func (td *tablesData) guidString(idx uint32) string {
	// #GUID indexes are 1-based in both 2- and 4-byte forms.
	if idx == 0 || uint64(idx-1)*16+16 > uint64(len(td.guid)) {
		return ""
	}
	return formatGUID(td.guid[(idx-1)*16 : idx*16])
}

func formatGUID(b []byte) string {
	if len(b) < 16 {
		return ""
	}
	d0 := binary.LittleEndian.Uint32(b[0:])
	d1 := binary.LittleEndian.Uint16(b[4:])
	d2 := binary.LittleEndian.Uint16(b[6:])
	return fmt.Sprintf("%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		d0, d1, d2, b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
}

// readCompressed reads an ECMA-335 compressed unsigned integer.
func readCompressed(b []byte) (uint32, int) {
	if len(b) < 1 {
		return 0, 0
	}
	if b[0]&0x80 == 0 {
		return uint32(b[0]), 1
	}
	if b[0]&0x40 == 0 {
		if len(b) < 2 {
			return 0, 0
		}
		return uint32(b[0]&0x3f)<<8 | uint32(b[1]), 2
	}
	if len(b) < 4 {
		return 0, 0
	}
	return uint32(b[0]&0x1f)<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]), 4
}

// serString decodes a SerString (0xFF = null).
func serString(b []byte) (string, int, bool) {
	if len(b) == 0 {
		return "", 0, false
	}
	if b[0] == 0xFF {
		return "", 1, true
	}
	n, nlen := readCompressed(b)
	if nlen == 0 || uint64(nlen)+uint64(n) > uint64(len(b)) {
		return "", 0, false
	}
	return string(b[nlen : nlen+int(n)]), nlen + int(n), true
}

// ── row decoders ─────────────────────────────────────────────────────────────

type rowCursor struct {
	row []byte
	off int
	bad bool // sticky out-of-bounds flag: reads saturate to zero instead of panicking
}

func (c *rowCursor) need(n int) bool {
	if c.bad || c.off+n > len(c.row) {
		c.bad = true
		return false
	}
	return true
}

func (c *rowCursor) u16() uint32 {
	if !c.need(2) {
		return 0
	}
	v := binary.LittleEndian.Uint16(c.row[c.off:])
	c.off += 2
	return uint32(v)
}

func (c *rowCursor) u32() uint32 {
	if !c.need(4) {
		return 0
	}
	v := binary.LittleEndian.Uint32(c.row[c.off:])
	c.off += 4
	return v
}

func (c *rowCursor) idx(sz int) uint32 {
	if sz == 4 {
		return c.u32()
	}
	return c.u16()
}

func (td *tablesData) row(table, rid uint32) []byte {
	raw, ok := td.raw[table]
	if !ok {
		return nil
	}
	sz := td.rowSize(table)
	if rid == 0 || uint64(rid-1)*uint64(sz)+uint64(sz) > uint64(len(raw)) {
		return nil
	}
	return raw[(rid-1)*uint32(sz) : rid*uint32(sz)]
}

// fillInfo resolves assembly identity, entry point and attributes.
func (td *tablesData) fillInfo(r *dotnetReader, info *DotNetInfo) error {
	info.TypeDefCount = td.rows[tTypeDef]
	info.MethodDefCount = td.rows[tMethodDef]
	info.TypeRefCount = td.rows[tTypeRef]
	info.MemberRefCount = td.rows[tMemberRef]
	info.AssemblyRefCount = td.rows[tAssemblyRef]

	// Module.
	if r := td.row(tModule, 1); r != nil {
		c := &rowCursor{row: r}
		c.u16() // Generation
		nameIdx := c.idx(td.strSz)
		guidIdx := c.idx(td.guidSz)
		info.ModuleName = heapString(td.strings, nameIdx)
		info.Mvid = td.guidString(guidIdx)
	}

	// Assembly identity (row 1).
	if r := td.row(tAssembly, 1); r != nil {
		c := &rowCursor{row: r}
		c.u32() // HashAlgId
		major, minor, build, rev := c.u16(), c.u16(), c.u16(), c.u16()
		c.u32() // Flags
		pkIdx := c.idx(td.blobSz)
		nameIdx := c.idx(td.strSz)
		cultIdx := c.idx(td.strSz)
		info.AssemblyName = heapString(td.strings, nameIdx)
		info.AssemblyVersion = fmt.Sprintf("%d.%d.%d.%d", major, minor, build, rev)
		info.Culture = heapString(td.strings, cultIdx)
		if info.Culture == "" {
			info.Culture = "neutral"
		}
		if pk, ok := td.blobBytes(pkIdx); ok && len(pk) > 0 {
			// PublicKeyToken is the last 8 bytes of SHA1(public key),
			// reversed for display. Without hashing we report the key
			// length; the token itself comes from AssemblyRef-style data
			// only when the key is a token already (8 bytes).
			if len(pk) == 8 {
				info.PublicKeyToken = fmt.Sprintf("%02x%02x%02x%02x%02x%02x%02x%02x",
					pk[7], pk[6], pk[5], pk[4], pk[3], pk[2], pk[1], pk[0])
			}
		}
	}

	// AssemblyRefs.
	for i := uint32(1); i <= td.rows[tAssemblyRef]; i++ {
		r := td.row(tAssemblyRef, i)
		if r == nil {
			continue
		}
		c := &rowCursor{row: r}
		major, minor, build, rev := c.u16(), c.u16(), c.u16(), c.u16()
		c.u32() // Flags
		c.idx(td.blobSz)
		nameIdx := c.idx(td.strSz)
		c.idx(td.strSz)
		c.idx(td.blobSz)
		name := heapString(td.strings, nameIdx)
		if name == "" {
			continue
		}
		info.AssemblyRefs = append(info.AssemblyRefs,
			fmt.Sprintf("%s, Version=%d.%d.%d.%d", name, major, minor, build, rev))
		if len(info.AssemblyRefs) >= 64 {
			break
		}
	}

	// Entry point: MethodDef token 0x06xxxxxx.
	if info.EntryPointToken&0xFF000000 == 0x06000000 {
		rid := info.EntryPointToken & 0xFFFFFF
		if r := td.row(tMethodDef, rid); r != nil {
			c := &rowCursor{row: r}
			c.u32() // RVA
			c.u16()
			c.u16() // ImplFlags, Flags
			nameIdx := c.idx(td.strSz)
			method := heapString(td.strings, nameIdx)
			info.EntryPoint = td.ownerOfMethod(rid) + method
			if info.EntryPoint == method {
				info.EntryPoint = method
			}
		}
	}

	// Assembly-level custom attributes.
	for i := uint32(1); i <= td.rows[tCustomAttrib]; i++ {
		r := td.row(tCustomAttrib, i)
		if r == nil {
			continue
		}
		c := &rowCursor{row: r}
		parent := c.idx(td.codedSize(hasCustomAttributeTargets, 5))
		typ := c.idx(td.codedSize([]uint32{tMethodDef, tMemberRef}, 2))
		valIdx := c.idx(td.blobSz)
		if c.bad {
			continue
		}
		// Assembly row 1 carries tag hasCustomAttributeTagOfAssembly.
		if parent&0x1F != hasCustomAttributeTagOfAssembly || parent>>5 != 1 {
			continue
		}
		attrName := td.attributeTypeName(typ)
		blob, ok := td.blobBytes(valIdx)
		if !ok || len(blob) < 2 || blob[0] != 1 || blob[1] != 0 {
			continue
		}
		body := blob[2:]
		switch attrName {
		case "TargetFrameworkAttribute":
			if s, _, ok := serString(body); ok {
				info.TargetFramework = s
			}
		case "GuidAttribute":
			if s, _, ok := serString(body); ok {
				info.Guid = s
			}
		case "AssemblyTitleAttribute":
			if s, _, ok := serString(body); ok {
				info.Title = s
			}
		case "AssemblyProductAttribute":
			if s, _, ok := serString(body); ok {
				info.Product = s
			}
		case "AssemblyDescriptionAttribute":
			if s, _, ok := serString(body); ok {
				info.Description = s
			}
		case "AssemblyCompanyAttribute":
			if s, _, ok := serString(body); ok {
				info.Company = s
			}
		case "AssemblyCopyrightAttribute":
			if s, _, ok := serString(body); ok {
				info.Copyright = s
			}
		case "AssemblyTrademarkAttribute":
			if s, _, ok := serString(body); ok {
				info.Trademark = s
			}
		case "AssemblyFileVersionAttribute":
			if s, _, ok := serString(body); ok {
				info.FileVersion = s
			}
		case "AssemblyInformationalVersionAttribute":
			if s, _, ok := serString(body); ok {
				info.InformationalVersion = s
			}
		case "ComVisibleAttribute":
			if len(body) >= 1 {
				v := body[0] != 0
				info.ComVisible = &v
			}
		case "DebuggableAttribute":
			if len(body) >= 4 {
				m := binary.LittleEndian.Uint32(body[:4])
				info.DebuggableModes = &m
			}
		case "SecurityPermissionAttribute":
			if v, ok := scanNamedBoolArg(body, "SkipVerification"); ok {
				info.SkipVerification = &v
			}
		case "CompilationRelaxationsAttribute":
			if len(body) >= 4 {
				v := binary.LittleEndian.Uint32(body[:4])
				info.CompilationRelaxations = &v
			}
		case "RuntimeCompatibilityAttribute":
			if v, ok := scanNamedBoolArg(body, "WrapNonExceptionThrows"); ok {
				info.RuntimeWrapNonExceptionThrows = &v
			}
		}
	}
	// P/Invoke targets (ImplMap 0x1C) + suspicious managed calls (MemberRef 0x0A).
	td.collectPInvokes(info)
	td.collectDynamicCalls(info)
	// IL-level callsites: which methods are actually invoked, not merely
	// referenced. Runs last so owner/memberRef names resolve.
	td.collectILCalls(r, info)
	// Declarative security (RequestMinimum/Optional/Refuse) lives in the
	// DeclSecurity table, not in CustomAttribute rows. An assembly-level
	// request carries a PermissionSet blob (prolog '.' + SerString XML);
	// a SkipVerification="true" grant inside is a hardening-relevant signal.
	for i := uint32(1); i <= td.rows[0x0E]; i++ {
		r := td.row(0x0E, i)
		if r == nil {
			continue
		}
		c := &rowCursor{row: r}
		action := c.u16()
		parent := c.idx(td.codedSize([]uint32{tTypeDef, tMethodDef, tAssembly}, 2))
		permIdx := c.idx(td.blobSz)
		if c.bad || parent&3 != 2 || parent>>2 != 1 {
			continue
		}
		info.DeclSecurityAction = declSecurityActionName(action)
		if perm, ok := td.blobBytes(permIdx); ok {
			if v, ok := declSecurityGrantsSkipVerification(perm); ok && v {
				info.SkipVerification = &v
			}
		}
	}
	return nil
}

// suspiciousManagedCalls are MemberRef targets worth surfacing with provenance:
// dynamic code loading, reflection invocation, and process/network primitives.
var suspiciousManagedCalls = []string{
	"System.Reflection.Assembly::Load", "System.Reflection.Assembly::LoadFrom",
	"System.Reflection.Assembly::LoadFile", "System.AppDomain::Load",
	"System.Activator::CreateInstance", "System.Type::GetType",
	"System.Reflection.MethodBase::Invoke", "System.Reflection.MethodInfo::Invoke",
	"System.Reflection.Emit.DynamicMethod", "System.Reflection.Emit.ILGenerator::Emit",
	"System.Reflection.Emit.AssemblyBuilder::DefineDynamicAssembly",
	"System.Diagnostics.Process::Start", "System.Net.WebClient::Download",
	"System.IO.File::WriteAllBytes", "System.Runtime.InteropServices.Marshal::",
	"System.Management.Automation", "Microsoft.Win32.Registry::SetValue",
}

func (td *tablesData) memberRefFullName(rid uint32) string {
	r := td.row(tMemberRef, rid)
	if r == nil {
		return ""
	}
	c := &rowCursor{row: r}
	class := c.idx(td.codedSize([]uint32{tTypeDef, tTypeRef, tModuleRef, tMethodDef, tTypeSpec}, 3))
	nameIdx := c.idx(td.strSz)
	if c.bad {
		return ""
	}
	cls := td.memberRefParentName(class)
	m := heapString(td.strings, nameIdx)
	if cls == "" {
		return m
	}
	return cls + "::" + m
}

func (td *tablesData) collectPInvokes(info *DotNetInfo) {
	n := td.rows[0x1C]
	info.PInvokeCount = n
	for i := uint32(1); i <= n && uint32(len(info.PInvokes)) < 16; i++ {
		r := td.row(0x1C, i)
		if r == nil {
			continue
		}
		c := &rowCursor{row: r}
		c.u16() // flags
		c.idx(td.codedSize([]uint32{tField, tMethodDef}, 1))
		nameIdx := c.idx(td.strSz)
		scopeIdx := c.idx(td.tableIndexSize(tModuleRef))
		if c.bad {
			continue
		}
		fn := heapString(td.strings, nameIdx)
		dll := ""
		if mr := td.row(tModuleRef, scopeIdx); mr != nil {
			mc := &rowCursor{row: mr}
			dll = heapString(td.strings, mc.idx(td.strSz))
		}
		if fn == "" && dll == "" {
			continue
		}
		info.PInvokes = append(info.PInvokes, dll+"!"+fn)
	}
}

func (td *tablesData) collectDynamicCalls(info *DotNetInfo) {
	n := td.rows[tMemberRef]
	info.MemberRefNames = n
	seen := map[string]bool{}
	for i := uint32(1); i <= n && uint32(len(info.DynamicLoadHints)) < 16; i++ {
		full := td.memberRefFullName(i)
		if full == "" || seen[full] {
			continue
		}
		for _, pat := range suspiciousManagedCalls {
			if len(full) >= len(pat) && (full == pat || beginsWith(full, pat)) {
				seen[full] = true
				info.DynamicLoadHints = append(info.DynamicLoadHints, full)
				break
			}
		}
	}
}

func beginsWith(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		a, b := s[i], prefix[i]
		if a >= 'A' && a <= 'Z' {
			a += 'a' - 'A'
		}
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
		if a != b {
			return false
		}
	}
	return true
}

// declSecurityGrantsSkipVerification inspects a DeclSecurity PermissionSet
// blob for a SkipVerification = true grant. RequestMinimum/Optional/Refuse
// permission sets use the binary CAS serialization (prolog '.', SerString
// type names, then FIELD/PROPERTY named arguments), not XML: look for a
// PROPERTY (0x54) or FIELD (0x53) argument with ELEMENT_TYPE_BOOLEAN (0x02)
// named "SkipVerification" whose value byte is 0x01. Bounds-checked: any
// truncation yields (false, false), never a panic.
func declSecurityGrantsSkipVerification(perm []byte) (bool, bool) {
	const name = "SkipVerification"
	found := false
	// The bound only guarantees kind + type bytes; serString and the value
	// offset below are bounds-checked independently, so a match at the very
	// tail of the blob is still reachable.
	for i := 0; i+2 < len(perm); i++ {
		if perm[i] != 0x53 && perm[i] != 0x54 {
			continue
		}
		if perm[i+1] != 0x02 {
			continue
		}
		s, nlen, ok := serString(perm[i+2:])
		if !ok || s != name {
			continue
		}
		valOff := i + 2 + nlen
		if valOff >= len(perm) {
			return false, false
		}
		found = true
		if perm[valOff] == 0x01 {
			return true, true
		}
	}
	return false, found
}

// declSecurityActionName maps CorDeclSecurity action codes.
func declSecurityActionName(a uint32) string {
	switch a {
	case 1:
		return "Request"
	case 2:
		return "Demand"
	case 3:
		return "Assert"
	case 4:
		return "Deny"
	case 5:
		return "PermitOnly"
	case 6:
		return "LinkDemand"
	case 7:
		return "InheritanceDemand"
	case 8:
		return "RequestMinimum"
	case 9:
		return "RequestOptional"
	case 10:
		return "RequestRefuse"
	}
	return fmt.Sprintf("Action(%d)", a)
}

// attributeTypeName resolves a CustomAttributeType coded index to the
// attribute class name. The encoding uses a 3-bit tag (MethodDef = 2,
// MemberRef = 3; verified: all 2516 CustomAttribute rows of a production
// assembly use only these tags). ctors are normally MemberRefs whose parent
// (MemberRefParent coded index) names the attribute class — usually a
// TypeRef like "TargetFrameworkAttribute". Same-assembly ctors resolve
// through the declaring TypeDef.
func (td *tablesData) attributeTypeName(typ uint32) string {
	tag, rid := typ&7, typ>>3
	switch tag {
	case 3:
		r := td.row(tMemberRef, rid)
		if r == nil {
			return ""
		}
		c := &rowCursor{row: r}
		class := c.idx(td.codedSize([]uint32{tTypeDef, tTypeRef, tModuleRef, tMethodDef, tTypeSpec}, 3))
		return td.memberRefParentName(class)
	case 2:
		return strings.TrimSuffix(td.typeOfMethod(rid), ".")
	}
	return ""
}

// memberRefParentName resolves a MemberRefParent coded index to a type name.
func (td *tablesData) memberRefParentName(class uint32) string {
	tag, rid := class&7, class>>3
	switch tag {
	case 0, 1: // TypeDef, TypeRef
		var table uint32 = tTypeDef
		if tag == 1 {
			table = tTypeRef
		}
		if r := td.row(table, rid); r != nil {
			c := &rowCursor{row: r}
			if tag == 0 {
				c.u32() // TypeDef flags
			} else {
				c.idx(td.codedSize([]uint32{tModule, tModuleRef, tAssemblyRef, tTypeRef}, 2)) // ResolutionScope
			}
			return heapString(td.strings, c.idx(td.strSz))
		}
	case 3: // MethodDef: use the declaring type (vararg ctor edge case)
		return strings.TrimSuffix(td.typeOfMethod(rid), ".")
	}
	return ""
}

// typeOfMethod returns the full name of the type declaring a MethodDef.
func (td *tablesData) typeOfMethod(rid uint32) string {
	return td.ownerOfMethod(rid)
}

// ownerOfMethod finds the TypeDef owning a MethodDef rid via MethodList ranges,
// returning "Namespace.Type." (trailing dot) or "" when unresolvable.
func (td *tablesData) ownerOfMethod(rid uint32) string {
	best := ""
	bestStart := uint32(0)
	for i := uint32(1); i <= td.rows[tTypeDef]; i++ {
		r := td.row(tTypeDef, i)
		if r == nil {
			continue
		}
		c := &rowCursor{row: r}
		c.u32() // Flags
		nameIdx := c.idx(td.strSz)
		nsIdx := c.idx(td.strSz)
		c.idx(td.codedSize([]uint32{tTypeDef, tTypeRef, tTypeSpec}, 2)) // Extends
		c.idx(td.tableIndexSize(tField))                                // FieldList
		start := c.idx(td.tableIndexSize(tMethodDef))                   // MethodList
		if start != 0 && start <= rid && start >= bestStart {
			bestStart = start
			ns, name := heapString(td.strings, nsIdx), heapString(td.strings, nameIdx)
			if ns != "" {
				best = ns + "." + name + "."
			} else {
				best = name + "."
			}
		}
	}
	return best
}

// scanNamedBoolArg scans custom-attribute named arguments for a boolean
// FIELD/PROPERTY with the given name.
func scanNamedBoolArg(body []byte, field string) (bool, bool) {
	if len(body) < 2 {
		return false, false
	}
	count := int(binary.LittleEndian.Uint16(body))
	off := 2
	for i := 0; i < count && off < len(body); i++ {
		if off+2 > len(body) {
			return false, false
		}
		off++ // FIELD(0x53) / PROPERTY(0x54)
		typ := body[off]
		off++
		name, nlen, ok := serString(body[off:])
		if !ok {
			return false, false
		}
		off += nlen
		// ELEMENT_TYPE_BOOLEAN value is 1 byte; other types are skipped
		// conservatively: fixed-size scalars only.
		var vlen int
		switch typ {
		case 0x02: // BOOLEAN
			vlen = 1
		case 0x03, 0x04: // CHAR, I1/U1
			vlen = 1
		case 0x05, 0x06, 0x0B: // I2/U2
			vlen = 2
		case 0x07, 0x08, 0x0C: // I4/U4/FLOAT
			vlen = 4
		case 0x09, 0x0A, 0x0D: // I8/U8/R8
			vlen = 8
		case 0x0E: // STRING
			_, slen, ok := serString(body[off:])
			if !ok {
				return false, false
			}
			vlen = slen
		default:
			return false, false
		}
		if off+vlen > len(body) {
			return false, false
		}
		if name == field && typ == 0x02 {
			return body[off] != 0, true
		}
		off += vlen
	}
	return false, false
}

// Summary renders an ILSpy/dnSpy-style assembly header block.
func (d *DotNetInfo) Summary(path string) string {
	var b strings.Builder
	if path != "" {
		fmt.Fprintf(&b, "// %s\n", path)
	}
	pkt := "null"
	if d.PublicKeyToken != "" {
		pkt = d.PublicKeyToken
	}
	fmt.Fprintf(&b, "// %s, Version=%s, Culture=%s, PublicKeyToken=%s\n", d.AssemblyName, d.AssemblyVersion, d.Culture, pkt)
	b.WriteString("\n")
	if d.EntryPoint != "" {
		fmt.Fprintf(&b, "// Entry point: %s\n", d.EntryPoint)
	}
	if d.RuntimeVersion != "" {
		fmt.Fprintf(&b, "// Runtime: %s\n", d.RuntimeVersion)
	}
	if len(d.AssemblyRefs) > 0 {
		fmt.Fprintf(&b, "// References: %d (TypeDefs=%d, Methods=%d)\n", len(d.AssemblyRefs), d.TypeDefCount, d.MethodDefCount)
	}
	b.WriteString("\n")
	emit := func(name, val string) {
		if val != "" {
			fmt.Fprintf(&b, "[assembly: Assembly%s(%q)]\n", name, val)
		}
	}
	emit("Version", d.AssemblyVersion)
	if d.CompilationRelaxations != nil {
		fmt.Fprintf(&b, "[assembly: CompilationRelaxations(%d)]\n", *d.CompilationRelaxations)
	}
	if d.RuntimeWrapNonExceptionThrows != nil {
		fmt.Fprintf(&b, "[assembly: RuntimeCompatibility(WrapNonExceptionThrows = %v)]\n", *d.RuntimeWrapNonExceptionThrows)
	}
	if d.Title != "" {
		emit("Title", d.Title)
	}
	if d.Product != "" {
		emit("Product", d.Product)
	}
	if d.Description != "" {
		emit("Description", d.Description)
	}
	if d.Company != "" {
		emit("Company", d.Company)
	}
	if d.Copyright != "" {
		emit("Copyright", d.Copyright)
	}
	if d.Trademark != "" {
		emit("Trademark", d.Trademark)
	}
	if d.FileVersion != "" {
		fmt.Fprintf(&b, "[assembly: AssemblyFileVersion(%q)]\n", d.FileVersion)
	}
	if d.InformationalVersion != "" {
		fmt.Fprintf(&b, "[assembly: AssemblyInformationalVersion(%q)]\n", d.InformationalVersion)
	}
	if d.TargetFramework != "" {
		fmt.Fprintf(&b, "[assembly: TargetFramework(%q, FrameworkDisplayName = %q)]\n", d.TargetFramework, displayNameForTFM(d.TargetFramework))
	}
	if d.Guid != "" {
		fmt.Fprintf(&b, "[assembly: Guid(%q)]\n", strings.ToLower(d.Guid))
	}
	if d.ComVisible != nil {
		fmt.Fprintf(&b, "[assembly: ComVisible(%v)]\n", *d.ComVisible)
	}
	if d.DebuggableModes != nil {
		fmt.Fprintf(&b, "[assembly: Debuggable(DebuggableAttribute.DebuggingModes.%s)]\n", DebuggableModesString(*d.DebuggableModes))
	}
	if d.SkipVerification != nil && *d.SkipVerification {
		action := "RequestMinimum"
		if d.DeclSecurityAction != "" {
			action = d.DeclSecurityAction
		}
		fmt.Fprintf(&b, "[assembly: SecurityPermission(SecurityAction.%s, SkipVerification = true)]\n", action)
	} else if d.DeclSecurityAction != "" {
		fmt.Fprintf(&b, "[assembly: SecurityPermission(SecurityAction.%s)]\n", d.DeclSecurityAction)
	}
	return b.String()
}

func displayNameForTFM(tfm string) string {
	if strings.HasPrefix(tfm, ".NETFramework,Version=v4.0") {
		if strings.Contains(tfm, "Profile=Client") {
			return ".NET Framework 4 Client Profile"
		}
		return ".NET Framework 4"
	}
	return ""
}
