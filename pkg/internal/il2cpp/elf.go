package il2cpp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
)

// ELF is a minimal little-endian ELF32/ELF64 reader sufficient for locating
// IL2CPP structures inside Android shared objects. Its distinguishing feature
// is the relocation table: Android strips pointers from data sections and
// materialises them only at load time through R_*_RELATIVE relocations, so
// every "pointer read" has to consult the relocation stream.
type ELF struct {
	Data    []byte
	Is64    bool
	Machine uint16

	segments []elfSegment
	sections []elfSection
	relocs   []elfReloc // sorted by Vaddr
	relrOK   bool
}

type elfSegment struct {
	Type   uint32
	Flags  uint32
	Off    uint64
	Vaddr  uint64
	FileSz uint64
}

type elfSection struct {
	Name    string
	Type    uint32
	Flags   uint64
	Off     uint64
	Size    uint64
	Addr    uint64
	EntSize uint64
}

type elfReloc struct {
	Vaddr uint64
	Value uint64
}

const (
	ptLoad = 1

	shtProgbits    = 1
	shtRela        = 4
	shtNoBits      = 8
	shtRel         = 9
	shtDynsym      = 11
	shtRelr        = 19
	shtAndroidRela = 0x6000000f
	shtAndroidRel  = 0x6000000e
	shtAndroidRelr = 0x6fffff00

	shfAlloc = 0x2
	shfExec  = 0x4
	shfWrite = 0x1
)

// Architecture-specific R_<ARCH>_RELATIVE type codes.
func relativeRelocType(is64 bool, machine uint16) uint64 {
	if is64 {
		switch machine {
		case 183: // EM_AARCH64
			return 1027
		case 62: // EM_X86_64
			return 8
		case 243: // EM_RISCV
			return 3
		}
		return 0
	}
	switch machine {
	case 40: // EM_ARM
		return 23
	case 3: // EM_386
		return 8
	}
	return 0
}

// ParseELF validates and loads an ELF image with its relocation table.
func ParseELF(data []byte) (*ELF, error) {
	if len(data) < 52 {
		return nil, fmt.Errorf("file too small for ELF")
	}
	if data[0] != 0x7F || data[1] != 'E' || data[2] != 'L' || data[3] != 'F' {
		return nil, fmt.Errorf("not an ELF file")
	}
	is64 := data[4] == 2
	if data[5] != 1 {
		return nil, fmt.Errorf("big-endian ELF is not supported")
	}
	e := &ELF{Data: data, Is64: is64}
	var phoff, shoff, phentsize, shentsize uint64
	var phnum, shnum, shstrndx int
	if is64 {
		e.Machine = binary.LittleEndian.Uint16(data[18:20])
		phoff = binary.LittleEndian.Uint64(data[32:40])
		shoff = binary.LittleEndian.Uint64(data[40:48])
		phentsize = uint64(binary.LittleEndian.Uint16(data[54:56]))
		shentsize = uint64(binary.LittleEndian.Uint16(data[58:60]))
		phnum = int(binary.LittleEndian.Uint16(data[56:58]))
		shnum = int(binary.LittleEndian.Uint16(data[60:62]))
		shstrndx = int(binary.LittleEndian.Uint16(data[62:64]))
	} else {
		e.Machine = binary.LittleEndian.Uint16(data[18:20])
		phoff = uint64(binary.LittleEndian.Uint32(data[28:32]))
		shoff = uint64(binary.LittleEndian.Uint32(data[32:36]))
		phentsize = uint64(binary.LittleEndian.Uint16(data[42:44]))
		shentsize = uint64(binary.LittleEndian.Uint16(data[46:48]))
		phnum = int(binary.LittleEndian.Uint16(data[44:46]))
		shnum = int(binary.LittleEndian.Uint16(data[48:50]))
		shstrndx = int(binary.LittleEndian.Uint16(data[50:52]))
	}

	// Sections first: the relocation streams live in sections.
	if shoff > 0 && shnum > 0 && shoff+uint64(shnum)*shentsize <= uint64(len(data)) {
		var shstrtab []byte
		raw := make([]elfSection, shnum)
		for i := 0; i < shnum; i++ {
			base := shoff + uint64(i)*shentsize
			var typ uint32
			var flags, off, size, addr, entsize uint64
			var nameOff uint32
			if is64 {
				nameOff = binary.LittleEndian.Uint32(data[base : base+4])
				typ = binary.LittleEndian.Uint32(data[base+4 : base+8])
				flags = binary.LittleEndian.Uint64(data[base+8 : base+16])
				addr = binary.LittleEndian.Uint64(data[base+16 : base+24])
				off = binary.LittleEndian.Uint64(data[base+24 : base+32])
				size = binary.LittleEndian.Uint64(data[base+32 : base+40])
				entsize = binary.LittleEndian.Uint64(data[base+56 : base+64])
			} else {
				nameOff = binary.LittleEndian.Uint32(data[base : base+4])
				typ = binary.LittleEndian.Uint32(data[base+4 : base+8])
				flags = uint64(binary.LittleEndian.Uint32(data[base+8 : base+12]))
				addr = uint64(binary.LittleEndian.Uint32(data[base+12 : base+16]))
				off = uint64(binary.LittleEndian.Uint32(data[base+16 : base+20]))
				size = uint64(binary.LittleEndian.Uint32(data[base+20 : base+24]))
				entsize = uint64(binary.LittleEndian.Uint32(data[base+36 : base+40]))
			}
			raw[i] = elfSection{Type: typ, Flags: flags, Off: off, Size: size, Addr: addr, EntSize: entsize}
			_ = nameOff
		}
		if shstrndx > 0 && shstrndx < shnum {
			s := raw[shstrndx]
			if s.Off+s.Size <= uint64(len(data)) {
				shstrtab = data[s.Off : s.Off+s.Size]
			}
		}
		for i := range raw {
			var nameOff uint32
			base := shoff + uint64(i)*shentsize
			if is64 {
				nameOff = binary.LittleEndian.Uint32(data[base : base+4])
			} else {
				nameOff = binary.LittleEndian.Uint32(data[base : base+4])
			}
			raw[i].Name = cstringFrom(shstrtab, nameOff)
			e.sections = append(e.sections, raw[i])
		}
	}

	// Program headers (vaddr <-> file offset mapping).
	if phoff > 0 && phnum > 0 && phoff+uint64(phnum)*phentsize <= uint64(len(data)) {
		for i := 0; i < phnum; i++ {
			base := phoff + uint64(i)*phentsize
			var seg elfSegment
			if is64 {
				seg.Type = binary.LittleEndian.Uint32(data[base : base+4])
				seg.Flags = binary.LittleEndian.Uint32(data[base+4 : base+8])
				seg.Off = binary.LittleEndian.Uint64(data[base+8 : base+16])
				seg.Vaddr = binary.LittleEndian.Uint64(data[base+16 : base+24])
				seg.FileSz = binary.LittleEndian.Uint64(data[base+32 : base+40])
			} else {
				seg.Type = binary.LittleEndian.Uint32(data[base : base+4])
				seg.Off = uint64(binary.LittleEndian.Uint32(data[base+4 : base+8]))
				seg.Vaddr = uint64(binary.LittleEndian.Uint32(data[base+8 : base+12]))
				seg.FileSz = uint64(binary.LittleEndian.Uint32(data[base+16 : base+20]))
			}
			if seg.Type == ptLoad {
				e.segments = append(e.segments, seg)
			}
		}
	}
	if len(e.segments) == 0 && len(e.sections) == 0 {
		return nil, fmt.Errorf("ELF has neither program headers nor sections")
	}

	if err := e.loadRelocations(); err != nil {
		return nil, err
	}
	sort.Slice(e.relocs, func(i, j int) bool { return e.relocs[i].Vaddr < e.relocs[j].Vaddr })
	return e, nil
}

func cstringFrom(b []byte, off uint32) string {
	if b == nil || int(off) >= len(b) {
		return ""
	}
	end := bytes.IndexByte(b[off:], 0)
	if end < 0 {
		return string(b[off:])
	}
	return string(b[off : int(off)+end])
}

// loadRelocations decodes every relocation section in the image and keeps the
// R_*_RELATIVE entries: for those, Value is the address the loader will store
// at Vaddr.
func (e *ELF) loadRelocations() error {
	relType := relativeRelocType(e.Is64, e.Machine)
	if relType == 0 {
		return fmt.Errorf("unsupported ELF machine %d", e.Machine)
	}
	add := func(vaddr, value uint64) {
		e.relocs = append(e.relocs, elfReloc{Vaddr: vaddr, Value: value})
	}
	for _, s := range e.sections {
		if s.Off+s.Size > uint64(len(e.Data)) {
			continue
		}
		b := e.Data[s.Off : s.Off+s.Size]
		switch s.Type {
		case shtRela:
			e.parsePlainRela(b, relType, add)
		case shtRel:
			e.parsePlainRel(b, relType, add)
		case shtAndroidRela, shtAndroidRel:
			e.parseAndroidPacked(b, s.Type == shtAndroidRela, relType, add)
		case shtRelr, shtAndroidRelr:
			e.parseRelr(b, add)
		}
	}
	return nil
}

func (e *ELF) parsePlainRela(b []byte, relType uint64, add func(uint64, uint64)) {
	if e.Is64 {
		for off := 0; off+24 <= len(b); off += 24 {
			rOffset := binary.LittleEndian.Uint64(b[off : off+8])
			rInfo := binary.LittleEndian.Uint64(b[off+8 : off+16])
			rAddend := binary.LittleEndian.Uint64(b[off+16 : off+24])
			if rInfo&0xFFFFFFFF == relType {
				add(rOffset, rAddend)
			}
		}
		return
	}
	for off := 0; off+12 <= len(b); off += 12 {
		rOffset := uint64(binary.LittleEndian.Uint32(b[off : off+4]))
		rInfo := uint64(binary.LittleEndian.Uint32(b[off+4 : off+8]))
		rAddend := uint64(binary.LittleEndian.Uint32(b[off+8 : off+12]))
		if rInfo&0xFF == relType {
			add(rOffset, rAddend)
		}
	}
}

func (e *ELF) parsePlainRel(b []byte, relType uint64, add func(uint64, uint64)) {
	if e.Is64 {
		for off := 0; off+16 <= len(b); off += 16 {
			rOffset := binary.LittleEndian.Uint64(b[off : off+8])
			rInfo := binary.LittleEndian.Uint64(b[off+8 : off+16])
			if rInfo&0xFFFFFFFF == relType {
				if raw, ok := e.rawQword(rOffset); ok {
					add(rOffset, raw)
				}
			}
		}
		return
	}
	for off := 0; off+8 <= len(b); off += 8 {
		rOffset := uint64(binary.LittleEndian.Uint32(b[off : off+4]))
		rInfo := uint64(binary.LittleEndian.Uint32(b[off+4 : off+8]))
		if rInfo&0xFF == relType {
			if raw, ok := e.rawDword(rOffset); ok {
				add(rOffset, raw)
			}
		}
	}
}

// parseAndroidPacked decodes the APS2 stream used by modern Android linkers.
// Stream shape (lld/bionic): "APS2", SLEB128(total), SLEB128(initial offset),
// then relocation groups. Group flags: 1 = grouped-by-info, 2 =
// grouped-by-offset-delta, 4 = grouped-by-addend, 8 = has-addend.
func (e *ELF) parseAndroidPacked(b []byte, isRela bool, relType uint64, add func(uint64, uint64)) {
	if len(b) < 6 || string(b[:4]) != "APS2" {
		return
	}
	d := &slebDecoder{b: b[4:]}
	const (
		flagGroupedInfo   = 1
		flagGroupedDelta  = 2
		flagGroupedAddend = 4
		flagHasAddend     = 8
	)
	count, ok1 := d.next()
	offset, ok2 := d.next()
	if !ok1 || !ok2 {
		return
	}
	// Sanity: the new format always starts with offset 0. Old pre-lld streams
	// had no total count; treat a nonzero second value as a decode failure.
	if offset != 0 || count <= 0 || count > 100_000_000 {
		return
	}
	var info, addend uint64
	processed := uint64(0)
	for processed < count && !d.failed {
		groupSize, ok := d.next()
		if !ok || groupSize == 0 || groupSize > count {
			return
		}
		groupFlags, ok := d.next()
		if !ok {
			return
		}
		var groupDelta uint64
		if groupFlags&flagGroupedDelta != 0 {
			if v, ok := d.next(); ok {
				groupDelta = v
			}
		}
		if groupFlags&flagGroupedInfo != 0 {
			if v, ok := d.next(); ok {
				info = v
			}
		}
		groupedAddend := groupFlags&flagGroupedAddend != 0
		hasAddend := groupFlags&flagHasAddend != 0
		if isRela {
			switch {
			case hasAddend && groupedAddend:
				if v, ok := d.next(); ok {
					addend += v
				}
			case !hasAddend:
				addend = 0
			}
		}
		for i := uint64(0); i < groupSize && !d.failed; i++ {
			if groupFlags&flagGroupedDelta == 0 {
				if v, ok := d.next(); ok {
					offset += v
				}
			} else {
				offset += groupDelta
			}
			if groupFlags&flagGroupedInfo == 0 {
				if v, ok := d.next(); ok {
					info = v
				}
			}
			if isRela && hasAddend && !groupedAddend {
				if v, ok := d.next(); ok {
					addend += v
				}
			}
			if e.infoIsRelative(info, relType) {
				if isRela {
					add(offset, addend)
				} else if raw, ok2 := e.rawQword(offset); ok2 {
					add(offset, raw)
				}
			}
		}
		processed += groupSize
	}
}

func (e *ELF) infoIsRelative(info uint64, relType uint64) bool {
	if e.Is64 {
		return info&0xFFFFFFFF == relType
	}
	return info&0xFF == relType
}

// parseRelr decodes SHT_RELR / SHT_ANDROID_RELR: relative relocations whose
// value equals the relocated address itself.
func (e *ELF) parseRelr(b []byte, add func(uint64, uint64)) {
	word := 8
	if !e.Is64 {
		word = 4
	}
	var base uint64
	for off := 0; off+word <= len(b); off += word {
		var v uint64
		if e.Is64 {
			v = binary.LittleEndian.Uint64(b[off : off+word])
		} else {
			v = uint64(binary.LittleEndian.Uint32(b[off : off+word]))
		}
		if v&1 == 0 {
			base = v
			add(base, base)
			base += uint64(word)
		} else {
			bits := uint(8*word - 1)
			for n := uint(1); n <= bits; n++ {
				if v>>n&1 == 1 {
					addr := base + uint64(n-1)*uint64(word)
					add(addr, addr)
				}
			}
			base += uint64(bits) * uint64(word)
		}
	}
	e.relrOK = true
}

type slebDecoder struct {
	b      []byte
	pos    int
	failed bool
}

func (d *slebDecoder) next() (uint64, bool) {
	var result uint64
	var shift uint
	for {
		if d.pos >= len(d.b) {
			d.failed = true
			return 0, false
		}
		c := d.b[d.pos]
		d.pos++
		result |= uint64(c&0x7F) << shift
		if c&0x80 == 0 {
			if c&0x40 != 0 && shift < 64 {
				result |= ^uint64(0) << (shift + 7) // sign extend
			}
			return result, true
		}
		shift += 7
		if shift > 63 {
			d.failed = true
			return 0, false
		}
	}
}

// Sections exposes the parsed section table.
func (e *ELF) Sections() []elfSection { return e.sections }

// Offset maps a virtual address to a file offset.
func (e *ELF) Offset(vaddr uint64) (uint64, bool) {
	for _, s := range e.segments {
		if vaddr >= s.Vaddr && vaddr < s.Vaddr+s.FileSz {
			return s.Off + (vaddr - s.Vaddr), true
		}
	}
	for _, s := range e.sections {
		if s.Type == shtNoBits || s.Addr == 0 {
			continue
		}
		if vaddr >= s.Addr && vaddr < s.Addr+s.Size {
			return s.Off + (vaddr - s.Addr), true
		}
	}
	return 0, false
}

func (e *ELF) rawQword(vaddr uint64) (uint64, bool) {
	off, ok := e.Offset(vaddr)
	if !ok || off+8 > uint64(len(e.Data)) {
		return 0, false
	}
	return binary.LittleEndian.Uint64(e.Data[off : off+8]), true
}

func (e *ELF) rawDword(vaddr uint64) (uint64, bool) {
	off, ok := e.Offset(vaddr)
	if !ok || off+4 > uint64(len(e.Data)) {
		return 0, false
	}
	return uint64(binary.LittleEndian.Uint32(e.Data[off : off+4])), true
}

// ReadBytes returns up to n raw bytes at a virtual address.
func (e *ELF) ReadBytes(vaddr uint64, n int) []byte {
	off, ok := e.Offset(vaddr)
	if !ok {
		return nil
	}
	end := off + uint64(n)
	if end > uint64(len(e.Data)) {
		end = uint64(len(e.Data))
	}
	if off >= end {
		return nil
	}
	return e.Data[off:end]
}

// Qword reads a pointer-sized value at vaddr, honouring relocations so a
// stored pointer resolves to its target even though the on-disk slot is zero.
func (e *ELF) Qword(vaddr uint64) uint64 {
	if v, ok := e.RelocValue(vaddr); ok {
		return v
	}
	if e.Is64 {
		v, _ := e.rawQword(vaddr)
		return v
	}
	v, _ := e.rawDword(vaddr)
	return v
}

// RelocValue returns the loader-applied value for a relocated slot.
func (e *ELF) RelocValue(vaddr uint64) (uint64, bool) {
	i := sort.Search(len(e.relocs), func(i int) bool { return e.relocs[i].Vaddr >= vaddr })
	if i < len(e.relocs) && e.relocs[i].Vaddr == vaddr {
		return e.relocs[i].Value, true
	}
	return 0, false
}

// SlotsWithValue lists virtual addresses of relocation slots holding exactly
// val — the primary way to find structures that point at a known target.
func (e *ELF) SlotsWithValue(val uint64) []uint64 {
	var out []uint64
	for _, r := range e.relocs {
		if r.Value == val {
			out = append(out, r.Vaddr)
		}
	}
	return out
}

// CString reads a NUL-terminated string at vaddr (bounded).
func (e *ELF) CString(vaddr uint64, max int) string {
	b := e.ReadBytes(vaddr, max)
	if b == nil {
		return ""
	}
	if end := bytes.IndexByte(b, 0); end >= 0 {
		return string(b[:end])
	}
	return string(b)
}

// IsExec reports whether a section holds executable code.
func (s elfSection) IsExec() bool { return s.Flags&shfExec != 0 }

// IsAllocData reports whether a section is allocated, non-executable data
// worth scanning for IL2CPP structures.
func (s elfSection) IsAllocData() bool {
	return s.Flags&shfAlloc != 0 && s.Flags&shfExec == 0 && s.Type != shtNoBits
}
