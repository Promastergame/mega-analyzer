package apkloader

import (
	"bytes"
	"encoding/binary"
)

const (
	peMaxImportDLLs   = 4096
	peMaxImportThunks = 65536 // shared by all descriptors, including ordinal imports
	peMaxImportNames  = 16384
)

type peImportResult struct {
	Names    []string
	Delayed  int
	Warnings []string
}

// parsePEImports includes normal and delay-load imports, with FirstThunk/IAT
// fallback per descriptor. A partial standard-library result must not hide
// later descriptors. No walk may leave the raw section backing it.
func parsePEImports(data []byte) []string { return inspectPEImports(data).Names }

func inspectPEImports(data []byte) peImportResult {
	var result peImportResult
	warn := func(message string) {
		for _, existing := range result.Warnings {
			if existing == message {
				return
			}
		}
		result.Warnings = append(result.Warnings, message)
	}
	le := binary.LittleEndian
	span := func(off, n uint64) bool { return off <= uint64(len(data)) && n <= uint64(len(data))-off }
	u16 := func(off uint64) uint16 { return le.Uint16(data[off : off+2]) }
	u32 := func(off uint64) uint64 { return uint64(le.Uint32(data[off : off+4])) }
	if !span(0, 64) || string(data[:2]) != "MZ" {
		return result
	}
	pe := u32(0x3c)
	if pe < 64 || !span(pe, 24) || string(data[pe:pe+4]) != "PE\x00\x00" {
		return result
	}
	opt, optSize := pe+24, uint64(u16(pe+20))
	if optSize < 2 || !span(opt, optSize) {
		return result
	}
	fixed, ptrSize, ordinal := uint64(96), uint64(4), uint64(1)<<31
	switch u16(opt) {
	case 0x10b:
	case 0x20b:
		fixed, ptrSize, ordinal = 112, 8, uint64(1)<<63
	default:
		return result
	}
	if optSize < fixed {
		return result
	}
	ndirs := u32(opt + fixed - 4)
	if ndirs > (optSize-fixed)/8 {
		warn("data directories exceed the optional header")
		return result
	}
	imageBase := u32(opt + 28)
	if ptrSize == 8 {
		imageBase = le.Uint64(data[opt+24 : opt+32])
	}
	type section struct{ va, raw, size uint64 }
	nsec, secAt := uint64(u16(pe+6)), opt+optSize
	if nsec > 512 || !span(secAt, nsec*40) {
		warn("invalid section table")
		return result
	}
	headers := u32(opt + 60)
	if headers == 0 {
		headers = secAt + nsec*40
	}
	if !span(0, headers) {
		warn("headers exceed the file")
		return result
	}
	sections := make([]section, 0, nsec)
	for i := uint64(0); i < nsec; i++ {
		at := secAt + i*40
		s := section{u32(at + 12), u32(at + 20), u32(at + 16)}
		if !span(s.raw, s.size) || s.va+s.size > 1<<32 {
			warn("invalid raw section range")
			return result
		}
		sections = append(sections, s)
	}
	// VirtualSize can include zero-fill: those RVAs do not address file bytes.
	rvaSpan := func(rva, need uint64) (uint64, uint64, bool) {
		if rva == 0 || rva >= 1<<32 || need > 1<<32-rva {
			return 0, 0, false
		}
		if rva < headers && need <= headers-rva {
			return rva, headers - rva, true
		}
		for _, s := range sections {
			if rva >= s.va && rva-s.va < s.size {
				delta := rva - s.va
				if need <= s.size-delta {
					return s.raw + delta, s.size - delta, true
				}
			}
		}
		return 0, 0, false
	}
	readName := func(rva, skip uint64) (string, bool) {
		off, remaining, ok := rvaSpan(rva, skip+1)
		if !ok {
			return "", false
		}
		length := remaining - skip
		if length > 4096 {
			length = 4096
		}
		name := data[off+skip : off+skip+length]
		end := bytes.IndexByte(name, 0)
		if end <= 0 {
			return "", false
		}
		return string(name[:end]), true
	}
	toRVA := func(value uint64, legacyVA bool) (uint64, bool) {
		if legacyVA {
			if value < imageBase {
				return 0, false
			}
			value -= imageBase
		}
		return value, value > 0 && value < 1<<32
	}
	seen := make(map[string]bool)
	budget := peMaxImportThunks
	for _, table := range []struct {
		index, stride uint64
		label         string
		delayed       bool
	}{{1, 20, "import table", false}, {13, 32, "delay import table", true}} {
		if table.index >= ndirs {
			continue
		}
		dir := opt + fixed + table.index*8
		rva, size := u32(dir), u32(dir+4)
		if rva == 0 && size == 0 {
			continue
		}
		off, _, ok := rvaSpan(rva, size)
		if !ok || size < table.stride {
			warn(table.label + ": invalid directory range")
			continue
		}
		terminated := false
		for d := uint64(0); d < size/table.stride && d < peMaxImportDLLs; d++ {
			at := off + d*table.stride
			empty := true
			for j := uint64(0); j < table.stride; j += 4 {
				empty = empty && u32(at+j) == 0
			}
			if empty {
				terminated = true
				break
			}
			nameRVA, thunkRVA := u32(at+12), u32(at)
			legacyVA := false
			if table.delayed {
				attrs := u32(at)
				if attrs > 1 {
					warn(table.label + ": unsupported descriptor attributes")
					continue
				}
				legacyVA = attrs == 0
				nameRVA, thunkRVA = u32(at+4), u32(at+16)
				if thunkRVA == 0 {
					thunkRVA = u32(at + 12)
				}
			} else if thunkRVA == 0 {
				thunkRVA = u32(at + 16)
			}
			nameRVA, nameOK := toRVA(nameRVA, legacyVA)
			thunkRVA, thunkOK := toRVA(thunkRVA, legacyVA)
			if _, ok := readName(nameRVA, 0); !nameOK || !thunkOK || !ok {
				warn(table.label + ": invalid DLL name or thunk address")
				continue
			}
			thunkOff, remaining, ok := rvaSpan(thunkRVA, ptrSize)
			if !ok {
				warn(table.label + ": thunk array has no file backing")
				continue
			}
			thunkTerminated := false
			for t := uint64(0); t < remaining/ptrSize; t++ {
				if budget == 0 {
					warn("import scan work limit reached; coverage is incomplete")
					return result
				}
				budget--
				value := u32(thunkOff + t*ptrSize)
				if ptrSize == 8 {
					value = le.Uint64(data[thunkOff+t*ptrSize : thunkOff+(t+1)*ptrSize])
				}
				if value == 0 {
					thunkTerminated = true
					break
				}
				if value&ordinal != 0 {
					continue // ordinal imports have no symbol name
				}
				nameRVA, ok := toRVA(value, legacyVA)
				name, nameOK := readName(nameRVA, 2)
				if !ok || !nameOK {
					warn(table.label + ": invalid or unterminated import name")
					continue
				}
				if table.delayed {
					result.Delayed++
				}
				if !seen[name] {
					seen[name] = true
					result.Names = append(result.Names, name)
					if len(result.Names) >= peMaxImportNames {
						warn("import name limit reached; coverage is incomplete")
						return result
					}
				}
			}
			if !thunkTerminated {
				warn(table.label + ": unterminated thunk array")
			}
		}
		if !terminated {
			warn(table.label + ": descriptor terminator missing or descriptor limit reached")
		}
	}
	return result
}
