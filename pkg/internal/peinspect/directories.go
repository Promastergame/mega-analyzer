package peinspect

import (
	"encoding/binary"
	"fmt"
)

type rvaMapper func(uint64, uint64) (uint64, bool)
type vaValidator func(uint64, uint64) bool

const (
	guardCFInstrumented         = 0x100
	guardCFFunctionTablePresent = 0x400
	maxGuardFunctions           = 1_000_000
	maxTLSCallbacks             = 64
)

func (m *Metadata) diagnostic(format string, args ...any) {
	m.AnalysisStatus = "partial"
	if len(m.Diagnostics) < 64 {
		m.Diagnostics = append(m.Diagnostics, fmt.Sprintf(format, args...))
	}
}

func sectionPermissions(chars uint32) string {
	flags := []byte("---")
	if chars&0x40000000 != 0 {
		flags[0] = 'r'
	}
	if chars&0x80000000 != 0 {
		flags[1] = 'w'
	}
	if chars&0x20000000 != 0 {
		flags[2] = 'x'
	}
	return string(flags)
}

func readPEPointer(data []byte, offset, size uint64) uint64 {
	if size == 8 {
		return binary.LittleEndian.Uint64(data[offset : offset+8])
	}
	return uint64(binary.LittleEndian.Uint32(data[offset : offset+4]))
}

// Offsets are relative to IMAGE_LOAD_CONFIG_DIRECTORY, not the PE optional header.
func (m *Metadata) inspectLoadConfig(cfg []byte, ptrSize uint64, validVA vaValidator, rvaRange rvaMapper, data []byte) {
	cookieAt, checkAt, tableAt, countAt, flagsAt := uint64(60), uint64(72), uint64(80), uint64(84), uint64(88)
	if m.Is64Bit {
		cookieAt, checkAt, tableAt, countAt, flagsAt = 88, 112, 128, 136, 144
	}
	covered := func(off, size uint64) bool { return off <= uint64(len(cfg)) && size <= uint64(len(cfg))-off }
	if covered(cookieAt, ptrSize) {
		cookie := readPEPointer(cfg, cookieAt, ptrSize)
		if cookie != 0 && validVA(cookie, ptrSize) {
			value := true
			m.StackCookie = &value
		}
	}
	if m.SafeSEH != nil && !*m.SafeSEH && covered(64, 8) {
		table := readPEPointer(cfg, 64, 4)
		count := readPEPointer(cfg, 68, 4)
		if table >= m.ImageBase && count > 0 && count <= maxGuardFunctions {
			_, ok := rvaRange(table-m.ImageBase, count*4)
			*m.SafeSEH = ok
		}
	}
	m.CFGStatus = "not_configured"
	if !covered(flagsAt, 4) {
		if m.DllCharacteristics&0x4000 != 0 {
			m.CFGStatus = "incomplete"
			m.diagnostic("CFG flag is set but Load Config does not cover GuardFlags")
		}
		return
	}
	m.GuardFlags = binary.LittleEndian.Uint32(cfg[flagsAt : flagsAt+4])
	if m.GuardFlags&guardCFInstrumented == 0 {
		return
	}
	check := readPEPointer(cfg, checkAt, ptrSize)
	dispatch := readPEPointer(cfg, checkAt+ptrSize, ptrSize)
	if !validVA(check, ptrSize) && !validVA(dispatch, ptrSize) {
		m.CFGStatus = "invalid"
		m.diagnostic("CFG instrumentation has no valid check/dispatch pointer storage")
		return
	}
	if m.GuardFlags&guardCFFunctionTablePresent != 0 {
		table, count := readPEPointer(cfg, tableAt, ptrSize), readPEPointer(cfg, countAt, ptrSize)
		stride := uint64(4 + (m.GuardFlags >> 28))
		if count > maxGuardFunctions {
			m.CFGStatus = "incomplete"
			m.diagnostic("CFG table exceeds %d entries", maxGuardFunctions)
			return
		}
		if table < m.ImageBase || count == 0 {
			m.CFGStatus = "invalid"
			m.diagnostic("CFG function table is missing or empty")
			return
		}
		off, ok := rvaRange(table-m.ImageBase, count*stride)
		if !ok {
			m.CFGStatus = "invalid"
			m.diagnostic("CFG function table exceeds file-backed section data")
			return
		}
		var previous uint64
		for i := uint64(0); i < count; i++ {
			rva := uint64(binary.LittleEndian.Uint32(data[off+i*stride:]))
			if m.ImageBase > ^uint64(0)-rva || !validVA(m.ImageBase+rva, 1) || (i > 0 && rva < previous) {
				m.CFGStatus = "invalid"
				m.diagnostic("CFG function table entry %d is invalid or out of order", i)
				return
			}
			previous = rva
		}
	}
	m.CFValid, m.CFGStatus = true, "validated"
}

func (m *Metadata) inspectTLS(data []byte, rva, size, ptrSize uint64, rvaRange rvaMapper, validVA vaValidator) {
	m.TLSStatus = "invalid"
	minimum := uint64(24)
	if m.Is64Bit {
		minimum = 40
	}
	off, ok := rvaRange(rva, size)
	if !ok || size < minimum {
		m.diagnostic("TLS directory is truncated or out of bounds (need %d bytes)", minimum)
		return
	}
	callbacks := readPEPointer(data, off+3*ptrSize, ptrSize)
	if callbacks == 0 {
		m.TLSStatus = "complete"
		return
	}
	if callbacks < m.ImageBase || callbacks-m.ImageBase >= 1<<32 {
		m.diagnostic("TLS callback array address is outside the image")
		return
	}
	for i := uint64(0); i <= maxTLSCallbacks; i++ {
		ptrOff, ok := rvaRange(callbacks-m.ImageBase+i*ptrSize, ptrSize)
		if !ok {
			m.diagnostic("TLS callback array is unterminated or truncated after %d entries", m.TLSCallbacks)
			return
		}
		address := readPEPointer(data, ptrOff, ptrSize)
		if address == 0 {
			m.TLSStatus = "complete"
			return
		}
		if i == maxTLSCallbacks {
			m.TLSStatus = "partial"
			m.diagnostic("TLS callback limit (%d) reached", maxTLSCallbacks)
			return
		}
		if !validVA(address, 1) {
			m.diagnostic("TLS callback %d points outside the image", i)
			return
		}
		m.TLSCallbacks++
		m.TLSCallbackAddresses = append(m.TLSCallbackAddresses, address)
	}
}

func (m *Metadata) inspectRelocations(data []byte, rva, size uint64, rvaRange rvaMapper, validVA vaValidator) {
	m.RelocationStatus = "invalid"
	off, ok := rvaRange(rva, size)
	if !ok || size < 8 {
		m.diagnostic("Base relocation directory is truncated or out of bounds")
		return
	}
	b := data[off : off+size]
	for len(b) > 0 {
		if len(b) < 8 {
			m.diagnostic("Base relocation directory has a truncated block header")
			return
		}
		page := uint64(binary.LittleEndian.Uint32(b))
		blockSize := uint64(binary.LittleEndian.Uint32(b[4:]))
		if blockSize < 8 || blockSize > uint64(len(b)) || blockSize%4 != 0 || page%4096 != 0 {
			m.diagnostic("Invalid base relocation block at page RVA %#x", page)
			return
		}
		for i := uint64(8); i < blockSize; i += 2 {
			entry := binary.LittleEndian.Uint16(b[i:])
			kind := entry >> 12
			if kind == 0 {
				continue
			} // IMAGE_REL_BASED_ABSOLUTE is alignment padding.
			width := uint64(0)
			switch kind {
			case 1, 2:
				width = 2
			case 3:
				width = 4
			case 4:
				width = 2
				if i+4 > blockSize {
					m.diagnostic("HIGHADJ relocation has no adjustment word")
					return
				}
				i += 2
			case 5, 7:
				if m.Architecture == "arm" {
					width = 8
				}
			case 9:
				if m.Architecture == "ia64" {
					width = 16
				}
			case 10:
				width = 8
			}
			if width == 0 {
				m.RelocationStatus = "unsupported"
				m.diagnostic("Unsupported relocation type %d for %s", kind, m.Architecture)
				return
			}
			target := page + uint64(entry&0xfff)
			if target >= 1<<32 || m.ImageBase > ^uint64(0)-target || !validVA(m.ImageBase+target, width) {
				m.diagnostic("Relocation target RVA %#x is outside the image", target)
				return
			}
			m.RelocationEntries++
			m.HasRelocations = true
		}
		b = b[blockSize:]
	}
	m.RelocValid = m.HasRelocations
	m.RelocationStatus = "complete"
}
