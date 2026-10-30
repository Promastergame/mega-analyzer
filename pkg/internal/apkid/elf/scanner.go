// Package elf provides a minimal ELF scanner for APKiD use-cases:
// SONAME extraction, section name listing, and UPX stub detection.
// It does NOT implement the full ELF spec — any parse error yields a
// partial ELFInfo with Valid=false.
package elf

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// ELFInfo holds relevant fields extracted from an ELF binary.
type ELFInfo struct {
	// Sections lists all section names (from .shstrtab).
	Sections []string

	// HasUPX is true when UPX magic bytes are found in the first 1 KB.
	HasUPX bool

	// Is64Bit is true for ELF64, false for ELF32.
	Is64Bit bool

	// Valid is true when the ELF header parsed without fatal errors.
	Valid bool
}

var (
	elfMagic      = []byte{0x7f, 'E', 'L', 'F'}
	upxMagic      = []byte("UPX!")
	upxScanWindow = 1024
)

// ScanELF parses the ELF header and extracts fingerprint-relevant metadata.
// It never panics. On any error it returns a partial ELFInfo.
func ScanELF(data []byte) (*ELFInfo, error) {
	info := &ELFInfo{}
	if len(data) < 16 {
		return info, errors.New("elf: too short")
	}
	if !bytes.HasPrefix(data, elfMagic) {
		return info, errors.New("elf: bad magic")
	}

	// Quick UPX scan in first 1 KB (before header parsing, always works).
	scanEnd := upxScanWindow
	if scanEnd > len(data) {
		scanEnd = len(data)
	}
	info.HasUPX = bytes.Contains(data[:scanEnd], upxMagic)

	// EI_CLASS at offset 4: 1=32-bit, 2=64-bit. Anything else selects no
	// valid struct layout — guessing 32-bit would decode garbage section
	// headers (and their names feed packer rules), so reject it.
	class := data[4]
	switch class {
	case 2:
		info.Is64Bit = true
	case 1:
		// 32-bit, handled below.
	default:
		return info, errors.New("elf: bad class byte")
	}

	// EI_DATA at offset 5: 1=little-endian, 2=big-endian.
	var bo binary.ByteOrder = binary.LittleEndian
	if data[5] == 2 {
		bo = binary.BigEndian
	}

	// Parse section header and extract section names.
	var err error
	if info.Is64Bit {
		err = parseSections64(data, bo, info)
	} else {
		err = parseSections32(data, bo, info)
	}
	if err != nil {
		// Non-fatal: continue without section names.
		_ = err
	}

	info.Valid = true
	return info, nil
}

// ─── ELF32 ───────────────────────────────────────────────────────────────────

// All header arithmetic is uint64: int(u32) wraps on 32-bit builds, and a
// wrapped bounds check passes negative offsets to the slicer (panic). The
// 64-bit path had the same hole via int(u64) on every platform.

func parseSections32(data []byte, bo binary.ByteOrder, info *ELFInfo) error {
	size := uint64(len(data))
	if size < 52 {
		return errors.New("elf32: header too short")
	}
	shOff := uint64(bo.Uint32(data[32:36]))
	shEntSize := uint64(bo.Uint16(data[46:48]))
	shNum := uint64(bo.Uint16(data[48:50]))
	shStrIdx := uint64(bo.Uint16(data[50:52]))

	if shEntSize < 40 || shNum == 0 || shOff == 0 {
		return nil // no sections
	}
	// Subtraction avoids wrapping hostile ELF64 offsets before the check.
	if shOff > size || shNum*shEntSize > size-shOff {
		return errors.New("elf32: section headers overflow")
	}
	if shStrIdx >= shNum {
		return errors.New("elf32: invalid shstrndx")
	}

	// Read .shstrtab section header.
	shstrOff := shOff + shStrIdx*shEntSize
	shstrDataOff := uint64(bo.Uint32(data[shstrOff+16 : shstrOff+20]))
	shstrSize := uint64(bo.Uint32(data[shstrOff+20 : shstrOff+24]))
	if shstrDataOff > size || shstrSize > size-shstrDataOff {
		return errors.New("elf32: shstrtab overflow")
	}
	strtab := data[shstrDataOff : shstrDataOff+shstrSize]

	for i := uint64(0); i < shNum; i++ {
		shBase := shOff + i*shEntSize
		nameOff := uint64(bo.Uint32(data[shBase : shBase+4]))
		name := cstring(strtab, nameOff)
		if name != "" {
			info.Sections = append(info.Sections, name)
		}
	}
	return nil
}

// ─── ELF64 ───────────────────────────────────────────────────────────────────

func parseSections64(data []byte, bo binary.ByteOrder, info *ELFInfo) error {
	size := uint64(len(data))
	if size < 64 {
		return errors.New("elf64: header too short")
	}
	shOff := bo.Uint64(data[40:48])
	shEntSize := uint64(bo.Uint16(data[58:60]))
	shNum := uint64(bo.Uint16(data[60:62]))
	shStrIdx := uint64(bo.Uint16(data[62:64]))

	if shEntSize < 64 || shNum == 0 || shOff == 0 {
		return nil
	}
	// Subtraction avoids wrapping hostile ELF64 offsets before the check.
	if shOff > size || shNum*shEntSize > size-shOff {
		return errors.New("elf64: section headers overflow")
	}
	if shStrIdx >= shNum {
		return errors.New("elf64: invalid shstrndx")
	}

	shstrBase := shOff + shStrIdx*shEntSize
	shstrDataOff := bo.Uint64(data[shstrBase+24 : shstrBase+32])
	shstrSize := bo.Uint64(data[shstrBase+32 : shstrBase+40])
	if shstrDataOff > size || shstrSize > size-shstrDataOff {
		return errors.New("elf64: shstrtab overflow")
	}
	strtab := data[shstrDataOff : shstrDataOff+shstrSize]

	for i := uint64(0); i < shNum; i++ {
		shBase := shOff + i*shEntSize
		nameOff := uint64(bo.Uint32(data[shBase : shBase+4]))
		name := cstring(strtab, nameOff)
		if name != "" {
			info.Sections = append(info.Sections, name)
		}
	}
	return nil
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// cstring reads a null-terminated string from strtab at offset off.
func cstring(strtab []byte, off uint64) string {
	if off >= uint64(len(strtab)) {
		return ""
	}
	end := off
	for end < uint64(len(strtab)) && strtab[end] != 0 {
		end++
	}
	return string(strtab[off:end])
}
