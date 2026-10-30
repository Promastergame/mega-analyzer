package apkid

import (
	"encoding/binary"
	"testing"

	elfpkg "mega-analyzer/pkg/internal/apkid/elf"
)

// Review round: hostile ELF section offsets (64-bit panic before the uint64
// rewrite), EI_CLASS validation, SONAME field removal.

// buildELF64 crafts a minimal ELF64 with one section named ".text".
func buildELF64(t *testing.T, shoff uint64, class byte) []byte {
	t.Helper()
	buf := make([]byte, 64)
	copy(buf[0:], []byte{0x7f, 'E', 'L', 'F', class, 1, 1, 0})
	binary.LittleEndian.PutUint16(buf[16:], 2)     // ET_EXEC
	binary.LittleEndian.PutUint16(buf[18:], 0x3E)  // x86-64
	binary.LittleEndian.PutUint32(buf[20:], 1)     // version
	binary.LittleEndian.PutUint64(buf[40:], shoff) // shoff
	binary.LittleEndian.PutUint16(buf[58:], 64)    // shentsize
	binary.LittleEndian.PutUint16(buf[60:], 1)     // shnum
	binary.LittleEndian.PutUint16(buf[62:], 0)     // shstrndx
	if shoff != 0 && shoff < 1<<32 {
		for uint64(len(buf)) < shoff+64 {
			buf = append(buf, 0)
		}
		sec := make([]byte, 64)
		binary.LittleEndian.PutUint32(sec[0:], 1)    // name offset
		binary.LittleEndian.PutUint32(sec[4:], 1)    // PROGBITS
		binary.LittleEndian.PutUint64(sec[24:], 128) // sh_offset
		binary.LittleEndian.PutUint64(sec[32:], 7)   // sh_size
		copy(buf[shoff:], sec)
		for uint64(len(buf)) < 128 {
			buf = append(buf, 0)
		}
		buf = append(buf, 0)
		buf = append(buf, []byte(".text")...)
		buf = append(buf, 0)
	}
	return buf
}

func TestReviewELF64Sections(t *testing.T) {
	info, err := elfpkg.ScanELF(buildELF64(t, 64, 2))
	if err != nil {
		t.Fatalf("ScanELF: %v", err)
	}
	if !info.Valid || !info.Is64Bit {
		t.Errorf("expected valid 64-bit, got %+v", info)
	}
	if len(info.Sections) != 1 || info.Sections[0] != ".text" {
		t.Errorf("sections = %v, want [.text]", info.Sections)
	}
}

func TestReviewELF64HostileShoffNoPanic(t *testing.T) {
	data := buildELF64(t, 64, 2)
	// Corrupt shoff in place to a huge value: int() conversion used to wrap
	// it negative, slip past the bounds check, and panic the slicer.
	// Section errors are non-fatal by design (partial info), so the contract
	// is: no panic, no phantom sections.
	binary.LittleEndian.PutUint64(data[40:], 0xFFFFFFFFFFFFFF00)
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ScanELF panicked on hostile shoff: %v", r)
			}
		}()
		info, err := elfpkg.ScanELF(data)
		if err != nil {
			t.Fatalf("section errors are non-fatal, got err: %v", err)
		}
		if len(info.Sections) != 0 {
			t.Errorf("hostile shoff should yield no sections, got %v", info.Sections)
		}
	}()
}

func TestReviewELFBadClass(t *testing.T) {
	for _, class := range []byte{0, 3, 9} {
		info, err := elfpkg.ScanELF(buildELF64(t, 64, class))
		if err == nil {
			t.Errorf("class %d: expected error, got %+v", class, info)
		}
		if info.Valid {
			t.Errorf("class %d: Valid must be false", class)
		}
	}
}
