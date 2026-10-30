package elf

import (
	"encoding/binary"
	"reflect"
	"testing"
)

func elfFixture(bits int, bo binary.ByteOrder) []byte {
	const tab = "\x00.text\x00.shstrtab\x00"
	header, entry := 52, 40
	if bits == 64 {
		header, entry = 64, 64
	}
	b := make([]byte, header+3*entry+len(tab))
	copy(b, elfMagic)
	b[4] = 1
	if bits == 64 {
		b[4] = 2
	}
	b[5] = 1
	if bo == binary.BigEndian {
		b[5] = 2
	}
	if bits == 64 {
		bo.PutUint64(b[40:], uint64(header))
		bo.PutUint16(b[58:], uint16(entry))
		bo.PutUint16(b[60:], 3)
		bo.PutUint16(b[62:], 2)
		base := header + 2*entry
		bo.PutUint64(b[base+24:], uint64(header+3*entry))
		bo.PutUint64(b[base+32:], uint64(len(tab)))
	} else {
		bo.PutUint32(b[32:], uint32(header))
		bo.PutUint16(b[46:], uint16(entry))
		bo.PutUint16(b[48:], 3)
		bo.PutUint16(b[50:], 2)
		base := header + 2*entry
		bo.PutUint32(b[base+16:], uint32(header+3*entry))
		bo.PutUint32(b[base+20:], uint32(len(tab)))
	}
	bo.PutUint32(b[header+entry:], 1)
	bo.PutUint32(b[header+2*entry:], 7)
	copy(b[header+3*entry:], tab)
	return b
}

func TestELFSectionTablesBothClassesAndEndiannesses(t *testing.T) {
	for _, bits := range []int{32, 64} {
		for _, bo := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
			info, err := ScanELF(elfFixture(bits, bo))
			if err != nil || !info.Valid || info.Is64Bit != (bits == 64) || !reflect.DeepEqual(info.Sections, []string{".text", ".shstrtab"}) {
				t.Fatalf("ELF%d %T=%+v %v", bits, bo, info, err)
			}
		}
	}
}

func TestELFInvalidHeadersAndUPXWindow(t *testing.T) {
	for _, b := range [][]byte{nil, make([]byte, 16), append(append([]byte(nil), elfMagic...), make([]byte, 12)...)} {
		info, err := ScanELF(b)
		if err == nil || info == nil || info.Valid {
			t.Fatalf("bad header=%+v %v", info, err)
		}
	}
	b := elfFixture(64, binary.LittleEndian)
	b = append(b, make([]byte, 2048)...)
	copy(b[100:], "UPX!")
	info, err := ScanELF(b)
	if err != nil || !info.HasUPX {
		t.Fatal("UPX in scan window missed")
	}
	copy(b[100:], "none")
	copy(b[1500:], "UPX!")
	info, err = ScanELF(b)
	if err != nil || info.HasUPX {
		t.Fatal("UPX outside scan window detected")
	}
	for _, bits := range []int{32, 64} {
		b = make([]byte, 16)
		copy(b, elfMagic)
		b[4] = 1
		if bits == 64 {
			b[4] = 2
		}
		info, err = ScanELF(b)
		if err != nil || !info.Valid || len(info.Sections) != 0 {
			t.Fatal("partial ELF should retain header metadata")
		}
	}
}

func TestELFSectionBounds(t *testing.T) {
	for _, bits := range []int{32, 64} {
		parse := parseSections32
		if bits == 64 {
			parse = parseSections64
		}
		if err := parse(nil, binary.LittleEndian, &ELFInfo{}); err == nil {
			t.Fatal("short section header")
		}
		empty := make([]byte, 64)
		if err := parse(empty, binary.LittleEndian, &ELFInfo{}); err != nil {
			t.Fatal(err)
		}
		for _, kind := range []string{"headers", "index", "strings", "wrapped-headers", "wrapped-strings"} {
			b := elfFixture(bits, binary.LittleEndian)
			bo := binary.LittleEndian
			if bits == 32 {
				switch kind {
				case "headers", "wrapped-headers":
					bo.PutUint32(b[32:], 0xffffffff)
				case "index":
					bo.PutUint16(b[50:], 3)
				case "strings", "wrapped-strings":
					bo.PutUint32(b[52+2*40+16:], 0xffffffff)
				}
			} else {
				switch kind {
				case "headers":
					bo.PutUint64(b[40:], uint64(len(b)))
				case "index":
					bo.PutUint16(b[62:], 3)
				case "strings":
					bo.PutUint64(b[64+2*64+24:], uint64(len(b)))
				case "wrapped-headers":
					bo.PutUint64(b[40:], ^uint64(0)-64)
				case "wrapped-strings":
					bo.PutUint64(b[64+2*64+24:], ^uint64(0)-8)
				}
			}
			if err := parse(b, bo, &ELFInfo{}); err == nil {
				t.Errorf("ELF%d %s bounds accepted", bits, kind)
			}
		}
	}
	for _, tt := range []struct {
		b    []byte
		off  uint64
		want string
	}{{[]byte("a\x00b"), 0, "a"}, {[]byte("abc"), 1, "bc"}, {nil, 0, ""}, {[]byte("a"), 99, ""}} {
		if got := cstring(tt.b, tt.off); got != tt.want {
			t.Errorf("cstring=%q", got)
		}
	}
}
