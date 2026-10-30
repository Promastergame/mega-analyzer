package dex

import (
	"encoding/binary"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// Synthetic header: no external APK or proprietary fixture is required.
func testDEX() []byte {
	b := make([]byte, headerSize)
	copy(b, "dex\n039\x00")
	binary.LittleEndian.PutUint32(b[32:], uint32(len(b)))
	binary.LittleEndian.PutUint32(b[40:], 0x12345678)
	return b
}

func TestParseDEXHeaderAndWarnings(t *testing.T) {
	info, err := ParseDEX(nil)
	if !errors.Is(err, errTooShort) || info == nil || info.Valid {
		t.Fatalf("short=%+v %v", info, err)
	}
	b := testDEX()
	b[0] = '!'
	if info, err = ParseDEX(b); err == nil || info.Valid {
		t.Fatal("bad magic accepted")
	}
	b = testDEX()
	b[40] = 0
	info, err = ParseDEX(b)
	if err != nil || info.Valid || len(info.Warnings) != 1 {
		t.Fatalf("endian=%+v %v", info, err)
	}
	b = testDEX()
	info, err = ParseDEX(b)
	if err != nil || !info.Valid || info.Version != "039" || len(info.Warnings) != 0 {
		t.Fatalf("valid=%+v %v", info, err)
	}
	b[7] = 1
	binary.LittleEndian.PutUint32(b[32:], 99999)
	binary.LittleEndian.PutUint32(b[52:], 0xffffffff)
	binary.LittleEndian.PutUint32(b[56:], 1)
	binary.LittleEndian.PutUint32(b[60:], 0xffffffff)
	info, err = ParseDEX(b)
	if err != nil || len(info.Warnings) != 4 {
		t.Fatalf("warnings=%+v %v", info, err)
	}
	for _, part := range []string{"terminator", "file_size", "map_list", "string_pool"} {
		if !strings.Contains(strings.Join(info.Warnings, ";"), part) {
			t.Errorf("missing warning %s", part)
		}
	}
}

func TestDEXStringTableIntegration(t *testing.T) {
	b := testDEX()
	b = append(b, make([]byte, 8)...)
	binary.LittleEndian.PutUint32(b[56:], 2)
	binary.LittleEndian.PutUint32(b[60:], headerSize)
	s := "com.android.tools.r8"
	binary.LittleEndian.PutUint32(b[headerSize:], uint32(len(b)))
	b = append(b, byte(len(s)))
	b = append(b, []byte(s)...)
	b = append(b, 0)
	binary.LittleEndian.PutUint32(b[headerSize+4:], 0xffffffff)
	binary.LittleEndian.PutUint32(b[32:], uint32(len(b)))
	info, err := ParseDEX(b)
	if err != nil || !info.Valid || !reflect.DeepEqual(info.StringPool, []string{s}) || info.Compiler != "d8/r8" {
		t.Fatalf("parsed=%+v %v", info, err)
	}
}

func TestMapListBoundsAndOrdering(t *testing.T) {
	for _, tt := range []struct {
		name  string
		off   uint32
		count uint32
		size  int
		want  string
	}{
		{"offset", 0xffffffff, 0, 4, "out of bounds"}, {"count", 0, 1025, 4, "implausibly"}, {"truncated", 0, 1, 4, "overflows"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b := make([]byte, tt.size)
			binary.LittleEndian.PutUint32(b, tt.count)
			err := parseMapList(b, tt.off, &DEXInfo{})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	b := make([]byte, 28)
	binary.LittleEndian.PutUint32(b, 2)
	binary.LittleEndian.PutUint16(b[4:], TypeCodeItem)
	binary.LittleEndian.PutUint16(b[16:], TypeDebugInfoItem)
	info := &DEXInfo{}
	if err := parseMapList(b, 0, info); err != nil || !reflect.DeepEqual(info.MapOrder, []uint16{TypeCodeItem, TypeDebugInfoItem}) {
		t.Fatalf("map=%v err=%v", info.MapOrder, err)
	}
	b = testDEX()
	binary.LittleEndian.PutUint32(b[52:], uint32(len(b)))
	b = append(b, make([]byte, 28)...)
	copy(b[headerSize:], []byte{2, 0, 0, 0})
	binary.LittleEndian.PutUint16(b[headerSize+4:], TypeCodeItem)
	binary.LittleEndian.PutUint16(b[headerSize+16:], TypeDebugInfoItem)
	parsed, err := ParseDEX(b)
	if err != nil || parsed.Compiler != "dx" {
		t.Fatalf("map heuristic=%+v %v", parsed, err)
	}
}

func TestULEB128AndStrings(t *testing.T) {
	for _, tt := range []struct {
		b []byte
		v uint32
		n int
	}{
		{nil, 0, 0}, {[]byte{0}, 0, 1}, {[]byte{0x7f}, 127, 1}, {[]byte{0xe5, 0x8e, 0x26}, 624485, 3}, {[]byte{0xff, 0xff, 0xff, 0xff, 0x0f}, 0xffffffff, 5}, {[]byte{0x80}, 0, 0}, {[]byte{0x80, 0x80, 0x80, 0x80, 0x80, 0}, 0, 0},
	} {
		v, n := decodeULEB128(tt.b)
		if v != tt.v || n != tt.n {
			t.Errorf("ULEB %x=%d,%d want %d,%d", tt.b, v, n, tt.v, tt.n)
		}
	}
	for _, tt := range []struct {
		b    []byte
		off  uint32
		want string
		bad  bool
	}{
		{nil, 0, "", true}, {[]byte{0x80}, 0, "", true}, {[]byte{0x81, 0x80, 0x04, 0}, 0, "", true}, {[]byte{1, 'a'}, 0, "", true}, {[]byte{0, 0}, 0, "", false}, {[]byte{3, 'a', 'b', 'c', 0}, 0, "abc", false},
	} {
		s, err := readMUTF8(tt.b, tt.off)
		if (err != nil) != tt.bad || s != tt.want {
			t.Errorf("string %x=%q,%v", tt.b, s, err)
		}
	}
	info := &DEXInfo{}
	if err := parseStringPool(nil, 0, 0, info); err != nil {
		t.Fatal(err)
	}
	if err := parseStringPool(nil, 0xffffffff, 1, info); err == nil {
		t.Fatal("table overflow accepted")
	}
	b := make([]byte, 50001*4)
	for i := 0; i < 50001; i++ {
		binary.LittleEndian.PutUint32(b[i*4:], 0xffffffff)
	}
	if err := parseStringPool(b, 0, 50001, info); err != nil || len(info.Warnings) != 1 || len(info.StringPool) != 0 {
		t.Fatalf("cap: %+v %v", info, err)
	}
}

func TestCompilerHeuristics(t *testing.T) {
	for _, tt := range []struct {
		s     string
		order []uint16
		want  string
	}{
		{"com.android.jack", nil, "jack"}, {"com/android/jack", nil, "jack"}, {"jf.dexlib2", nil, "dexlib2"}, {"dexlib2.writer", nil, "dexlib2"}, {"com.android.tools.r8", nil, "d8/r8"},
		{"", []uint16{TypeAnnotationSetRefList, TypeCodeItem, TypeDebugInfoItem}, "d8/r8"},
		{"", []uint16{TypeCodeItem, TypeCodeItem, TypeDebugInfoItem}, ""},
		{"", []uint16{TypeCodeItem, TypeDebugInfoItem, TypeDebugInfoItem}, "dx"},
		{"", []uint16{TypeCodeItem, TypeAnnotationSetRefList, TypeAnnotationSetRefList}, ""},
		{"unknown", nil, ""},
	} {
		got := inferCompiler(&DEXInfo{StringPool: []string{tt.s}, MapOrder: tt.order})
		if got != tt.want {
			t.Errorf("compiler %q %v=%q want %q", tt.s, tt.order, got, tt.want)
		}
	}
}
