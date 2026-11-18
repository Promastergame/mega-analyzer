package main

import (
	"encoding/binary"
	"errors"
	"testing"
)

// A small Android-format trie: ro.hardware (ranchu), ro.product.model (SDK).
// The product node is hardware's left sibling, exercising the length ordering.
func testArea() []byte {
	data := make([]byte, 2048)
	word := func(at int, v uint32) { binary.LittleEndian.PutUint32(data[at:], v) }
	word(0, 1024)
	word(8, areaMagic)
	word(12, areaVersion)
	word(128+16, 0x20)
	word(128+0x20, 2)
	copy(data[128+0x20+20:], "ro")
	word(128+0x20+16, 0x40)
	word(128+0x40, 8)
	copy(data[128+0x40+20:], "hardware")
	word(128+0x40+4, 0x200)
	word(128+0x40+8, 0x80)
	word(128+0x80, 7)
	copy(data[128+0x80+20:], "product")
	word(128+0x80+16, 0xc0)
	word(128+0xc0, 5)
	copy(data[128+0xc0+20:], "model")
	word(128+0xc0+4, 0x2c0)
	word(128+0x200, 6<<24)
	copy(data[128+0x200+4:], "ranchu")
	copy(data[128+0x200+96:], "ro.hardware")
	word(128+0x2c0, 3<<24)
	copy(data[128+0x2c0+4:], "SDK")
	copy(data[128+0x2c0+96:], "ro.product.model")
	return data
}

func TestLocateAndroidPropertiesAndMissingKeys(t *testing.T) {
	for _, tt := range []struct {
		key    string
		offset int
	}{{"ro.hardware", 128 + 0x200}, {"ro.product.model", 128 + 0x2c0}} {
		got, err := locateProperty(testArea(), tt.key)
		if err != nil || got != tt.offset {
			t.Fatalf("%s: offset=%d, err=%v", tt.key, got, err)
		}
	}
	for _, key := range []string{"ro.product.name", "ro.hardware.extra", "persist.sys.locale"} {
		if _, err := locateProperty(testArea(), key); !errors.Is(err, errNotFound) {
			t.Fatalf("%s: %v", key, err)
		}
	}
}

func TestRejectMalformedAreasWithoutPanicking(t *testing.T) {
	for _, mutate := range []func([]byte){
		func(b []byte) { binary.LittleEndian.PutUint32(b[12:], 0) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[:4], 0xffffffff) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[128+16:], 0xfffffffc) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[128+0x40+8:], 0x40) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[128+0xc0+4:], 3) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[128+0xc0+4:], 0xfffffffc) },
		func(b []byte) { b[128+0x2c0+96] = 'X' },
	} {
		area := testArea()
		mutate(area)
		if _, err := locateProperty(area, "ro.product.model"); err == nil {
			t.Fatal("malformed area accepted")
		}
	}
	for _, length := range []int{0, 20, 128, 200, 900} {
		if _, err := locateProperty(testArea()[:length], "ro.product.model"); err == nil {
			t.Fatal("truncated area accepted")
		}
	}
}
