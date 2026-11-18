package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteMappedReadOnlyPropertyAndPreserveOtherIdentity(t *testing.T) {
	for _, oldSerial := range []uint32{3 << 24, 99<<24 | longFlag} {
		area := testArea()
		binary.LittleEndian.PutUint32(area[128+0x2c0:], oldSerial)
		path := filepath.Join(t.TempDir(), "area")
		if err := os.WriteFile(path, area, 0600); err != nil {
			t.Fatal(err)
		}
		if err := writeProperty(path, "ro.product.model", "Pixel 3"); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		offset, err := locateProperty(got, "ro.product.model")
		if err != nil {
			t.Fatal(err)
		}
		serial := binary.LittleEndian.Uint32(got[offset:])
		if serial>>24 != 7 || serial&(longFlag|1) != 0 || string(got[offset+4:offset+11]) != "Pixel 3" {
			t.Fatalf("invalid committed value: serial=%x", serial)
		}
		if !bytes.Equal(got[128+0x200:128+0x200+infoNameOffset+12], area[128+0x200:128+0x200+infoNameOffset+12]) {
			t.Fatal("unrelated hardware property changed")
		}
	}
}

func TestActivePropertyWriterIsNotOverwritten(t *testing.T) {
	area := testArea()
	binary.LittleEndian.PutUint32(area[128+0x2c0:], 3<<24|1)
	path := filepath.Join(t.TempDir(), "area")
	if err := os.WriteFile(path, area, 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeProperty(path, "ro.product.model", "Pixel 3"); err == nil {
		t.Fatal("active writer overwritten")
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, area) {
		t.Fatal("rejected write modified the area")
	}
}
