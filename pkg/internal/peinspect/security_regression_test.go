package peinspect

import (
	"encoding/binary"
	"testing"
)

// Independent field offsets from Windows SDK 10.0.26100.0 winnt.h.
// These tests are injected with go -overlay; production sources are unchanged.
func TestRegressionPECFGUsesSDKLayout(t *testing.T) {
	for _, tc := range []struct {
		name                           string
		machine                        uint16
		size, checkOffset, flagsOffset int
	}{
		{"PE32", 0x14c, 92, 72, 88},
		{"PE32plus", 0x8664, 148, 112, 144},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := make([]byte, tc.size)
			binary.LittleEndian.PutUint32(cfg, uint32(len(cfg)))
			binary.LittleEndian.PutUint32(cfg[tc.flagsOffset:], 0x500)
			va := uint64(fixtureImageBase + fixtureTextRVA + 0xf0)
			if tc.machine == 0x8664 {
				binary.LittleEndian.PutUint64(cfg[tc.checkOffset:], va)
				binary.LittleEndian.PutUint64(cfg[128:], fixtureImageBase+fixtureTextRVA+0x100)
				binary.LittleEndian.PutUint64(cfg[136:], 1)
			} else {
				binary.LittleEndian.PutUint32(cfg[tc.checkOffset:], uint32(va))
				binary.LittleEndian.PutUint32(cfg[80:], fixtureImageBase+fixtureTextRVA+0x100)
				binary.LittleEndian.PutUint32(cfg[84:], 1)
			}
			data := buildFixturePE(t, peFixtureOpts{machine: tc.machine, ndirs: true, dllChars: 0x4000, loadCfg: cfg, sehCount: -1})
			// Store a check-function pointer and an in-bounds GFID entry.
			if tc.machine == 0x8664 {
				binary.LittleEndian.PutUint64(data[512+0xf0:], fixtureImageBase+fixtureTextRVA+0x180)
			} else {
				binary.LittleEndian.PutUint32(data[512+0xf0:], fixtureImageBase+fixtureTextRVA+0x180)
			}
			binary.LittleEndian.PutUint32(data[512+0x100:], fixtureTextRVA+0x180)
			data[512+0x180] = 0xc3
			meta, err := Inspect(data)
			if err != nil {
				t.Fatal(err)
			}
			if meta.GuardFlags != 0x500 || !meta.CFValid {
				t.Fatalf("SDK GuardFlags=0x500 and valid check pointer: parsed GuardFlags=%#x CFValid=%v", meta.GuardFlags, meta.CFValid)
			}
		})
	}
}

func TestRegressionPELegacyEditListIsNotCFG(t *testing.T) {
	cfg := make([]byte, 112)
	binary.LittleEndian.PutUint32(cfg, uint32(len(cfg)))
	// Offset 80 is EditList, not GuardCFCheckFunctionPointer, in PE32+.
	binary.LittleEndian.PutUint64(cfg[80:], fixtureImageBase+fixtureTextRVA)
	data := buildFixturePE(t, peFixtureOpts{machine: 0x8664, ndirs: true, dllChars: 0x4000, loadCfg: cfg})
	meta, err := Inspect(data)
	if err != nil {
		t.Fatal(err)
	}
	if meta.CFValid {
		t.Fatal("legacy EditList incorrectly confirms CFG")
	}
}

func TestRegressionPEEmptySectionDoesNotPanic(t *testing.T) {
	data := buildFixturePE(t, peFixtureOpts{machine: 0x14c, ndirs: true})
	sec := 64 + 24 + 96 + 16*8
	binary.LittleEndian.PutUint32(data[sec+16:], 0)
	binary.LittleEndian.PutUint32(data[sec+20:], 0xfffffff0)
	defer func() {
		if value := recover(); value != nil {
			t.Fatalf("empty raw section causes panic: %v", value)
		}
	}()
	_, _ = Inspect(data)
}

func TestRegressionPETLS64StandardDirectory(t *testing.T) {
	data := buildFixturePE(t, peFixtureOpts{machine: 0x8664, ndirs: true})
	dir := 64 + 24 + 112 + 9*8
	binary.LittleEndian.PutUint32(data[dir:], fixtureTextRVA)
	binary.LittleEndian.PutUint32(data[dir+4:], 40)
	binary.LittleEndian.PutUint64(data[512+24:], fixtureImageBase+fixtureTextRVA+128)
	binary.LittleEndian.PutUint64(data[512+128:], fixtureImageBase+fixtureTextRVA+256)
	meta, err := Inspect(data)
	if err != nil {
		t.Fatal(err)
	}
	if meta.TLSCallbacks != 1 {
		t.Fatalf("40-byte IMAGE_TLS_DIRECTORY64: callbacks=%d, want 1", meta.TLSCallbacks)
	}
}

func TestRegressionPEInvalidCertificateCannotHideOverlay(t *testing.T) {
	data := buildFixturePE(t, peFixtureOpts{machine: 0x8664, ndirs: true})
	data = append(data, make([]byte, 256)...)
	dir := 64 + 24 + 112 + 4*8
	binary.LittleEndian.PutUint32(data[dir:], uint32(len(data)+128))
	binary.LittleEndian.PutUint32(data[dir+4:], 256)
	meta, err := Inspect(data)
	if err != nil {
		t.Fatal(err)
	}
	if meta.OverlaySize != 256 {
		t.Fatalf("invalid certificate=%s hides overlay: got %d, want 256", meta.Signature.Status, meta.OverlaySize)
	}
}

func TestRegressionPERelocationsRejectMalformedTail(t *testing.T) {
	data := buildFixturePE(t, peFixtureOpts{machine: 0x14c, ndirs: true})
	dir := 64 + 24 + 96 + 5*8
	binary.LittleEndian.PutUint32(data[dir:], fixtureTextRVA)
	binary.LittleEndian.PutUint32(data[dir+4:], 20)
	binary.LittleEndian.PutUint32(data[512:], fixtureTextRVA)
	binary.LittleEndian.PutUint32(data[516:], 12)
	binary.LittleEndian.PutUint16(data[520:], 0x3100)
	// Second block has an invalid zero BlockSize.
	binary.LittleEndian.PutUint32(data[524:], fixtureTextRVA)
	meta, err := Inspect(data)
	if err != nil {
		return
	}
	if meta.RelocValid {
		t.Fatal("malformed relocation tail accepted as RelocValid=true without an incomplete state")
	}
}
