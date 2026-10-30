package experimental

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func reviewPEFile(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(testTempDir(t), "review.exe")
	if err := os.WriteFile(p, data, 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestReviewPELoadConfig(t *testing.T) {
	for _, is64 := range []bool{false, true} {
		name := "PE32"
		if is64 {
			name = "PE32Plus"
		}
		t.Run(name, func(t *testing.T) {
			data := buildMockPE(is64, 0, false, true, 0, 0)
			clear(data[0x320:0x390])
			binary.LittleEndian.PutUint32(data[0x320:], 112)
			dir := 0x58 + 96
			if is64 {
				dir = 0x58 + 112
			}
			binary.LittleEndian.PutUint32(data[dir+10*8+4:], 112)
			// Offsets specified by IMAGE_LOAD_CONFIG_DIRECTORY32/64 in Windows SDK.
			if is64 {
				binary.LittleEndian.PutUint64(data[0x320+88:], 0x1400010a0)
			} else {
				binary.LittleEndian.PutUint32(data[0x320+60:], 0x4010a0)
			}
			b, err := analyzePE(reviewPEFile(t, data))
			if err != nil {
				t.Fatal(err)
			}
			if !b.HasStackCookie {
				t.Error("valid SecurityCookie VA missed")
			}
			if !is64 && b.SafeSEH {
				t.Error("SafeSEH=true despite absent SEHandlerTable and SEHandlerCount")
			}
		})
	}
}

func TestReviewPEFakeSignature(t *testing.T) {
	b, err := analyzePE(reviewPEFile(t, buildMockPE(true, 0, true, false, 0, 0)))
	if err != nil {
		t.Fatal(err)
	}
	if b.HasEmbeddedSignature || b.Signature.Status != "invalid" {
		t.Error("MOCK_SIGNATURE text accepted as embedded signature")
	}
}

func TestReviewPEOverflow(t *testing.T) {
	data := make([]byte, 64)
	copy(data, "MZ")
	binary.LittleEndian.PutUint32(data[0x3c:], 0xfffffff0)
	defer func() {
		if p := recover(); p != nil {
			t.Errorf("parser panicked: %v", p)
		}
	}()
	if _, err := analyzePE(reviewPEFile(t, data)); err == nil {
		t.Error("invalid offset accepted")
	}
}

func TestReviewPEDirectoryBounds(t *testing.T) {
	data := buildMockPE(false, 0, true, false, 0, 0)
	binary.LittleEndian.PutUint16(data[0x44+2:], 0)
	// No room for any directory in the declared optional header.
	binary.LittleEndian.PutUint16(data[0x44+16:], 96)
	b, err := analyzePE(reviewPEFile(t, data))
	if err == nil && b.HasEmbeddedSignature {
		t.Error("Security Directory read outside SizeOfOptionalHeader")
	}
}

func TestReviewPECandidateExtensions(t *testing.T) {
	root := testTempDir(t)
	for _, ext := range []string{"exe", "scr", "cpl", "efi", "bin"} {
		if err := os.WriteFile(filepath.Join(root, "sample."+ext), buildMockPE(true, 0, false, false, 0, 0), 0600); err != nil {
			t.Fatal(err)
		}
	}
	paths, err := collectPECandidates(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 5 {
		t.Errorf("detected %d of 5 PE files: %v", len(paths), paths)
	}
}

func TestReviewPEMissingRoot(t *testing.T) {
	res, err := NewPEModule().Run(context.Background(), Input{TargetDir: filepath.Join(testTempDir(t), "missing")})
	if err == nil && !res.Skipped {
		t.Error("nonexistent target reported as successfully scanned")
	}
}

func TestReviewPEFindingCount(t *testing.T) {
	res := &ModuleResult{}
	summarizePEBriefing(res, &peBriefing{Path: "sample.exe", Is64Bit: true}, ".")
	if res.Stats["findings"] != len(res.Findings) {
		t.Errorf("stats=%d actual=%d", res.Stats["findings"], len(res.Findings))
	}
}
