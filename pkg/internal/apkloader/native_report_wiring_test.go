package apkloader

// Wiring tests: the structured PE/CLI analysis must travel with the native
// report (Go fallback fills it, the merge backfills it when Rust ran).

import (
	"encoding/binary"
	"testing"

	"mega-analyzer/pkg/internal/peinspect"
)

func TestEnrichNativeReportBackfillsPEStructure(t *testing.T) {
	pe := &peinspect.Metadata{Architecture: "x86", EntryPointRVA: 0x1000}
	dn := &peinspect.DotNetInfo{IsDotNet: true, AssemblyName: "A"}
	dst := &NativeScanReport{}
	enrichNativeReport(dst, &NativeScanReport{PE: pe, DotNet: dn})
	if dst.PE != pe {
		t.Error("PE structure not backfilled from the Go report")
	}
	if dst.DotNet != dn {
		t.Error("DotNet summary not backfilled from the Go report")
	}

	// The primary scanner wins when it already carries the sections.
	keep := &peinspect.Metadata{Architecture: "x86_64"}
	dst2 := &NativeScanReport{PE: keep}
	enrichNativeReport(dst2, &NativeScanReport{PE: pe, DotNet: dn})
	if dst2.PE != keep {
		t.Error("merge overwrote the primary PE structure")
	}
	if dst2.DotNet != dn {
		t.Error("DotNet summary not backfilled alongside a kept PE")
	}
	enrichNativeReport(nil, dst2) // must not panic
	enrichNativeReport(dst2, nil) // must not panic
}

// minimalNativePE builds a headers-only x86 PE that both peinspect.Inspect
// and debug/pe accept: DOS + PE + COFF + OPT32 + one empty section.
func minimalNativePE() []byte {
	img := make([]byte, 0x400)
	copy(img, []byte("MZ"))
	binary.LittleEndian.PutUint32(img[0x3c:], 0x80)
	copy(img[0x80:], []byte("PE\x00\x00"))
	binary.LittleEndian.PutUint16(img[0x84:], 0x14c)
	binary.LittleEndian.PutUint16(img[0x86:], 1)
	binary.LittleEndian.PutUint16(img[0x94:], 224)
	opt := 0x98
	binary.LittleEndian.PutUint16(img[opt:], 0x10b)
	binary.LittleEndian.PutUint32(img[opt+60:], 0x200)
	binary.LittleEndian.PutUint32(img[opt+92:], 16) // debug/pe requires optSize == 96+8*ndirs
	sec := opt + 224
	copy(img[sec:], []byte(".text\x00\x00\x00"))
	binary.LittleEndian.PutUint32(img[sec+36:], 0x60000020)
	return img
}

func TestAnalyzePEGoCarriesPEStructure(t *testing.T) {
	rep := analyzePEGo(minimalNativePE())
	if rep == nil {
		t.Fatal("analyzePEGo returned nil for a valid minimal PE")
	}
	if rep.TargetFormat != "pe" || rep.TargetArch != "x86" {
		t.Errorf("format/arch = %q/%q, want pe/x86", rep.TargetFormat, rep.TargetArch)
	}
	if rep.PE == nil {
		t.Fatal("PE structure missing from the Go native report")
	}
	if len(rep.PE.Sections) != 1 || rep.PE.Sections[0].Name != ".text" {
		t.Errorf("sections = %+v, want one .text", rep.PE.Sections)
	}
	if rep.PE.Signature.Status != "absent" {
		t.Errorf("signature status = %q, want absent", rep.PE.Signature.Status)
	}
	if rep.DotNet != nil {
		t.Errorf("native image must not carry a DotNet summary: %+v", rep.DotNet)
	}
}
