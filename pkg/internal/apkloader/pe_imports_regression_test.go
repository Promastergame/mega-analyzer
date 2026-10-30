package apkloader

// Regression tests for the 2026-09-21 PE audit: the import table must stay
// readable when only FirstThunk is populated (debug/pe stops at such
// descriptors), W+X sections must be counted for PE, and merging the pure-Go
// pass into a Rust report must deduplicate cross-scanner finding IDs without
// re-scoring the primary report on the Go severity scale.

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// peImportTableFixture builds a minimal PE32+ with one import descriptor for
// kernel32!VirtualAllocEx. OriginalFirstThunk controls the layout under test:
// 0 leaves only FirstThunk populated, as some linkers and packers do.
func peImportTableFixture(oft uint32) []byte {
	b := reviewPENativeSample(0x8664, 0x4140)
	p32 := func(at int, v uint32) { binary.LittleEndian.PutUint32(b[at:], v) }
	binary.LittleEndian.PutUint16(b[0x86:], 1) // NumberOfSections = 1
	p32(0x98+60, 0x200)                        // SizeOfHeaders
	s := 0x98 + 240                            // section table
	copy(b[s:], ".text")
	p32(s+8, 0x200)       // VirtualSize
	p32(s+12, 0x1000)     // VirtualAddress
	p32(s+16, 0x200)      // SizeOfRawData
	p32(s+20, 0x200)      // PointerToRawData
	p32(s+36, 0xe0000020) // W+R+X | CNT_CODE
	// Import directory (dir 1): RVA 0x1000 → file offset 0x200.
	p32(0x98+112+8, 0x1000)
	p32(0x98+112+12, 40)
	// Import descriptor: OriginalFirstThunk, Name RVA 0x1080, FirstThunk RVA 0x1040.
	p32(0x200, oft)
	p32(0x20c, 0x1080)
	p32(0x210, 0x1040)
	binary.LittleEndian.PutUint64(b[0x240:], 0x10a0) // thunk → name RVA
	copy(b[0x280:], "kernel32.dll\x00")              // RVA 0x1080
	copy(b[0x2a2:], "VirtualAllocEx\x00")            // RVA 0x10a0 + 2-byte hint
	return b
}

func TestParsePEImportsFallsBackToFirstThunk(t *testing.T) {
	for _, oft := range []uint32{0x1040, 0} {
		got := parsePEImports(peImportTableFixture(oft))
		if len(got) != 1 || got[0] != "VirtualAllocEx" {
			t.Errorf("OriginalFirstThunk=%#x: imports = %v, want [VirtualAllocEx]", oft, got)
		}
	}
}

func TestNativeGoFlagsImportsWithoutOriginalFirstThunk(t *testing.T) {
	for _, oft := range []uint32{0x1040, 0} {
		r, ok := AnalyzeNativeGo(peImportTableFixture(oft))
		if !ok || r.Verdict == "parse-error" {
			t.Fatalf("OriginalFirstThunk=%#x: fixture not parsed: %+v", oft, r)
		}
		found := false
		for _, f := range r.Findings {
			if f.ID == "import-VirtualAllocEx" {
				found = true
			}
		}
		if !found {
			t.Errorf("OriginalFirstThunk=%#x: import-VirtualAllocEx finding missing: %+v", oft, r.Findings)
		}
	}
}

func TestNativeGoDetectsPEWXSections(t *testing.T) {
	r, ok := AnalyzeNativeGo(peImportTableFixture(0x1040))
	if !ok || r.Verdict == "parse-error" {
		t.Fatalf("fixture not parsed: %+v", r)
	}
	if r.Hardening.WxSections != 1 {
		t.Fatalf("Hardening.WxSections = %d, want 1 (W+X .text section)", r.Hardening.WxSections)
	}
	found := false
	for _, f := range r.Findings {
		if f.ID == "wx-section" {
			found = true
		}
	}
	if !found {
		t.Fatalf("wx-section finding missing: %+v", r.Findings)
	}
}

func TestEnrichNativeReportDedupesAcrossScanners(t *testing.T) {
	dst := &NativeScanReport{Score: 31, Verdict: "low", Findings: []NativeFinding{
		{ID: "no-nx-pe", Severity: "high", Confidence: "high"},
		{ID: "no-aslr-pe", Severity: "medium", Confidence: "high"},
		{ID: "no-cfg-pe", Severity: "medium", Confidence: "high"},
	}}
	src := &NativeScanReport{Findings: []NativeFinding{
		{ID: "no-dep", Severity: "medium", Confidence: "medium"},     // = no-nx-pe
		{ID: "no-aslr", Severity: "medium", Confidence: "medium"},    // = no-aslr-pe
		{ID: "no-cfg", Severity: "low", Confidence: "medium"},        // = no-cfg-pe
		{ID: "entropy-high", Severity: "high", Confidence: "medium"}, // Go-only signal
	}}
	enrichNativeReport(dst, src)

	if len(dst.Findings) != 4 {
		t.Fatalf("got %d findings, want 3 Rust + 1 unique Go: %+v", len(dst.Findings), dst.Findings)
	}
	// The Rust score is a severity×confidence sum with decay and caps;
	// re-deriving it from the Go table once re-scaled every merged report
	// (31/low became 54). The primary scanner owns score and verdict.
	if dst.Score != 31 || dst.Verdict != "low" {
		t.Fatalf("merge re-scored the primary report: score=%d verdict=%s, want 31/low", dst.Score, dst.Verdict)
	}
	ids := map[string]bool{}
	for _, f := range dst.Findings {
		ids[f.ID] = true
	}
	if !ids["entropy-high"] {
		t.Fatalf("unique Go finding dropped: %+v", dst.Findings)
	}
	for _, alias := range []string{"no-dep", "no-aslr", "no-cfg"} {
		if ids[alias] {
			t.Fatalf("unaliased Go finding %q kept alongside its Rust twin: %+v", alias, dst.Findings)
		}
	}
}

func TestParsePEImportsRejectsNonPE(t *testing.T) {
	for name, data := range map[string][]byte{
		"empty":   {},
		"elf":     {0x7f, 'E', 'L', 'F'},
		"no-nt":   bytes.Repeat([]byte{0}, 128),
		"truncpe": peImportTableFixture(0x1040)[:0x120],
	} {
		if got := parsePEImports(data); len(got) != 0 {
			t.Errorf("%s: parsePEImports(%d bytes) = %v, want none", name, len(data), got)
		}
	}
}
