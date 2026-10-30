package experimental

import (
	"testing"
)

// ─── binsim.go ────────────────────────────────────────────────────────────

func TestJaccard_BothEmpty(t *testing.T) {
	got := jaccard(map[uint64]struct{}{}, map[uint64]struct{}{})
	if got != 0 {
		t.Errorf("expected 0 for empty sets, got %f", got)
	}
}

func TestJaccard_OneEmpty(t *testing.T) {
	a := map[uint64]struct{}{1: {}, 2: {}}
	b := map[uint64]struct{}{}
	got := jaccard(a, b)
	if got != 0 {
		t.Errorf("expected 0 when one set empty, got %f", got)
	}
}

func TestJaccard_Identical(t *testing.T) {
	a := map[uint64]struct{}{1: {}, 2: {}, 3: {}}
	b := map[uint64]struct{}{1: {}, 2: {}, 3: {}}
	got := jaccard(a, b)
	if got != 1.0 {
		t.Errorf("expected 1.0 for identical sets, got %f", got)
	}
}

func TestJaccard_NoOverlap(t *testing.T) {
	a := map[uint64]struct{}{1: {}, 2: {}}
	b := map[uint64]struct{}{3: {}, 4: {}}
	got := jaccard(a, b)
	if got != 0.0 {
		t.Errorf("expected 0.0 for disjoint sets, got %f", got)
	}
}

func TestJaccard_PartialOverlap(t *testing.T) {
	a := map[uint64]struct{}{1: {}, 2: {}, 3: {}}
	b := map[uint64]struct{}{2: {}, 3: {}, 4: {}}
	got := jaccard(a, b)
	// intersection=2, union=4 → 0.5
	if got < 0.49 || got > 0.51 {
		t.Errorf("expected ~0.5, got %f", got)
	}
}

func TestJaccard_BiggerBAsSmaller(t *testing.T) {
	// Test branch where big < small (swaps)
	a := map[uint64]struct{}{1: {}, 2: {}, 3: {}, 4: {}, 5: {}}
	b := map[uint64]struct{}{1: {}, 2: {}}
	got := jaccard(a, b)
	// intersection=2, union=5 → 0.4
	if got < 0.39 || got > 0.41 {
		t.Errorf("expected ~0.4, got %f", got)
	}
}

// ─── elf.go ───────────────────────────────────────────────────────────────

func TestEndianStr_Big(t *testing.T) {
	if endianStr(2) != "Big" {
		t.Errorf("expected 'Big' for data=2, got %q", endianStr(2))
	}
}

func TestEndianStr_Little(t *testing.T) {
	if endianStr(1) != "Little" {
		t.Errorf("expected 'Little' for data=1, got %q", endianStr(1))
	}
}

func TestRelroStr_None(t *testing.T) {
	if relroStr(false, false) != "None" {
		t.Errorf("expected 'None'")
	}
}

func TestRelroStr_Partial(t *testing.T) {
	if relroStr(true, false) != "Partial" {
		t.Errorf("expected 'Partial'")
	}
}

func TestRelroStr_Full(t *testing.T) {
	if relroStr(true, true) != "Full" {
		t.Errorf("expected 'Full'")
	}
}

func TestELFReader_U32_LittleEndian(t *testing.T) {
	data := []byte{0x01, 0x00, 0x00, 0x00} // LE = 1
	r := newELFReader(data, false)
	if r.u32(0) != 1 {
		t.Errorf("expected 1, got %d", r.u32(0))
	}
}

func TestELFReader_U32_BigEndian(t *testing.T) {
	data := []byte{0x00, 0x00, 0x00, 0x01} // BE = 1
	r := newELFReader(data, true)
	if r.u32(0) != 1 {
		t.Errorf("expected 1, got %d", r.u32(0))
	}
}

func TestELFReader_U32_OutOfBounds(t *testing.T) {
	data := []byte{0x01, 0x02}
	r := newELFReader(data, false)
	if r.u32(0) != 0 {
		t.Errorf("expected 0 on out-of-bounds, got %d", r.u32(0))
	}
}

func TestELFReader_U16_BothEndians(t *testing.T) {
	data := []byte{0x00, 0x01}
	rLE := newELFReader(data, false)
	if rLE.u16(0) != 0x0100 {
		t.Errorf("LE u16 wrong: got 0x%04x", rLE.u16(0))
	}
	rBE := newELFReader(data, true)
	if rBE.u16(0) != 0x0001 {
		t.Errorf("BE u16 wrong: got 0x%04x", rBE.u16(0))
	}
}

func TestELFReader_U64_LittleEndian(t *testing.T) {
	data := []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	r := newELFReader(data, false)
	if r.u64(0) != 2 {
		t.Errorf("expected 2, got %d", r.u64(0))
	}
}

func TestELFReader_U64At_OutOfBounds(t *testing.T) {
	data := []byte{0x01, 0x02}
	r := newELFReader(data, false)
	if r.u64At(data, 0) != 0 {
		t.Errorf("expected 0 on out-of-bounds u64At, got %d", r.u64At(data, 0))
	}
}

// ─── experimental.go ──────────────────────────────────────────────────────

func TestTotalFindings_Nil(t *testing.T) {
	var r *Result
	if r.TotalFindings() != 0 {
		t.Error("expected 0 for nil Result")
	}
}

func TestTotalFindings_Empty(t *testing.T) {
	r := &Result{}
	if r.TotalFindings() != 0 {
		t.Error("expected 0 for empty Result")
	}
}

func TestTotalFindings_WithFindings(t *testing.T) {
	r := &Result{
		Modules: []*ModuleResult{
			{Findings: []Finding{{}, {}}},
			{Findings: []Finding{{}}},
		},
	}
	if r.TotalFindings() != 3 {
		t.Errorf("expected 3, got %d", r.TotalFindings())
	}
}

func TestHighestSeverity_Nil(t *testing.T) {
	var r *Result
	if r.HighestSeverity() != SevInfo {
		t.Error("expected SevInfo for nil Result")
	}
}

func TestHighestSeverity_Empty(t *testing.T) {
	r := &Result{}
	if r.HighestSeverity() != SevInfo {
		t.Error("expected SevInfo for empty Result")
	}
}

func TestHighestSeverity_Critical(t *testing.T) {
	r := &Result{
		Modules: []*ModuleResult{
			{Findings: []Finding{
				{Severity: SevLow},
				{Severity: SevCritical},
				{Severity: SevHigh},
			}},
		},
	}
	if r.HighestSeverity() != SevCritical {
		t.Errorf("expected SevCritical, got %v", r.HighestSeverity())
	}
}
