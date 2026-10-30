package apkloader

import (
	"testing"
)

// ─── DeadCodeAnalysis getters ─────────────────────────────────────────────────

func TestGetUnreachableBlocks_Empty(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_RETURN, Offset: 1, Src1: 0},
	}
	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)
	a := AnalyzeDeadCode(cfg, ssa)
	blocks := a.GetUnreachableBlocks()
	if blocks == nil {
		t.Error("GetUnreachableBlocks should return non-nil slice")
	}
}

func TestGetDeadAssignments_NonNil(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_CONST, Offset: 1, Dst: 1, Imm: 2},
		{Kind: MIR_RETURN, Offset: 2, Src1: 0},
	}
	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)
	a := AnalyzeDeadCode(cfg, ssa)
	da := a.GetDeadAssignments()
	if da == nil {
		t.Error("GetDeadAssignments should return non-nil slice")
	}
}

// ─── ParseDEXBytes with invalid data ─────────────────────────────────────────

func TestParseDEXBytes_TooSmall(t *testing.T) {
	_, err := ParseDEXBytes([]byte{0x64, 0x65, 0x78})
	if err == nil {
		t.Error("expected error for too-small input")
	}
}

func TestParseDEXBytes_BadMagic(t *testing.T) {
	data := make([]byte, 112)
	data[0] = 0xFF // bad magic
	_, err := ParseDEXBytes(data)
	if err == nil {
		t.Error("expected error for bad magic")
	}
}

func TestParseDEXBytes_Empty(t *testing.T) {
	_, err := ParseDEXBytes(nil)
	if err == nil {
		t.Error("expected error for nil input")
	}
}

// ─── NativeScanReport helpers ─────────────────────────────────────────────────

func TestAnalyzeNativeGo_EmptyBytes(t *testing.T) {
	_, ok := AnalyzeNativeGo(nil)
	if ok {
		t.Error("nil data should not be recognized")
	}
}

func TestAnalyzeNativeGo_TinyBuffer(t *testing.T) {
	_, ok := AnalyzeNativeGo([]byte{0x01, 0x02})
	if ok {
		t.Error("tiny buffer should not be recognized")
	}
}

func TestAnalyzeNativeGo_ELFMagic(t *testing.T) {
	// Minimal ELF header: magic + class byte
	elf := make([]byte, 64)
	elf[0] = 0x7f
	elf[1] = 'E'
	elf[2] = 'L'
	elf[3] = 'F'
	elf[4] = 2 // 64-bit
	elf[5] = 1 // little-endian
	elf[6] = 1 // version
	// The parser may fail on incomplete header but should not panic
	_, _ = AnalyzeNativeGo(elf)
}

func TestAnalyzeNativeGo_PEMagic(t *testing.T) {
	// Minimal PE header: MZ magic
	pe := make([]byte, 64)
	pe[0] = 'M'
	pe[1] = 'Z'
	_, _ = AnalyzeNativeGo(pe)
}
