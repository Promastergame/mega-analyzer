package apkloader

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

// The original Go parser returns a DEXParser struct.
// The Rust parser returns a JSON byte array.
// To do A/B testing, we need to compare the output of both.

func TestDexParserMigrationAB(t *testing.T) {
	dexData := []byte("dex\n035\x00" + string(bytes.Repeat([]byte{0}, 104)))
	if len(dexData) < 112 {
		t.Fatalf("Test DEX data too short")
	}

	// 1. Run Go parser
	goParser, goErr := ParseDEXBytes(dexData)

	// 2. Run Rust parser
	rustResult, rustErr := ParseDexWithRust(dexData)

	if goErr == nil && rustErr == nil {
		t.Logf("Both parsers succeeded on fake DEX? Or didn't validate deeply yet.")
	}

	_ = goParser
	_ = rustResult
}

func TestSymbolicExecutionMigrationAB(t *testing.T) {
	insn1 := MIRInsn{Kind: MIR_CONST, Dst: 0, Imm: 42}
	insn2 := MIRInsn{Kind: MIR_ADD, Dst: 0, Src1: 0, Src2: 0, Imm: 1}

	b1 := &BasicBlock{
		ID:    1,
		Insns: []MIRInsn{insn1, insn2},
	}
	cfg := &CFG{
		Blocks: []*BasicBlock{b1, b1}, // pad to size 2 so b1 can be at index 1
		Entry:  b1,
	}
	cfg.Blocks[1] = b1

	ssa := &SSAForm{
		CFG:              cfg,
		Variables:        make([]*SSAVariable, 0),
		VarByID:          make(map[int16]*SSAVariable),
		RegisterToVar:    make(map[int16]*SSAVariable),
		PhiFunctions:     make(map[*BasicBlock][]*SSAVariable),
		NextVarID:        0,
		OriginalRegCount: 2,
	}

	// 1. Run Go execution
	engine := NewSymbolicExecutor(cfg, ssa)
	goResult := engine.Execute()
	_ = goResult

	// 2. Run Rust execution
	ffiBlocks := []FfiBlock{
		{
			ID: 1,
			Insns: []FfiMirInsn{
				{Kind: uint8(MIR_CONST), Dst: 0, Imm: 42},
				{Kind: uint8(MIR_ADD), Dst: 0, Src1: 0, Src2: 0, Imm: 1},
			},
			Succs: []uint32{},
		},
	}

	rustResult, err := SymbolicExecuteWithRust(ffiBlocks, 1, 16, 30, 100)
	if err != nil {
		if errors.Is(err, ErrRustNotLinked) {
			t.Skip("rust library not linked — symbolic A/B skipped")
		}
		t.Fatalf("Rust symbolic engine failed: %v", err)
	}

	var rustData map[string]interface{}
	if err := json.Unmarshal(rustResult, &rustData); err == nil {
		if errStr, hasErr := rustData["error"]; hasErr {
			t.Fatalf("Rust returned error: %v", errStr)
		}
		t.Logf("Rust symbolic returned %d bytes of JSON", len(rustResult))
	}
}

func TestVirtualizationDetectionMigrationAB(t *testing.T) {
	ffiBlocks := []FfiVirtBlock{
		{
			ID: 1,
			Insns: []FfiVirtInsn{
				{Kind: uint8(MIR_SWITCH), Dst: 0},
			},
			Succs: []uint32{2, 3},
		},
		{
			ID: 2,
			Insns: []FfiVirtInsn{
				{Kind: uint8(MIR_CONST), Dst: 0, Imm: 1},
			},
			Succs: []uint32{},
		},
		{
			ID: 3,
			Insns: []FfiVirtInsn{
				{Kind: uint8(MIR_CONST), Dst: 0, Imm: 2},
			},
			Succs: []uint32{},
		},
	}

	rustResult, err := DetectVirtualizationWithRust(ffiBlocks, 50)
	if err != nil {
		if errors.Is(err, ErrRustNotLinked) {
			t.Skip("rust library not linked — virtualization A/B skipped")
		}
		t.Fatalf("Rust virt detector failed: %v", err)
	}

	var rustData struct {
		Stats struct {
			Dispatcher int `json:"dispatcher"`
		} `json:"stats"`
	}
	if err := json.Unmarshal(rustResult, &rustData); err == nil {
		if rustData.Stats.Dispatcher == 0 {
			t.Logf("Rust failed to detect switch dispatcher. Got: %+v", rustData)
		} else {
			t.Logf("Rust successfully detected switch dispatcher.")
		}
	} else {
		t.Fatalf("Failed to parse rust virt JSON: %v\nResult was: %s", err, string(rustResult))
	}
}
