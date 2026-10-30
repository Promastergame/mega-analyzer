package apkloader

import (
	"errors"
	"testing"
	"unsafe"
)

func TestDeobfuscateWithRust(t *testing.T) {
	// 0. Verify size
	if unsafe.Sizeof(rustMIRInsn{}) != 40 {
		t.Fatalf("rustMIRInsn size mismatch: expected 40, got %d", unsafe.Sizeof(rustMIRInsn{}))
	}

	// 1. Create a simple obfuscated MIR stream:
	//   const v0, 10
	//   add v0, v0, 0  <-- Dead arithmetic (x + 0 = x)
	//   xor v1, v1, v1 <-- Arithmetic identity (x ^ x = 0)
	//   return v0
	mir := []MIRInsn{
		{
			Kind:     MIR_CONST,
			Dst:      0,
			Imm:      10,
			DataType: TypeInt,
		},
		{
			Kind:     MIR_ADD,
			Dst:      0,
			Src1:     0,
			Imm:      0, // literal 0
			DataType: TypeInt,
		},
		{
			Kind:     MIR_XOR,
			Dst:      1,
			Src1:     1,
			Src2:     1,
			DataType: TypeInt,
		},
		{
			Kind:     MIR_RETURN,
			Src1:     0,
			DataType: TypeInt,
		},
	}

	// 2. Call Rust deobfuscator (mode 1 = default)
	res, err := DeobfuscateWithRust(mir, 1)
	if err != nil {
		if errors.Is(err, ErrRustNotLinked) {
			t.Skip("Skipping Rust-dependent test: Rust library not linked")
		}
		t.Fatalf("Rust deobfuscation failed: %v", err)
	}

	// 3. Verify results
	t.Logf("Rust deobfuscation results: %+v", res)

	if res.InstructionsBefore != 4 {
		t.Errorf("Expected 4 instructions before, got %d", res.InstructionsBefore)
	}

	// add v0, v0, 0 and xor v1, v1, v1 should be simplified/removed
	// Expected: const v0, 10; mov v1, 0; return v0
	// (Note: DCE might remove mov v1, 0 if v1 is never used, but here it might stay as a simplified op)

	if res.PatternsApplied == 0 && res.ConstantsResolved == 0 {
		t.Errorf("Expected some patterns or constants to be resolved/applied, got 0")
	}

	if res.ReductionPercent <= 0 {
		t.Logf("Warning: Reduction percent is 0, but patterns might have simplified instructions without removing them")
	}

	t.Logf("Deobfuscation took %d ms", res.DurationMs)
}
