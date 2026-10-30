package cfg

import (
	"fmt"
	"testing"
)

// Regression for irbuild.go:323 and irbuild.go:406.
//
// Both sites sliced operands[1:] unconditionally, so any opcode reaching those
// branches with an empty operand list panicked with
// "slice bounds out of range [1:0]". In the pipeline the panic was swallowed by
// the worker recover() (workers.go:111), so the file was silently dropped from
// analysis: no error, no non-zero exit code, just a missing finding.
// Real trigger from testdata/eval: "fill-array-data v1, :array_iv" in
// smali/eval/app/ZeroIv.smali.
func TestIRFromLegacyEmptyOperandsNoPanic(t *testing.T) {
	opcodes := []string{
		"goto", "goto/16", "goto/32",
		"packed-switch", "sparse-switch", "fill-array-data",
		"invoke-virtual", "invoke-static", "invoke-direct", "invoke-super",
		"invoke-interface", "invoke-virtual/range", "filled-new-array",
		"move", "move-object", "move-result", "move-result-object",
		"const/4", "const/16", "const-string", "new-instance", "new-array",
		"aget", "aget-object", "aput", "iget", "iget-object", "iput",
		"sget", "sget-object", "sput", "array-length", "check-cast",
		"instance-of", "if-eqz", "if-eq", "add-int", "add-int/2addr",
		"return", "return-void", "return-object", "throw", "nop",
	}

	var panics []string
	for _, opcode := range opcodes {
		for _, operands := range [][]string{nil, {}} {
			func() {
				defer func() {
					if r := recover(); r != nil {
						panics = append(panics, fmt.Sprintf("%s(len=%d): %v", opcode, len(operands), r))
					}
				}()
				_ = irFromLegacy(opcode, operands)
			}()
		}
	}

	if len(panics) > 0 {
		t.Fatalf("irFromLegacy panicked on empty operand lists (%d cases): %v", len(panics), panics)
	}
}

// A label-only or register-only operand list is the shape produced by malformed
// or truncated smali; the tail scan must still run without indexing past the slice.
func TestIRFromLegacySingleOperandBranches(t *testing.T) {
	for _, opcode := range []string{"packed-switch", "sparse-switch", "fill-array-data", "aget", "aget-object"} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("irFromLegacy(%q, 1 operand) panicked: %v", opcode, r)
				}
			}()
			_ = irFromLegacy(opcode, []string{"v1"})
			_ = irFromLegacy(opcode, []string{":array_iv"})
		}()
	}
}
