package apkloader

import "fmt"

// ValidationError describes a single consistency issue found after patching.
type ValidationError struct {
	PC      uint32
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("pc=0x%x: %s", e.PC, e.Message)
}

// ValidationResult holds all issues found by Validate.
type ValidationResult struct {
	Errors   []ValidationError
	Warnings []ValidationError
}

func (r *ValidationResult) OK() bool { return len(r.Errors) == 0 }

func (r *ValidationResult) add(pc uint32, msg string) {
	r.Errors = append(r.Errors, ValidationError{pc, msg})
}

func (r *ValidationResult) warn(pc uint32, msg string) {
	r.Warnings = append(r.Warnings, ValidationError{pc, msg})
}

// Validate checks the patched instruction stream for consistency.
// Checks:
//  1. Offsets are monotonically increasing
//  2. All branch targets land on a valid instruction offset
//  3. At least one return instruction exists
//  4. No instruction extends past the stream
func Validate(insns []RawInsn) ValidationResult {
	res := ValidationResult{}
	if len(insns) == 0 {
		res.add(0, "empty instruction stream")
		return res
	}

	// Build offset set for branch target validation
	offsets := make(map[uint32]bool, len(insns))
	for _, insn := range insns {
		offsets[insn.Offset] = true
	}

	hasReturn := false
	prevOffset := uint32(0)

	for i, insn := range insns {
		// 1. Monotonic offsets
		if i > 0 && insn.Offset <= prevOffset {
			res.add(insn.Offset, fmt.Sprintf("non-monotonic offset (prev=0x%x)", prevOffset))
		}
		prevOffset = insn.Offset

		// 2. Branch targets must land on known offsets
		if insn.IsBranch() {
			target := insn.BranchTarget()
			if !offsets[target] {
				res.add(insn.Offset, fmt.Sprintf("branch target 0x%x not found in stream", target))
			}
		}

		// 3. Track returns
		if insn.IsReturn() {
			hasReturn = true
		}

		// 4. Size sanity
		if insn.Size == 0 {
			res.add(insn.Offset, "instruction has size=0")
		}
	}

	if !hasReturn {
		res.add(0, "no return instruction in patched method")
	}

	return res
}

// ValidatePatch runs Validate on p.Modified and returns the result.
func (p *Patcher) ValidatePatch() ValidationResult {
	return Validate(p.Modified)
}

// BuildValidated builds bytecode and validates before returning.
// Returns an error if validation finds any errors.
func (p *Patcher) BuildValidated() ([]byte, ValidationResult, error) {
	res := p.ValidatePatch()
	if !res.OK() {
		return nil, res, fmt.Errorf("patch validation failed: %d error(s)", len(res.Errors))
	}
	code, err := p.Build()
	return code, res, err
}
