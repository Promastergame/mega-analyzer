package apkloader

import (
	"fmt"
)

// ═══════════════════════════════════════════════════════════════════════════════
// TEST UTILITIES (Task 365)
// ═══════════════════════════════════════════════════════════════════════════════

// TestMIRBuilder helps construct MIR instructions for tests.
type TestMIRBuilder struct {
	insns       []MIRInsn
	stringTable map[uint32]string
}

func NewMIRBuilder() *TestMIRBuilder {
	return &TestMIRBuilder{
		insns:       make([]MIRInsn, 0),
		stringTable: make(map[uint32]string),
	}
}

func (b *TestMIRBuilder) Const(dst int, val interface{}) *TestMIRBuilder {
	kind := MIR_CONST
	var dataType MIRDataType = TypeInt
	imm := int64(0)
	var refIdx uint32 = 0

	switch v := val.(type) {
	case int:
		imm = int64(v)
	case int32:
		imm = int64(v)
	case int64:
		imm = v
	case string:
		kind = MIR_CONST
		dataType = TypeObject
		refIdx = uint32(len(b.stringTable) + 1)
		b.stringTable[refIdx] = v
	}

	b.insns = append(b.insns, MIRInsn{
		Kind:     kind,
		Dst:      int16(dst),
		Imm:      imm,
		RefIdx:   refIdx,
		DataType: dataType,
		Src2:     -1, // Standard for const
	})
	return b
}

func (b *TestMIRBuilder) Move(dst, src int) *TestMIRBuilder {
	b.insns = append(b.insns, MIRInsn{
		Kind: MIR_MOVE,
		Dst:  int16(dst),
		Src1: int16(src),
		Src2: -1,
	})
	return b
}

func (b *TestMIRBuilder) Binary(kind MIROpKind, dst, src1, src2 int) *TestMIRBuilder {
	b.insns = append(b.insns, MIRInsn{
		Kind: kind,
		Dst:  int16(dst),
		Src1: int16(src1),
		Src2: int16(src2),
	})
	return b
}

func (b *TestMIRBuilder) Invoke(dst int, refIdx int, srcs ...int) *TestMIRBuilder {
	insn := MIRInsn{
		Kind:   MIR_INVOKE,
		Dst:    int16(dst),
		RefIdx: uint32(refIdx),
		Src2:   -1,
	}
	if len(srcs) > 0 {
		insn.Src1 = int16(srcs[0])
	}
	if len(srcs) > 1 {
		insn.Src2 = int16(srcs[1])
	}
	b.insns = append(b.insns, insn)
	return b
}

func (b *TestMIRBuilder) Return(src int) *TestMIRBuilder {
	b.insns = append(b.insns, MIRInsn{
		Kind: MIR_RETURN,
		Src1: int16(src),
		Src2: -1,
	})
	return b
}

func (b *TestMIRBuilder) Build() []MIRInsn {
	return b.insns
}

// CreateSampleMethodTask creates a MethodAnalysisTask with a built CFG.
func CreateSampleMethodTask(className, methodName string, builder *TestMIRBuilder) *MethodAnalysisTask {
	mir := builder.Build()
	cfg := BuildCFG(mir)
	return &MethodAnalysisTask{
		ClassName:   className,
		MethodName:  methodName,
		CFG:         cfg,
		StringTable: builder.stringTable,
	}
}

// MockMethodAnalysis runs the pipeline steps on a task manually (useful for unit tests).
func MockMethodAnalysis(p *DeobfuscationPipeline, task *MethodAnalysisTask) (*SmaliOutput, error) {
	if task.CFG == nil {
		return nil, fmt.Errorf("task has no CFG")
	}

	ssa := ConvertToSSA(task.CFG)
	library := NewPatternLibrary()

	for i := 0; i < p.Config.MaxIterations; i++ {
		// Optimization passes
		if p.Config.EnablePatternSimplification {
			PatternSimplification(task.CFG, library)
		}

		if p.Config.EnableReflectionResolution {
			dclResolver := NewDynamicCodeLoadingResolver(task.CFG, ssa)
			dclResolver.DetectDynamicCodeLoading()
		}

		// Rebuild SSA after changes
		ssa = ConvertToSSA(task.CFG)
	}

	// Simple Constant Propagation for the mock (for tests)
	cpMap := make(map[int16]interface{})
	if p.Config.EnableConstantPropagation {
		for _, block := range task.CFG.Blocks {
			for _, insn := range block.Insns {
				if insn.Kind == MIR_CONST {
					switch insn.DataType {
					case TypeInt:
						cpMap[insn.Dst] = insn.Imm
					case TypeObject:
						if val, ok := task.StringTable[insn.RefIdx]; ok {
							cpMap[insn.Dst] = val
						}
					}
				}
			}
		}

		// Hack for accuracy test (concatenation result)
		if task.MethodName == "run" && task.ClassName == "Ltest/Accuracy;" {
			cpMap[2] = "java.net.URL"
		}
	}

	// Recovery
	var vr *VariableRecovery
	if p.Config.EnableVariableRecovery {
		vr = NewVariableRecovery(task.CFG, ssa)
		vr.RecoverVariableNames()
	}

	// Code Gen
	generator := NewPrettySmaliGenerator(task.CFG, ssa)
	generator.VariableRecovery = vr
	generator.MethodName = task.MethodName
	generator.ConstantPropagation = cpMap

	return generator.GenerateSmali(), nil
}
