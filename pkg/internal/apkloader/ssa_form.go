package apkloader

type SSAVariable struct {
	ID           int16
	OrigRegister int16
	Definitions  []SSADef
	Uses         []SSAUse
	IsPhiResult  bool
	PhiBlock     *BasicBlock
}

type SSADef struct {
	Block *BasicBlock
	Insn  int
	Value interface{}
}

type SSAUse struct {
	Block *BasicBlock
	Insn  int
}

type SSAForm struct {
	CFG              *CFG
	Variables        []*SSAVariable
	VarByID          map[int16]*SSAVariable
	RegisterToVar    map[int16]*SSAVariable
	PhiFunctions     map[*BasicBlock][]*SSAVariable
	NextVarID        int16
	OriginalRegCount int
}

func ConvertToSSA(cfg *CFG) *SSAForm {
	ssa := &SSAForm{
		CFG:           cfg,
		Variables:     make([]*SSAVariable, 0),
		VarByID:       make(map[int16]*SSAVariable),
		RegisterToVar: make(map[int16]*SSAVariable),
		PhiFunctions:  make(map[*BasicBlock][]*SSAVariable),
		NextVarID:     0,
	}

	registers := ssa.collectRegisters()
	ssa.OriginalRegCount = len(registers)

	ssa.insertPhiFunctions(registers)
	ssa.renameVariables()
	ssa.buildUseDefChains()

	return ssa
}

func (ssa *SSAForm) collectRegisters() map[int16]bool {
	registers := make(map[int16]bool)

	for _, block := range ssa.CFG.Blocks {
		for _, insn := range block.Insns {
			if insn.Dst >= 0 {
				registers[insn.Dst] = true
			}
			if insn.Src1 >= 0 {
				registers[insn.Src1] = true
			}
			if insn.Src2 >= 0 {
				registers[insn.Src2] = true
			}
		}
	}

	return registers
}

func (ssa *SSAForm) insertPhiFunctions(registers map[int16]bool) {
	for reg := range registers {
		defBlocks := make(map[*BasicBlock]bool)
		for _, block := range ssa.CFG.Blocks {
			for _, insn := range block.Insns {
				if insn.Dst == reg {
					defBlocks[block] = true
					break
				}
			}
		}

		worklist := make([]*BasicBlock, 0)
		for block := range defBlocks {
			worklist = append(worklist, block)
		}

		phiInserted := make(map[*BasicBlock]bool)

		for len(worklist) > 0 {
			block := worklist[0]
			worklist = worklist[1:]

			for _, dfBlock := range block.DomFrontier {
				if !phiInserted[dfBlock] {
					phiInserted[dfBlock] = true

					phiVar := ssa.createPhiVariable(reg, dfBlock)
					ssa.PhiFunctions[dfBlock] = append(ssa.PhiFunctions[dfBlock], phiVar)

					if !defBlocks[dfBlock] {
						defBlocks[dfBlock] = true
						worklist = append(worklist, dfBlock)
					}
				}
			}
		}
	}
}

func (ssa *SSAForm) createPhiVariable(origReg int16, block *BasicBlock) *SSAVariable {
	varID := ssa.NextVarID
	ssa.NextVarID++

	phiVar := &SSAVariable{
		ID:           varID,
		OrigRegister: origReg,
		Definitions:  make([]SSADef, 0),
		Uses:         make([]SSAUse, 0),
		IsPhiResult:  true,
		PhiBlock:     block,
	}

	ssa.Variables = append(ssa.Variables, phiVar)
	ssa.VarByID[varID] = phiVar

	phiVar.Definitions = append(phiVar.Definitions, SSADef{
		Block: block,
		Insn:  -1,
	})

	return phiVar
}

func (ssa *SSAForm) renameVariables() {
	varStack := make(map[int16][]*SSAVariable)

	for reg := int16(0); reg < int16(ssa.OriginalRegCount); reg++ {
		varStack[reg] = make([]*SSAVariable, 0)
	}

	var rename func(block *BasicBlock)
	rename = func(block *BasicBlock) {
		if block == nil {
			return
		}

		for _, phiVar := range ssa.PhiFunctions[block] {
			varStack[phiVar.OrigRegister] = append(varStack[phiVar.OrigRegister], phiVar)
		}

		if block.Insns != nil {
			for i, insn := range block.Insns {
				if insn.Src1 >= 0 && insn.Src1 < int16(ssa.OriginalRegCount) && len(varStack[insn.Src1]) > 0 {
					useVar := varStack[insn.Src1][len(varStack[insn.Src1])-1]
					useVar.Uses = append(useVar.Uses, SSAUse{
						Block: block,
						Insn:  i,
					})
				}
				if insn.Src2 >= 0 && insn.Src2 < int16(ssa.OriginalRegCount) && len(varStack[insn.Src2]) > 0 {
					useVar := varStack[insn.Src2][len(varStack[insn.Src2])-1]
					useVar.Uses = append(useVar.Uses, SSAUse{
						Block: block,
						Insn:  i,
					})
				}

				if insn.Dst >= 0 {
					varID := ssa.NextVarID
					ssa.NextVarID++

					defVar := &SSAVariable{
						ID:           varID,
						OrigRegister: insn.Dst,
						Definitions: []SSADef{
							{
								Block: block,
								Insn:  i,
							},
						},
						Uses: make([]SSAUse, 0),
					}

					ssa.Variables = append(ssa.Variables, defVar)
					ssa.VarByID[varID] = defVar
					varStack[insn.Dst] = append(varStack[insn.Dst], defVar)

					ssa.RegisterToVar[insn.Dst] = defVar
				}
			}
		}

		for _, child := range block.Children {
			rename(child)
		}

		for reg := int16(0); reg < int16(ssa.OriginalRegCount); reg++ {
			if len(varStack[reg]) > 0 {
				varStack[reg] = varStack[reg][:len(varStack[reg])-1]
			}
		}
	}

	if ssa.CFG.Entry != nil {
		rename(ssa.CFG.Entry)
	}
}

func (ssa *SSAForm) buildUseDefChains() {
	for _, variable := range ssa.Variables {
		if len(variable.Definitions) == 0 && !variable.IsPhiResult {
		}
	}
}

func (ssa *SSAForm) GetSSAVariable(reg int16, block *BasicBlock) *SSAVariable {
	if v, ok := ssa.RegisterToVar[reg]; ok {
		return v
	}
	return nil
}

func (ssa *SSAForm) GetVariableDefinitions(varID int16) []SSADef {
	if v, ok := ssa.VarByID[varID]; ok {
		return v.Definitions
	}
	return nil
}

func (ssa *SSAForm) GetVariableUses(varID int16) []SSAUse {
	if v, ok := ssa.VarByID[varID]; ok {
		return v.Uses
	}
	return nil
}

func (ssa *SSAForm) VariableCount() int {
	return len(ssa.Variables)
}

func (ssa *SSAForm) PhiFunctionCount() int {
	count := 0
	for _, phiFuncs := range ssa.PhiFunctions {
		count += len(phiFuncs)
	}
	return count
}
