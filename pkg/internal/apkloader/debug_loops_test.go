package apkloader

import (
	"fmt"
	"testing"
)

func TestDebugLoops(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 0},
		{Kind: MIR_IF, Offset: 1, Imm: 11, RawFlags: FlagBranch},
		{Kind: MIR_CONST, Offset: 3, Dst: 1, Imm: 0},
		{Kind: MIR_IF, Offset: 4, Imm: 8, RawFlags: FlagBranch},
		{Kind: MIR_ADD, Offset: 6, Dst: 1, Src1: 1, Src2: 1},
		{Kind: MIR_GOTO, Offset: 7, Imm: -3, RawFlags: FlagBranch},
		{Kind: MIR_ADD, Offset: 9, Dst: 0, Src1: 0, Src2: 0},
		{Kind: MIR_GOTO, Offset: 10, Imm: -9, RawFlags: FlagBranch},
		{Kind: MIR_RETURN, Offset: 12},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	fmt.Printf("Blocks: %d\n", len(cfg.Blocks))
	for _, b := range cfg.Blocks {
		fmt.Printf("Block %d: [%d-%d] Succs: ", b.ID, b.Start, b.End)
		for _, s := range b.Succs {
			fmt.Printf("%d ", s.ID)
		}
		fmt.Printf("Preds: ")
		for _, p := range b.Preds {
			fmt.Printf("%d ", p.ID)
		}
		if b.IDom != nil {
			fmt.Printf(" IDom: %d", b.IDom.ID)
		}
		fmt.Println()
	}

	analysis := AnalyzeLoops(cfg)
	fmt.Printf("Loops: %d\n", analysis.LoopCount())
	for i, l := range analysis.AllLoops {
		fmt.Printf("Loop %d: Header %d, Blocks: ", i, l.Header.ID)
		for _, b := range l.Blocks {
			fmt.Printf("%d ", b.ID)
		}
		fmt.Println()
	}
}
