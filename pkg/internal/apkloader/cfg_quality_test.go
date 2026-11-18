package apkloader

import "testing"

func TestCFGRebuildCompactsIDsAndRemovesDeletedExceptionTargets(t *testing.T) {
	entry := &BasicBlock{ID: 0, Insns: []MIRInsn{{Kind: MIR_CONST, Dst: 0, Imm: 1}}}
	handler := &BasicBlock{ID: 9, IsExceptionHandler: true, Insns: []MIRInsn{{Kind: MIR_RETURN, Src1: 0}}}
	unreachable := &BasicBlock{ID: 12, Insns: []MIRInsn{{Kind: MIR_RETURN, Src1: 0}}}
	deleted := &BasicBlock{ID: 15}
	graph := &CFG{
		Entry: entry, Blocks: []*BasicBlock{entry, handler, unreachable},
		HandlerBlocks:  []*BasicBlock{handler, deleted},
		ExceptionEdges: []*ExceptionEdge{{From: entry, To: handler}, {From: entry, To: deleted}, {From: deleted, To: handler}},
	}
	normalizeCFG(graph)
	for id, block := range graph.Blocks {
		if block.ID != id {
			t.Fatalf("block %d still has a sparse ID: %d", id, block.ID)
		}
	}
	if !entry.IsReachable || !handler.IsReachable || unreachable.IsReachable || deleted.IsReachable {
		t.Fatal("normal and exception reachability changed after compaction")
	}
	if len(graph.ExceptionEdges) != 1 || len(graph.HandlerBlocks) != 1 {
		t.Fatal("deleted exception targets survived graph rebuild")
	}
	graph.ComputeDominance()
	if ConvertToSSA(graph) == nil {
		t.Fatal("compacted CFG could not enter SSA analysis")
	}
}
