package cfg

import (
	"reflect"
	"testing"

	"mega-analyzer/pkg/internal/dexir"
)

func TestSmaliInputWhitespaceCommentsAndAliases(t *testing.T) {
	input := BuildInputFromLines("LTest;", "f", "()I", []string{
		".locals 1", "# comment", ":first", ":alias # same position", "", ".line 7",
		"const-string\tv0, \"a,#b\\\"c\" # ignored, comma", "goto\t:first # branch",
	})
	if len(input.Instructions) != 2 {
		t.Fatalf("instructions = %+v", input.Instructions)
	}
	ins := input.Instructions[0]
	if ins.Opcode != "const-string" || !reflect.DeepEqual(ins.Operands, []string{"v0", `"a,#b\"c"`}) {
		t.Fatalf("literal or whitespace corrupted: %+v", ins)
	}
	if ins.Line != 7 {
		t.Fatalf("source line = %d, want 7", ins.Line)
	}
	graph := NewCFGBuilder().Build(input)
	for _, name := range []string{":first", ":alias"} {
		if idx, ok := graph.LabelIndex.GetInstructionIndex(name); !ok || idx != 0 {
			t.Fatalf("label %s = %d, %v", name, idx, ok)
		}
	}
	if graph.Method.Instructions[1].IR.BranchLabel != "first" {
		t.Fatal("inline comment leaked into branch target")
	}
}

func TestSmaliInputSwitchPayloadsAreDataAndResolveByLabel(t *testing.T) {
	input := BuildInputFromLines("LTest;", "f", "(I)I", []string{
		"packed-switch p0, :packed", "sparse-switch p0, :sparse", "const/4 v0, 0x0", "return v0",
		":one", "const/4 v0, 0x1", "return v0", ":two", "const/4 v0, 0x2", "return v0",
		// Reverse order must not exchange payloads.
		":sparse", ".sparse-switch", "0x20 -> :two", ".end sparse-switch",
		":packed", ".packed-switch 0x5", ":one", ":two", ".end packed-switch",
	})
	if len(input.Instructions) != 8 {
		t.Fatalf("payload leaked into instructions: %d", len(input.Instructions))
	}
	g := NewCFGBuilder().Build(input)
	if input.Instructions[0].IR.Payload == nil || input.Instructions[1].IR.Payload == nil {
		t.Fatal("missing attached payloads")
	}
	if _, ok := g.LabelIndex.GetInstructionIndex(":packed"); ok {
		t.Fatal("data label resolved as executable code")
	}
	for index, keys := range map[int][]int{0: {5, 6}, 1: {0x20}} {
		n := g.NodeByIdx[index]
		if n.SwitchInfo == nil {
			t.Fatalf("no switch info at %d", index)
		}
		var got []int
		for _, target := range n.SwitchInfo.Targets {
			got = append(got, target.Key)
		}
		if !reflect.DeepEqual(got, keys) {
			t.Fatalf("switch %d keys=%v, want %v", index, got, keys)
		}
		if len(n.Successors) < 2 {
			t.Fatalf("switch %d missing cases or default", index)
		}
	}
	if i, ok := g.LabelIndex.GetInstructionIndex(":one"); !ok || i != 4 {
		t.Fatalf("payload case label replaced code label: %d, %v", i, ok)
	}
}

func TestSmaliInputSharedSwitchPayload(t *testing.T) {
	input := BuildInputFromLines("LTest;", "f", "(I)V", []string{
		"packed-switch p0, :data", "packed-switch p0, :data", "return-void", ":case", "return-void",
		":data", ".packed-switch -0x2", ":case", ".end packed-switch",
	})
	g := NewCFGBuilder().Build(input)
	for _, index := range []int{0, 1} {
		info := g.NodeByIdx[index].SwitchInfo
		if info == nil || len(info.Targets) != 1 || info.Targets[0].Key != -2 {
			t.Fatalf("switch %d: %+v", index, info)
		}
	}
}

func TestSmaliInputTryCatchRangesAndArrayData(t *testing.T) {
	input := BuildInputFromLines("LTest;", "f", "()V", []string{
		".locals 2", ":start", "invoke-static {}, LTest;->call()V", ":end", "return-void",
		":handler", "move-exception v0", "return-void", ":all", "move-exception v1", "return-void",
		".catch Ljava/lang/Exception; {:start .. :end} :handler", ".catchall {:start .. :end} :all",
	})
	if len(input.TryBlocks) != 2 {
		t.Fatalf("try blocks = %+v", input.TryBlocks)
	}
	for _, tr := range input.TryBlocks {
		if tr.StartIdx != 0 || tr.EndIdx != 0 {
			t.Fatalf("exclusive try end lost: %+v", tr)
		}
	}
	result := NewCFGBuilder().BuildEx(input)
	if result.Stats.ExceptionEdges != 2 {
		t.Fatalf("exception edges=%d", result.Stats.ExceptionEdges)
	}
	for _, n := range result.CFG.Handlers {
		if n.Type != NodeTypeCatch {
			t.Fatalf("handler type=%v", n.Type)
		}
	}
	array := BuildInputFromLines("LTest;", "f", "()V", []string{
		"fill-array-data v0, :data", "return-void", ":data", ".array-data 1", "0x7ft", "-0x1t", ".end array-data",
	})
	NewCFGBuilder().Build(array)
	if len(array.Instructions) != 2 {
		t.Fatalf("array bytes treated as instructions: %+v", array.Instructions)
	}
	p := array.Instructions[0].IR.Payload
	if p == nil || p.Kind != dexir.PayloadArrayData || !reflect.DeepEqual(p.Values, []byte{127, 255}) {
		t.Fatalf("array payload = %+v", p)
	}
}

func TestSmaliInputMalformedPayloadAndHandlerDoNotInventEdges(t *testing.T) {
	input := BuildInputFromLines("LTest;", "f", "()V", []string{
		"packed-switch v0, :data", "return-void", ":case", "return-void",
		".catchall {:missing .. :case} :case", ":data", ".packed-switch 0x0", ":case", // unterminated
	})
	g := NewCFGBuilder().Build(input)
	if len(input.TryBlocks) != 0 {
		t.Fatal("unresolved handler range accepted")
	}
	if p := input.Instructions[0].IR.Payload; p != nil {
		t.Fatalf("unterminated payload accepted: %+v", p)
	}
	if len(g.NodeByIdx[0].SwitchInfo.Targets) != 0 {
		t.Fatal("invented switch edge")
	}
}

func TestSmaliInputInvokeRangesAndAnnotationData(t *testing.T) {
	input := BuildInputFromLines("LTest;", "f", "()V", []string{
		".annotation runtime LTest;", "value = {", "\"not executable\"", "}", ".end annotation",
		"invoke-static/range\t{v1 .. v3} , LTest;->call(III)V # comment",
		"return-void",
	})
	g := NewCFGBuilder().Build(input)
	if len(input.Instructions) != 2 {
		t.Fatalf("annotation contents leaked: %+v", input.Instructions)
	}
	ir := g.Method.Instructions[0].IR
	if !reflect.DeepEqual(ir.Srcs, []int32{1, 2, 3}) || ir.Method == nil {
		t.Fatalf("range invoke lost operands: %+v", ir)
	}
}
