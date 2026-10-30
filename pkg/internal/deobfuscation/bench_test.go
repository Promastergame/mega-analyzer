package deobfuscation

import (
	"context"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/cfg"
)

func benchXORData() []byte {
	plain := "the quick brown fox jumps over the lazy dog many many times over again"
	out := make([]byte, len(plain))
	for i := range plain {
		out[i] = plain[i] ^ 0x5A
	}
	return out
}

func BenchmarkCrackXOR(b *testing.B) {
	data := benchXORData()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		crackXOR(data)
	}
}

func BenchmarkTryDecryptString(b *testing.B) {
	in := "SGVsbG8gV29ybGQgdGhpcyBpcyBhIHRlc3Q="
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = tryDecryptString(in)
	}
}

func BenchmarkShannonEntropy(b *testing.B) {
	data := []byte(strings.Repeat("A1b2C3d4", 32))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		shannonEntropy(data)
	}
}

func BenchmarkResolveStringTables(b *testing.B) {
	d := NewJSDeobfuscator(DefaultJSOptions())
	in := `var _0x1=['log','warn','error','hello','world'];` +
		strings.Repeat(`console[_0x1[0]](_0x1[3]);`, 50)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		d.ResolveStringTables(in)
	}
}

func BenchmarkInlineProxyFunctions(b *testing.B) {
	d := NewJSDeobfuscator(DefaultJSOptions())
	in := `function _0xb(a,b){return a + b;}` +
		strings.Repeat(`var x=_0xb("a","b");`, 50)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		d.InlineProxyFunctions(in)
	}
}

func benchCFFGraph() *cfg.ControlFlowGraph {
	const stateReg = "v0"
	cases := make([]*cfg.CFGNode, 12)
	for i := range cases {
		cases[i] = &cfg.CFGNode{
			ID: 2 + i, Type: cfg.NodeTypeBasic, RPONumber: 10 + i,
			Instructions: []cfg.InstructionRef{
				{Index: 0, Opcode: "const/4", Raw: "const/4 v0, 0x1"},
			},
		}
	}
	dispatcher := &cfg.CFGNode{
		ID: 1, Type: cfg.NodeTypeSwitch, LoopDepth: 1, RPONumber: 5,
		SwitchInfo: &cfg.SwitchInfo{Type: cfg.SwitchPacked, Register: stateReg},
	}
	for i, c := range cases {
		dispatcher.SwitchInfo.Targets = append(dispatcher.SwitchInfo.Targets, cfg.SwitchTarget{Key: i, TargetID: c.ID})
		c.Predecessors = append(c.Predecessors, dispatcher)
	}
	dispatcher.Predecessors = append(dispatcher.Predecessors, cases...)
	entry := &cfg.CFGNode{ID: 0, Type: cfg.NodeTypeEntry, Successors: []*cfg.CFGNode{dispatcher}}
	nodes := append([]*cfg.CFGNode{entry, dispatcher}, cases...)
	return &cfg.ControlFlowGraph{MethodName: "bench", Entry: entry, Nodes: nodes}
}

func BenchmarkAnalyze(b *testing.B) {
	e := NewDefaultEngine()
	g := benchCFFGraph()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		e.Analyze(g)
	}
}

func BenchmarkAnalyzeAll(b *testing.B) {
	e := NewDefaultEngine()
	graphs := make([]*cfg.ControlFlowGraph, 256)
	for i := range graphs {
		graphs[i] = benchCFFGraph()
	}
	ctx := context.Background()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		e.AnalyzeAll(ctx, graphs)
	}
}
