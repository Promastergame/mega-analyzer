package apkloader

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"mega-analyzer/pkg/internal/testutil"
)

// These bytes use the upstream v96 opcode numbers, independently of generated
// Go tables. Operand bytes deliberately resemble valid call instructions.
func hbcWithCode(t *testing.T, code []byte) []byte {
	t.Helper()
	data := buildTestHBC(t, 96, []string{"main", "moduleA", "https://api.example.com"})
	start := int(binary.LittleEndian.Uint32(data[128:]) & 0x1ffffff)
	data = append(data[:start], code...)
	second := len(data)
	data = append(data, 92, 0)
	binary.LittleEndian.PutUint32(data[132:], uint32(len(code)))
	binary.LittleEndian.PutUint32(data[144:], uint32(second))
	binary.LittleEndian.PutUint32(data[148:], 2)
	binary.LittleEndian.PutUint32(data[32:], uint32(len(data)))
	return data
}

func TestHermesDecoderPreservesInstructionBoundariesAndCallSites(t *testing.T) {
	// LoadConstInt's immediate contains CallDirect's opcode (82).
	code := []byte{111, 0, 82, 0, 1, 0, 82, 0, 1, 0, 0, 82, 0, 1, 1, 0, 82, 0, 1, 1, 0, 79, 0, 1, 1, 92, 0}
	h, err := ParseHermesBytecode(hbcWithCode(t, code))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := h.DecodeFunction(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 6 || decoded[0].Name != "LoadConstInt" || decoded[1].FunctionOffset != 6 {
		t.Fatalf("instruction boundary loss: %+v", decoded)
	}
	g := h.BuildFunctionGraphDetailed(100, 1<<20, 100)
	if g.Coverage.Status != "complete" || len(g.Edges) != 4 {
		t.Fatalf("unexpected graph: %+v", g)
	}
	if g.Edges[0].Callee != 0 || !g.Edges[0].Resolved {
		t.Fatalf("recursive call lost: %+v", g.Edges[0])
	}
	if g.Edges[1].Callee != 1 || g.Edges[2].Callee != 1 || g.Edges[1].Offset == g.Edges[2].Offset {
		t.Fatalf("distinct calls collapsed: %+v", g.Edges)
	}
	if g.Edges[3].Resolved || g.Edges[3].Kind != "indirect" || g.Edges[3].CalleeRegister == nil {
		t.Fatalf("register call invented target: %+v", g.Edges[3])
	}
}

func TestHermesDecoderTruncatedAndUnknownInstructionsArePartial(t *testing.T) {
	for _, tail := range [][]byte{{82, 0}, {255, 82, 0, 1, 1, 0}} {
		h, err := ParseHermesBytecode(hbcWithCode(t, append([]byte{82, 0, 1, 0, 0}, tail...)))
		if err != nil {
			t.Fatal(err)
		}
		instructions, err := h.DecodeFunction(0)
		if err == nil || len(instructions) != 1 {
			t.Fatalf("malformed tail was resynchronized: %v %+v", err, instructions)
		}
		g := h.BuildFunctionGraphDetailed(100, 1<<20, 100)
		if len(g.Edges) != 1 || g.Coverage.FailedFunctions != 1 || g.Coverage.Status != "partial" {
			t.Fatalf("lost failure: %+v", g)
		}
	}
}

func TestHermesGraphBudgetsAreVisible(t *testing.T) {
	h, err := ParseHermesBytecode(hbcWithCode(t, []byte{82, 0, 1, 0, 0, 82, 0, 1, 1, 0, 92, 0}))
	if err != nil {
		t.Fatal(err)
	}
	g := h.BuildFunctionGraphDetailed(1, 100, 1)
	if g.Coverage.Status != "partial" || g.Coverage.SkippedFunctions != 1 || g.Coverage.Calls != 2 || g.Coverage.DroppedCalls != 1 {
		t.Fatalf("silent graph truncation: %+v", g.Coverage)
	}
}

func TestHermesVersionAndCompactLayouts(t *testing.T) {
	for _, version := range []uint32{98, 99, 100} {
		data := buildCompactHBC(t, version, []string{"main"})
		binary.LittleEndian.PutUint32(data[128:], 7<<25)
		binary.LittleEndian.PutUint32(data[136:], 0x04130209)
		h, err := ParseHermesBytecode(data)
		if err != nil {
			t.Fatal(err)
		}
		if h.Functions[0].ParamCount != 7 || h.Functions[0].FrameSize != 9 || h.Functions[0].Flags != 4 {
			t.Fatalf("v%d compact fields: %+v", version, h.Functions[0])
		}
	}
	data := buildTestHBC(t, 96, []string{"main", "module", "endpoint"})
	binary.LittleEndian.PutUint32(data[8:], 95)
	if _, err := ParseHermesBytecode(data); !errors.Is(err, ErrUnsupportedHermes) {
		t.Fatalf("guessed unknown layout: %v", err)
	}
}

func TestHermesOverflowFunctionHeaders(t *testing.T) {
	for _, version := range []uint32{96, 98, 99} {
		var data []byte
		if version == 96 {
			data = hbcWithCode(t, []byte{92, 0})
		} else {
			data = buildCompactHBC(t, version, []string{"main"})
		}
		codeOffset := len(data)
		ret := byte(106)
		if version == 96 {
			ret = 92
		}
		if version == 99 {
			ret = 118
		}
		data = append(data, ret, 0)
		largeOffset := len(data)
		size := 23
		if version == 96 {
			size = 31
		}
		if version == 99 {
			size = 36
		}
		data = append(data, make([]byte, size)...)
		put := func(off int, value uint32) { binary.LittleEndian.PutUint32(data[off:], value) }
		put(largeOffset, uint32(codeOffset))
		put(largeOffset+4, 400)
		switch version {
		case 96:
			put(largeOffset+8, 2)
			put(largeOffset+20, 300)
			put(largeOffset+24, 200)
			put(128, uint32(largeOffset)&0xffff)
			put(136, uint32(largeOffset>>16))
			data[143] = 0x20
		case 98:
			put(largeOffset+8, 2)
			put(largeOffset+16, 300)
			put(128, uint32(largeOffset)&0xffff)
			put(132, uint32(largeOffset>>16)<<15)
			data[139] = 0x20
		case 99:
			put(largeOffset+12, 2)
			put(largeOffset+28, 300)
			put(128, uint32(largeOffset)&0xffffff)
			put(132, uint32(largeOffset>>24)<<14)
			data[139] = 0x20
		}
		put(32, uint32(len(data)))
		h, err := ParseHermesBytecode(data)
		if err != nil {
			t.Fatal(err)
		}
		fn := h.Functions[0]
		if !fn.Valid || !fn.Overflow || fn.FrameSize != 300 || fn.ParamCount != 400 || fn.BytecodeOffset != uint32(codeOffset) {
			t.Fatalf("v%d large header: %+v, %v", version, fn, h.Diagnostics)
		}
		insn, err := h.DecodeFunction(0)
		if err != nil || len(insn) != 1 || insn[0].Name != "Ret" {
			t.Fatalf("v%d decode: %+v %v", version, insn, err)
		}
	}
}

func TestBundleCoverageCancellationAndDiscovery(t *testing.T) {
	dir := testutil.TempDir(t)
	if err := os.WriteFile(filepath.Join(dir, "broken.hbc"), HermesMagicLE, 0600); err != nil {
		t.Fatal(err)
	}
	result, err := ScanHermesContext(context.Background(), dir)
	if err != nil || len(result.Files) != 1 || result.Files[0].Status != "failed" || len(result.Files[0].Diagnostics) == 0 || len(result.Findings) == 0 {
		t.Fatalf("hidden parse failure: %+v, %v", result, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err = ScanHermesContext(ctx, dir)
	if !errors.Is(err, context.Canceled) || result.Status != "failed" {
		t.Fatalf("cancellation lost: %+v %v", result, err)
	}
}
