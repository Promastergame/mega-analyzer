package adapters

import (
	"reflect"
	"testing"

	"mega-analyzer/pkg/internal/parser"
	"mega-analyzer/pkg/internal/types"
)

func TestSharedSmaliSourceLinesPreserveIR(t *testing.T) {
	p := parser.NewSmaliParser(smaliTestSource)
	sc, err := p.Parse()
	if err != nil {
		t.Fatal(err)
	}
	before := append([]string(nil), p.Lines()...)
	got := FromSmaliClassLines(sc, p.Lines())
	want := FromSmaliClass(sc, smaliTestSource)
	if !reflect.DeepEqual(got, want) {
		t.Fatal("shared source index changed typed IR, payloads or source locations")
	}
	if !reflect.DeepEqual(before, p.Lines()) {
		t.Fatal("IR conversion mutated the parser's source lines")
	}
}

func TestSmaliIRInvalidSourceRange(t *testing.T) {
	sc := &types.SmaliClass{Methods: []types.SmaliMethod{{
		Name: "invalid", SourceRange: types.SourceRange{LineStart: 3, LineEnd: 1},
	}}}
	got := FromSmaliClassLines(sc, []string{".class public LA;", ".super Ljava/lang/Object;", ".method public invalid()V"})
	if len(got.Methods) != 1 || len(got.Methods[0].Instructions) != 0 {
		t.Fatalf("invalid source range invented instructions: %+v", got)
	}
}
