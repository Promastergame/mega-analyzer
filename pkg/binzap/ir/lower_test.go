package ir

import (
	"testing"

	"mega-analyzer/pkg/binzap/lex"
)

func TestLowerTokensAndClassify(t *testing.T) {
	tokens := []lex.Token{
		{Type: lex.TokenUnknown, Value: ".method", Line: 1},
		{Type: lex.TokenUnknown, Value: "public", Line: 1},
		{Type: lex.TokenUnknown, Value: "static", Line: 1},
		{Type: lex.TokenMethodRef, Value: "foo(I;Ljava/lang/String;)V", Line: 1},
		{Type: lex.TokenOpcode, Value: "const-string", Line: 2},
		{Type: lex.TokenRegister, Value: "v0", Line: 2},
		{Type: lex.TokenLiteralString, Value: "hello", Line: 2},
		{Type: lex.TokenOpcode, Value: "move-object", Line: 3},
		{Type: lex.TokenRegister, Value: "v1", Line: 3},
		{Type: lex.TokenRegister, Value: "v0", Line: 3},
		{Type: lex.TokenOpcode, Value: "invoke-virtual", Line: 4},
		{Type: lex.TokenUnknown, Value: "{v1,", Line: 4},
		{Type: lex.TokenUnknown, Value: "v0}", Line: 4},
		{Type: lex.TokenMethodRef, Value: "->length()I", Line: 4},
		{Type: lex.TokenOpcode, Value: "move-result", Line: 5},
		{Type: lex.TokenRegister, Value: "v2", Line: 5},
		{Type: lex.TokenOpcode, Value: "iget-object", Line: 6},
		{Type: lex.TokenRegister, Value: "v3", Line: 6},
		{Type: lex.TokenOpcode, Value: "iput-object", Line: 7},
		{Type: lex.TokenRegister, Value: "v3", Line: 7},
		{Type: lex.TokenOpcode, Value: "if-eq", Line: 8},
		{Type: lex.TokenMethodRef, Value: ":cond_0", Line: 8},
		{Type: lex.TokenOpcode, Value: "return-void", Line: 9},
		{Type: lex.TokenOpcode, Value: "nop", Line: 10}, // OpUnknown
		{Type: lex.TokenUnknown, Value: ".end method", Line: 11},
		// Test second method triggered by opcode when cur == nil
		{Type: lex.TokenOpcode, Value: "call", Line: 12},
		{Type: lex.TokenOpcode, Value: "jmp", Line: 13},
	}

	prog := LowerTokens("test.smali", lex.DialectSmali, tokens)
	if len(prog.Methods) != 2 {
		t.Fatalf("expected 2 methods, got %d", len(prog.Methods))
	}

	m0 := prog.Methods[0]
	if len(m0.Params) != 2 {
		t.Errorf("expected 2 params from parseParams, got %v", m0.Params)
	}

	// Verify stats
	stats := prog.Stats()
	if stats.Instructions == 0 || stats.Blocks == 0 || stats.Invokes == 0 {
		t.Errorf("unexpected stats: %+v", stats)
	}

	// Test parseParams directly on invalid/empty signatures
	if p := parseParams("invalid"); len(p) != 0 {
		t.Errorf("expected nil for invalid sig, got %v", p)
	}
	if p := parseParams("()V"); len(p) != 0 {
		t.Errorf("expected 0 for ()V, got %v", p)
	}

	// Test extractRegisters
	regs := extractRegisters("smali", "{v0, v1}")
	if len(regs) != 2 || regs[0] != "v0" || regs[1] != "v1" {
		t.Errorf("extractRegisters unexpected: %v", regs)
	}
}
