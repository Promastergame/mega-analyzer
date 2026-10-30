package lex

import (
	"testing"
)

// ─── TokenType ────────────────────────────────────────────────────────────────

func TestTokenTypeConstants(t *testing.T) {
	// Ensure the constants are distinct and ordered correctly
	types := []TokenType{
		TokenUnknown,
		TokenOpcode,
		TokenRegister,
		TokenLiteralString,
		TokenLiteralInt,
		TokenMethodRef,
		TokenFieldRef,
		TokenClassRef,
		TokenLabel,
		TokenComment,
	}

	seen := make(map[TokenType]bool)
	for _, tt := range types {
		if seen[tt] {
			t.Errorf("duplicate token type value: %d", tt)
		}
		seen[tt] = true
	}

	if TokenUnknown != 0 {
		t.Error("TokenUnknown must be 0 (iota)")
	}
}

// ─── LexSmali ─────────────────────────────────────────────────────────────────

func TestLexSmali_EmptyInput(t *testing.T) {
	tokens := LexSmali("")
	if len(tokens) != 0 {
		t.Errorf("expected 0 tokens for empty input, got %d", len(tokens))
	}
}

func TestLexSmali_OnlyBlankLines(t *testing.T) {
	tokens := LexSmali("\n\n\n")
	if len(tokens) != 0 {
		t.Errorf("expected 0 tokens for blank lines, got %d", len(tokens))
	}
}

func TestLexSmali_CommentLine(t *testing.T) {
	tokens := LexSmali("# this is a comment\n")
	if len(tokens) != 0 {
		t.Errorf("expected 0 tokens for comment line, got %d", len(tokens))
	}
}

func TestLexSmali_Register_Cleaned(t *testing.T) {
	// Registers with trailing comma should have comma stripped
	source := "move v0, v1"
	tokens := LexSmali(source)
	for _, tok := range tokens {
		if tok.Type == TokenRegister {
			for _, ch := range tok.Value {
				if ch == ',' {
					t.Errorf("register token value still has comma: %q", tok.Value)
				}
			}
		}
	}
}

func TestLexSmali_MethodRef(t *testing.T) {
	source := `invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;`
	tokens := LexSmali(source)
	foundMethod := false
	for _, tok := range tokens {
		if tok.Type == TokenMethodRef {
			foundMethod = true
		}
	}
	if !foundMethod {
		t.Errorf("expected a TokenMethodRef in: %v", tokens)
	}
}

func TestLexSmali_LiteralStringStripsQuotes(t *testing.T) {
	source := `const-string v0, "hello world"`
	tokens := LexSmali(source)
	for _, tok := range tokens {
		if tok.Type == TokenLiteralString {
			if tok.Value != "hello world" {
				t.Errorf("expected literal string stripped of quotes, got %q", tok.Value)
			}
			return
		}
	}
	t.Error("no TokenLiteralString found")
}

func TestLexSmali_LineAndColumn(t *testing.T) {
	source := "const-string v0, \"hello\"\ninvoke-static {v0}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;"
	tokens := LexSmali(source)
	if len(tokens) == 0 {
		t.Fatal("expected tokens")
	}
	// First token on line 1
	if tokens[0].Line != 1 {
		t.Errorf("expected line 1 for first token, got %d", tokens[0].Line)
	}
	// Find tokens on line 2
	foundLine2 := false
	for _, tok := range tokens {
		if tok.Line == 2 {
			foundLine2 = true
			break
		}
	}
	if !foundLine2 {
		t.Error("expected at least one token on line 2")
	}
}

func TestLexSmali_UnknownToken(t *testing.T) {
	// Something that doesn't match any regex pattern
	source := "{}[]@#$%"
	tokens := LexSmali(source)
	for _, tok := range tokens {
		if tok.Type != TokenUnknown {
			t.Errorf("expected TokenUnknown for %q, got %v", tok.Value, tok.Type)
		}
	}
}

func TestLexSmali_ParamRegister(t *testing.T) {
	// p0, p1 are parameter registers
	source := "iget-object v0, p0, Lcom/example/Foo;->bar:Ljava/lang/String;"
	tokens := LexSmali(source)
	foundP0 := false
	for _, tok := range tokens {
		if tok.Type == TokenRegister && tok.Value == "p0" {
			foundP0 = true
		}
	}
	if !foundP0 {
		t.Errorf("expected p0 register token, tokens: %v", tokens)
	}
}

func TestLexSmali_StringWithSpaces(t *testing.T) {
	// String containing spaces must be lexed as a single token
	source := `const-string v0, "hello world foo"`
	tokens := LexSmali(source)
	strCount := 0
	for _, tok := range tokens {
		if tok.Type == TokenLiteralString {
			strCount++
			if tok.Value != "hello world foo" {
				t.Errorf("wrong string value: %q", tok.Value)
			}
		}
	}
	if strCount != 1 {
		t.Errorf("expected exactly 1 string token, got %d", strCount)
	}
}

// ─── LexX86 ───────────────────────────────────────────────────────────────────

func TestLexX86_BasicInstruction(t *testing.T) {
	source := "mov eax, ebx"
	tokens := LexX86(source)
	if len(tokens) < 2 {
		t.Fatalf("expected at least 2 tokens, got %d", len(tokens))
	}
	if tokens[0].Type != TokenOpcode || tokens[0].Value != "mov" {
		t.Errorf("expected opcode 'mov', got %+v", tokens[0])
	}
	if tokens[1].Type != TokenRegister || tokens[1].Value != "eax" {
		t.Errorf("expected register 'eax', got %+v", tokens[1])
	}
}

func TestLexX86_HexLiteral(t *testing.T) {
	source := "mov eax, 0xFF"
	tokens := LexX86(source)
	foundHex := false
	for _, tok := range tokens {
		if tok.Type == TokenLiteralInt {
			foundHex = true
			if tok.Value != "0xFF" {
				t.Errorf("expected 0xFF, got %q", tok.Value)
			}
		}
	}
	if !foundHex {
		t.Errorf("expected a hex literal token, got %v", tokens)
	}
}

func TestLexX86_EmptyInput(t *testing.T) {
	tokens := LexX86("")
	if len(tokens) != 0 {
		t.Errorf("expected 0 tokens, got %d", len(tokens))
	}
}

func TestLexX86_CommentStripped(t *testing.T) {
	source := "nop ; this is a comment"
	tokens := LexX86(source)
	// Only "nop" should be tokenized
	if len(tokens) != 1 {
		t.Errorf("expected 1 token (nop), got %d: %v", len(tokens), tokens)
	}
}

func TestLexX86_HashCommentStripped(t *testing.T) {
	source := "nop # this is a comment"
	tokens := LexX86(source)
	if len(tokens) != 1 {
		t.Errorf("expected 1 token (nop), got %d: %v", len(tokens), tokens)
	}
}

func TestLexX86_TrailingCommaStripped(t *testing.T) {
	source := "add eax, ebx"
	tokens := LexX86(source)
	for _, tok := range tokens {
		for _, ch := range tok.Value {
			if ch == ',' {
				t.Errorf("trailing comma not stripped from token %q", tok.Value)
			}
		}
	}
}

func TestLexX86_AllRegisters(t *testing.T) {
	regs := []string{"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
		"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"}
	for _, reg := range regs {
		source := "mov " + reg + ", 0x0"
		tokens := LexX86(source)
		foundReg := false
		for _, tok := range tokens {
			if tok.Type == TokenRegister && tok.Value == reg {
				foundReg = true
			}
		}
		if !foundReg {
			t.Errorf("register %s not recognised, tokens: %v", reg, tokens)
		}
	}
}

func TestLexX86_MultiLine(t *testing.T) {
	source := "push rbp\nmov rbp, rsp\npop rbp\nret"
	tokens := LexX86(source)
	// At minimum we expect 4 opcodes (push, mov, pop, ret) and some registers
	opcodeCount := 0
	for _, tok := range tokens {
		if tok.Type == TokenOpcode {
			opcodeCount++
		}
	}
	if opcodeCount < 4 {
		t.Errorf("expected >=4 opcodes, got %d", opcodeCount)
	}
}

func TestLexX86_BlankLines(t *testing.T) {
	source := "\n\n\nmov eax, ebx\n\n"
	tokens := LexX86(source)
	if len(tokens) == 0 {
		t.Error("expected tokens, got none")
	}
}

func TestLexX86_UnknownToken(t *testing.T) {
	// something that is not first position and not a known register
	source := "mov eax, myLabel"
	tokens := LexX86(source)
	foundUnknown := false
	for _, tok := range tokens {
		if tok.Type == TokenUnknown && tok.Value == "myLabel" {
			foundUnknown = true
		}
	}
	if !foundUnknown {
		t.Errorf("expected TokenUnknown for 'myLabel', tokens: %v", tokens)
	}
}

// ─── Matcher conditions ───────────────────────────────────────────────────────

func TestOpcode_Condition(t *testing.T) {
	cond := Opcode("nop")
	if !cond(Token{Type: TokenOpcode, Value: "nop"}) {
		t.Error("Opcode condition should match")
	}
	if cond(Token{Type: TokenOpcode, Value: "mov"}) {
		t.Error("Opcode condition should not match different value")
	}
	if cond(Token{Type: TokenRegister, Value: "nop"}) {
		t.Error("Opcode condition should not match wrong type")
	}
}

func TestAnyRegister_Condition(t *testing.T) {
	cond := AnyRegister()
	if !cond(Token{Type: TokenRegister, Value: "v0"}) {
		t.Error("AnyRegister should match TokenRegister")
	}
	if cond(Token{Type: TokenOpcode, Value: "v0"}) {
		t.Error("AnyRegister should not match non-register")
	}
}

func TestStringContains_Condition(t *testing.T) {
	cond := StringContains("foo")
	if !cond(Token{Type: TokenLiteralString, Value: "foobar"}) {
		t.Error("StringContains should match when substring present")
	}
	if cond(Token{Type: TokenLiteralString, Value: "bar"}) {
		t.Error("StringContains should not match when substring absent")
	}
	if cond(Token{Type: TokenOpcode, Value: "foobar"}) {
		t.Error("StringContains should not match wrong type")
	}
}

func TestStringEquals_Condition(t *testing.T) {
	cond := StringEquals("exact")
	if !cond(Token{Type: TokenLiteralString, Value: "exact"}) {
		t.Error("StringEquals should match exact value")
	}
	if cond(Token{Type: TokenLiteralString, Value: "exactmore"}) {
		t.Error("StringEquals should not match longer value")
	}
}

func TestAnyMethodRef_Condition(t *testing.T) {
	cond := AnyMethodRef()
	if !cond(Token{Type: TokenMethodRef, Value: "anything"}) {
		t.Error("AnyMethodRef should match TokenMethodRef")
	}
	if cond(Token{Type: TokenOpcode, Value: "anything"}) {
		t.Error("AnyMethodRef should not match non-method-ref")
	}
}

func TestMethodRefContains_Condition(t *testing.T) {
	cond := MethodRefContains("exec")
	if !cond(Token{Type: TokenMethodRef, Value: "Ljava/lang/Runtime;->exec"}) {
		t.Error("MethodRefContains should match")
	}
	if cond(Token{Type: TokenMethodRef, Value: "Ljava/lang/Runtime;->start"}) {
		t.Error("MethodRefContains should not match when substring absent")
	}
	if cond(Token{Type: TokenOpcode, Value: "exec"}) {
		t.Error("MethodRefContains should not match wrong type")
	}
}

// ─── Match engine edge cases ──────────────────────────────────────────────────

func TestMatch_EmptyPattern(t *testing.T) {
	tokens := []Token{{Type: TokenOpcode, Value: "nop"}}
	indices := Match(tokens, Pattern{})
	if len(indices) != 0 {
		t.Errorf("expected no matches for empty pattern, got %v", indices)
	}
}

func TestMatch_EmptyTokens(t *testing.T) {
	pattern := Pattern{Opcode("nop")}
	indices := Match(nil, pattern)
	if len(indices) != 0 {
		t.Errorf("expected no matches for empty tokens, got %v", indices)
	}
}

func TestMatch_PatternLongerThanTokens(t *testing.T) {
	tokens := []Token{{Type: TokenOpcode, Value: "nop"}}
	pattern := Pattern{Opcode("nop"), Opcode("ret")}
	indices := Match(tokens, pattern)
	if len(indices) != 0 {
		t.Errorf("expected no matches, got %v", indices)
	}
}

func TestMatch_MultipleMatches(t *testing.T) {
	tokens := []Token{
		{Type: TokenOpcode, Value: "nop"},
		{Type: TokenOpcode, Value: "nop"},
		{Type: TokenOpcode, Value: "nop"},
	}
	pattern := Pattern{Opcode("nop"), Opcode("nop")}
	indices := Match(tokens, pattern)
	if len(indices) != 2 {
		t.Errorf("expected 2 overlapping matches, got %v", indices)
	}
}

func TestMatch_SingleTokenPattern(t *testing.T) {
	tokens := []Token{
		{Type: TokenRegister, Value: "v0"},
		{Type: TokenRegister, Value: "v1"},
		{Type: TokenOpcode, Value: "nop"},
	}
	pattern := Pattern{AnyRegister()}
	indices := Match(tokens, pattern)
	if len(indices) != 2 {
		t.Errorf("expected 2 matches for AnyRegister, got %v", indices)
	}
}

func TestMatch_NoMatch(t *testing.T) {
	tokens := []Token{
		{Type: TokenOpcode, Value: "mov"},
		{Type: TokenRegister, Value: "eax"},
	}
	pattern := Pattern{Opcode("nop")}
	indices := Match(tokens, pattern)
	if len(indices) != 0 {
		t.Errorf("expected 0 matches, got %v", indices)
	}
}
