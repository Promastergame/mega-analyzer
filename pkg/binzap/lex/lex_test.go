package lex

import (
	"testing"
)

func TestLexSmali(t *testing.T) {
	source := `
		const-string v0, "MD5"
		invoke-static {v0}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;
	`
	tokens := LexSmali(source)

	if len(tokens) < 5 {
		t.Fatalf("Expected at least 5 tokens, got %d", len(tokens))
	}

	if tokens[0].Type != TokenOpcode || tokens[0].Value != "const-string" {
		t.Errorf("Expected const-string opcode, got %+v", tokens[0])
	}
	if tokens[1].Type != TokenRegister || tokens[1].Value != "v0" {
		t.Errorf("Expected register v0, got %+v", tokens[1])
	}
	if tokens[2].Type != TokenLiteralString || tokens[2].Value != "MD5" {
		t.Errorf("Expected literal string MD5, got %+v", tokens[2])
	}
	if tokens[3].Type != TokenOpcode || tokens[3].Value != "invoke-static" {
		t.Errorf("Expected invoke-static opcode, got %+v", tokens[3])
	}
}

func TestMatch(t *testing.T) {
	tokens := []Token{
		{Type: TokenOpcode, Value: "const-string"},
		{Type: TokenRegister, Value: "v0"},
		{Type: TokenLiteralString, Value: "MD5"},
		{Type: TokenOpcode, Value: "invoke-static"},
	}

	pattern := Pattern{
		Opcode("const-string"),
		AnyRegister(),
		StringEquals("MD5"),
	}

	indices := Match(tokens, pattern)
	if len(indices) != 1 || indices[0] != 0 {
		t.Errorf("Expected match at index 0, got %v", indices)
	}
}
