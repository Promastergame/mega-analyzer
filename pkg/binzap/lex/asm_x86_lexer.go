package lex

import (
	"regexp"
	"strings"
)

// Simplified regexes for x86/x64 assembly tokens.
var (
	rxX86Opcode     = regexp.MustCompile(`^[a-z]+$`)
	rxX86Register   = regexp.MustCompile(`^(eax|ebx|ecx|edx|esi|edi|ebp|esp|rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|r\d+d?)$`)
	rxX86LiteralHex = regexp.MustCompile(`^0x[0-9a-fA-F]+$`)
)

// callLikeOpcodes name control-transfer instructions whose first operand is a
// call/branch target. Recognising these lets the shared rule/taint engine treat
// the target as a method reference (fixing the previously dead x86 pipeline).
var callLikeOpcodes = map[string]bool{
	"call": true, "callq": true, "jmp": true, "jmpq": true,
	"je": true, "jne": true, "jz": true, "jnz": true,
	"jg": true, "jge": true, "jl": true, "jle": true,
	"ja": true, "jae": true, "jb": true, "jbe": true,
	"bl": true, "blx": true, "b": true,
}

// LexX86 performs lexical analysis on x86/x64 assembly code.
func LexX86(source string) []Token {
	var tokens []Token
	lines := strings.Split(source, "\n")
	offset := 0

	for lineIdx, line := range lines {
		lineNum := lineIdx + 1
		lineOffset := offset
		offset += len(line) + 1 // +1 for newline

		// Strip inline comments starting with ';' or '#'. A ';'/'#' inside a
		// quoted operand is preserved.
		codePart := stripAsmComment(line)

		trimmed := strings.TrimSpace(codePart)
		if trimmed == "" {
			continue
		}

		parts := fieldsPreservingQuotes(trimmed)
		if len(parts) == 0 {
			continue
		}
		colOffset := strings.Index(line, parts[0])
		if colOffset < 0 {
			colOffset = 0
		}

		opcode := ""
		for i, part := range parts {
			cleanPart := strings.TrimRight(part, ",")

			t := Token{
				Value:  cleanPart,
				Line:   lineNum,
				Column: colOffset + 1,
				Offset: lineOffset + colOffset,
			}

			switch {
			case i == 0 && rxX86Opcode.MatchString(cleanPart):
				t.Type = TokenOpcode
				opcode = cleanPart
			case len(cleanPart) >= 2 && strings.HasPrefix(cleanPart, "\"") && strings.HasSuffix(cleanPart, "\""):
				t.Type = TokenLiteralString
				t.Value = strings.Trim(cleanPart, "\"")
			case rxX86Register.MatchString(cleanPart):
				t.Type = TokenRegister
			case rxX86LiteralHex.MatchString(cleanPart):
				t.Type = TokenLiteralInt
			case i == 1 && callLikeOpcodes[opcode]:
				// call/branch target -> treat as a method reference so shared
				// dangerous-call rules can fire on native binaries too.
				t.Type = TokenMethodRef
			default:
				t.Type = TokenUnknown
			}

			tokens = append(tokens, t)
			colOffset += len(part) + 1
		}
	}

	return tokens
}

// stripAsmComment removes a trailing ';' or '#' comment, ignoring markers that
// appear inside a double-quoted operand.
func stripAsmComment(line string) string {
	inString := false
	for i, r := range line {
		if r == '"' {
			inString = !inString
			continue
		}
		if !inString && (r == ';' || r == '#') {
			return line[:i]
		}
	}
	return line
}

// fieldsPreservingQuotes splits on whitespace but keeps double-quoted operands
// (which may contain spaces) as a single field.
func fieldsPreservingQuotes(line string) []string {
	var result []string
	var current strings.Builder
	inString := false
	flush := func() {
		if current.Len() > 0 {
			result = append(result, current.String())
			current.Reset()
		}
	}
	for _, r := range line {
		switch {
		case r == '"':
			inString = !inString
			current.WriteRune(r)
		case (r == ' ' || r == '\t') && !inString:
			flush()
		default:
			current.WriteRune(r)
		}
	}
	flush()
	return result
}
