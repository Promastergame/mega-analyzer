package lex

import (
	"regexp"
	"strings"
)

// Simplified regexes for Smali tokens
var (
	rxOpcode        = regexp.MustCompile(`^[a-z]+(-[a-z0-9/]+)*$`)
	rxRegister      = regexp.MustCompile(`^[vp]\d+$`)
	rxLiteralString = regexp.MustCompile(`^".*"$`)
	rxMethodRef     = regexp.MustCompile(`^L[\w/]+;->[\w<>]+\(.*\).*$`)
)

// LexSmali performs lexical analysis on Smali source code.
// In a full implementation, this would be a high-performance state machine.
func LexSmali(source string) []Token {
	var tokens []Token
	lines := strings.Split(source, "\n")
	offset := 0

	for lineIdx, line := range lines {
		lineNum := lineIdx + 1
		lineOffset := offset
		offset += len(line) + 1 // +1 for newline

		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue // skip empty lines and comments
		}

		// A very naive split for demonstration.
		// A real lexer handles strings with spaces correctly.
		parts := parseSmaliLine(trimmed)

		colOffset := strings.Index(line, trimmed)
		for _, part := range parts {
			t := Token{
				Value:  part,
				Line:   lineNum,
				Column: colOffset + 1,
				Offset: lineOffset + colOffset,
			}

			if rxOpcode.MatchString(part) {
				t.Type = TokenOpcode
			} else if rxRegister.MatchString(strings.ReplaceAll(part, ",", "")) {
				t.Type = TokenRegister
				t.Value = strings.ReplaceAll(part, ",", "") // clean comma
			} else if rxLiteralString.MatchString(part) {
				t.Type = TokenLiteralString
				t.Value = strings.Trim(part, `"`) // strip quotes
			} else if rxMethodRef.MatchString(part) {
				t.Type = TokenMethodRef
			} else {
				t.Type = TokenUnknown
			}

			tokens = append(tokens, t)
			colOffset += len(part) + 1 // estimate column jump
		}
	}

	return tokens
}

// parseSmaliLine correctly splits a line, respecting string literals.
func parseSmaliLine(line string) []string {
	var result []string
	var current strings.Builder
	inString := false

	for _, r := range line {
		if r == '"' {
			inString = !inString
			current.WriteRune(r)
		} else if r == ' ' && !inString {
			if current.Len() > 0 {
				result = append(result, current.String())
				current.Reset()
			}
		} else {
			current.WriteRune(r)
		}
	}
	if current.Len() > 0 {
		result = append(result, current.String())
	}
	return result
}
