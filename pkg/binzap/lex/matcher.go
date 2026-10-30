package lex

import (
	"strings"
)

// Condition represents a function that checks if a Token meets specific criteria.
type Condition func(t Token) bool

// Pattern is a sequence of conditions that must be met sequentially to constitute a match.
type Pattern []Condition

// --- Built-in Matcher Conditions ---

// Opcode returns a condition that matches a TokenOpcode with a specific value.
func Opcode(val string) Condition {
	return func(t Token) bool {
		return t.Type == TokenOpcode && t.Value == val
	}
}

// AnyRegister returns a condition that matches any TokenRegister.
func AnyRegister() Condition {
	return func(t Token) bool {
		return t.Type == TokenRegister
	}
}

// StringContains returns a condition that matches a TokenLiteralString containing a substring.
func StringContains(substr string) Condition {
	return func(t Token) bool {
		return t.Type == TokenLiteralString && strings.Contains(t.Value, substr)
	}
}

// StringEquals returns a condition that matches a TokenLiteralString exactly.
func StringEquals(val string) Condition {
	return func(t Token) bool {
		return t.Type == TokenLiteralString && t.Value == val
	}
}

// AnyMethodRef returns a condition that matches any TokenMethodRef.
func AnyMethodRef() Condition {
	return func(t Token) bool {
		return t.Type == TokenMethodRef
	}
}

// MethodRefContains returns a condition that matches a TokenMethodRef containing a substring.
func MethodRefContains(substr string) Condition {
	return func(t Token) bool {
		return t.Type == TokenMethodRef && strings.Contains(t.Value, substr)
	}
}

// --- Matcher Engine ---

// Match finds all starting indices in a token stream where the pattern matches perfectly.
// For performance, this is a simple sliding window match.
func Match(tokens []Token, pattern Pattern) []int {
	var matchIndices []int
	if len(pattern) == 0 || len(tokens) == 0 {
		return matchIndices
	}

	for i := 0; i <= len(tokens)-len(pattern); i++ {
		match := true
		for j, condition := range pattern {
			if !condition(tokens[i+j]) {
				match = false
				break
			}
		}
		if match {
			matchIndices = append(matchIndices, i)
		}
	}
	return matchIndices
}
