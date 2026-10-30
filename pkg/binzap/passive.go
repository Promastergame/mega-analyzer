package binzap

import (
	"mega-analyzer/pkg/binzap/lex"
)

// ScanContext provides context to the passive rules about what is being scanned.
type ScanContext struct {
	File    string
	Dialect lex.Dialect
}

// Rule defines the interface that all passive scanner rules must implement.
type Rule interface {
	// ID returns a unique identifier for the rule (e.g., "BZ-PASS-001").
	ID() string

	// Name returns a human-readable name for the rule.
	Name() string

	// Severity returns the baseline severity of the rule.
	Severity() Severity

	// Match executes the rule logic against a stream of tokens.
	Match(ctx ScanContext, tokens []lex.Token) []Finding
}
