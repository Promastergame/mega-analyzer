package lex

// Dialect represents the instruction set dialect.
type Dialect string

const (
	DialectSmali Dialect = "smali"
	DialectX86   Dialect = "x86"
)

// TokenType categorizes the type of lexical token found.
type TokenType int

const (
	TokenUnknown TokenType = iota
	TokenOpcode
	TokenRegister
	TokenLiteralString
	TokenLiteralInt
	TokenMethodRef
	TokenFieldRef
	TokenClassRef
	TokenLabel
	TokenComment
	// Add more token types as needed
)

// Token represents a lexical token in the analyzed code.
type Token struct {
	Type   TokenType
	Value  string
	Line   int // 1-indexed line number
	Column int // 1-indexed column number
	Offset int // 0-indexed byte offset from the start of the file
}
