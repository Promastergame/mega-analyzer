package types

import (
	"strconv"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PARSING HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

// ParseAccessFlags парсит строковые модификаторы в AccessFlags.
func ParseAccessFlags(modifiers []string) AccessFlags {
	var flags AccessFlags
	for _, m := range modifiers {
		if flag, ok := stringToAccessFlag[m]; ok {
			flags |= flag
		}
	}
	return flags
}

// ParseInvokeType парсит строку типа invoke в InvokeType.
func ParseInvokeType(s string) InvokeType {
	if t, ok := invokeTypeByPrefix[s]; ok {
		return t
	}
	return InvokeUnknown
}

// ParseConditionOp парсит opcode условия в ConditionOp.
func ParseConditionOp(opcode string) ConditionOp {
	if op, ok := condOpByName[opcode]; ok {
		return op
	}
	return CondOpUnknown
}

// FormatDuration форматирует Duration человекочитаемо.
func FormatDuration(d time.Duration) string {
	if d < time.Millisecond {
		return strconv.FormatInt(d.Microseconds(), 10) + "µs"
	}
	if d < time.Second {
		return strconv.FormatInt(d.Milliseconds(), 10) + "ms"
	}
	return d.Round(time.Millisecond).String()
}

// TruncateString обрезает строку с защитой от panic.
func TruncateString(s string, maxLen int) string {
	if maxLen < 4 {
		maxLen = 4
	}
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// ═══════════════════════════════════════════════════════════════════════════════
// MATCHER INTERFACE (дизайн #15)
// ═══════════════════════════════════════════════════════════════════════════════

// Matcher — интерфейс для различных реализаций поиска.
// Позволяет подключать Aho-Corasick, Bloom filters, SIMD search.
type Matcher interface {
	// Match ищет совпадения в контенте.
	// contentLower — предвычисленный lowercase для оптимизации.
	// Возвращает найденные Match с заполненными SourceLocation.
	Match(content, contentLower []byte, filePath string) []Match

	// Name возвращает имя матчера для логирования.
	Name() string
}

// MatcherFunc — функциональный адаптер для Matcher.
type MatcherFunc struct {
	name    string
	matchFn func(content, contentLower []byte, filePath string) []Match
}

func NewMatcherFunc(name string, fn func(content, contentLower []byte, filePath string) []Match) *MatcherFunc {
	return &MatcherFunc{name: name, matchFn: fn}
}

func (m *MatcherFunc) Match(content, contentLower []byte, filePath string) []Match {
	return m.matchFn(content, contentLower, filePath)
}

func (m *MatcherFunc) Name() string { return m.name }
