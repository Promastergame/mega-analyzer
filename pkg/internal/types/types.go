// Package types — ядро типовой системы APK-анализатора v3.1
// Zero-allocation enums, типобезопасные union-типы, thread-safe операции.
//
// Thread-safety contract:
// - MethodMetrics: immutable после создания, NOT thread-safe во время заполнения
// - AnalysisResult: thread-safe через mu, но Finalize() делает immutable
// - Pattern: Compile() должен вызываться до использования, NOT thread-safe
package types

import (
	"bytes"
	"fmt"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// БАЗОВЫЕ КОМПОНЕНТЫ
// ═══════════════════════════════════════════════════════════════════════════════

// SourceLocation — единая точка в исходном коде.
type SourceLocation struct {
	File   string `json:"file,omitempty"`
	Line   int    `json:"line,omitempty"`
	Column int    `json:"column,omitempty"`
	Method string `json:"method,omitempty"`
}

func (s SourceLocation) String() string {
	if s.Column > 0 {
		return fmt.Sprintf("%s:%d:%d", s.File, s.Line, s.Column)
	}
	return fmt.Sprintf("%s:%d", s.File, s.Line)
}

// SourceRange — диапазон строк.
type SourceRange struct {
	File      string `json:"file,omitempty"`
	LineStart int    `json:"line_start"`
	LineEnd   int    `json:"line_end"`
}

// Scored — компонент с оценкой.
type Scored struct {
	Score      float64 `json:"score,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
}

// Categorized — компонент с категорией.
type Categorized struct {
	Category Category `json:"category"`
}

// ═══════════════════════════════════════════════════════════════════════════════
// УТИЛИТЫ: Line search — ZERO-ALLOC
// ═══════════════════════════════════════════════════════════════════════════════

// LineNumberAt возвращает номер строки по byte offset.
// O(byteIndex) без аллокаций.
func LineNumberAt(content []byte, byteIndex int) int {
	if byteIndex <= 0 || len(content) == 0 {
		return 1
	}
	if byteIndex > len(content) {
		byteIndex = len(content)
	}
	return 1 + bytes.Count(content[:byteIndex], []byte{'\n'})
}

// FindPatternLine ищет паттерн и возвращает номер строки.
// ВАЖНО: contentLower должен быть предвычислен вызывающим кодом!
// Это избегает O(N) аллокации на каждый вызов.
func FindPatternLine(content, contentLower []byte, pattern string) int {
	if len(content) == 0 || pattern == "" {
		return 0
	}
	patLower := strings.ToLower(pattern)
	patBytes := []byte(patLower)

	idx := bytes.Index(contentLower, patBytes)
	if idx < 0 {
		return 0
	}
	return LineNumberAt(content, idx)
}

// FindPatternLineSimple — версия для редких вызовов (создаёт contentLower).
// Использовать только если вызов один на файл!
func FindPatternLineSimple(content []byte, pattern string) int {
	if len(content) == 0 || pattern == "" {
		return 0
	}
	contentLower := bytes.ToLower(content)
	return FindPatternLine(content, contentLower, pattern)
}

// ═══════════════════════════════════════════════════════════════════════════════
// LineOffsets — предвычисленный индекс строк для быстрого поиска
// ═══════════════════════════════════════════════════════════════════════════════

// LineOffsets предвычисляет позиции начала каждой строки.
// Используется для множественных поисков в одном файле.
type LineOffsets struct {
	offsets []int // offsets[i] = byte offset начала строки i+1
}

// NewLineOffsets создаёт индекс строк для контента.
func NewLineOffsets(content []byte) *LineOffsets {
	if len(content) == 0 {
		return &LineOffsets{offsets: []int{0}}
	}

	// Предаллоцируем примерно (средняя строка ~40 bytes)
	offsets := make([]int, 0, len(content)/40+1)
	offsets = append(offsets, 0) // строка 1 начинается с 0

	for i, b := range content {
		if b == '\n' && i+1 < len(content) {
			offsets = append(offsets, i+1)
		}
	}
	return &LineOffsets{offsets: offsets}
}

// LineAt возвращает номер строки для byte offset.
// Thread-safe (read-only после создания).
func (lo *LineOffsets) LineAt(byteIndex int) int {
	// Guard против nil и пустого
	if lo == nil || len(lo.offsets) == 0 {
		return 1
	}
	if byteIndex < 0 {
		return 1
	}

	// Binary search
	low, high := 0, len(lo.offsets)-1
	for low <= high {
		mid := (low + high) / 2
		if lo.offsets[mid] <= byteIndex {
			if mid+1 >= len(lo.offsets) || lo.offsets[mid+1] > byteIndex {
				return mid + 1
			}
			low = mid + 1
		} else {
			high = mid - 1
		}
	}
	return 1
}

// LineCount возвращает общее количество строк.
func (lo *LineOffsets) LineCount() int {
	if lo == nil || len(lo.offsets) == 0 {
		return 0
	}
	return len(lo.offsets)
}
