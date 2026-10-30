// Package piracy — binary_analysis_fixed.go
// FIXED: Empty slice handling
package piracy

import (
	"context"
	"fmt"
	"math"
	"unicode"

	"mega-analyzer/pkg/internal/types"
)

// AnalyzeBinary анализирует бинарный файл
func (d *Detector) AnalyzeBinary(
	ctx context.Context,
	path string,
	data []byte,
) (*Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Bound extraction itself; truncating only after strings are assembled still
	// permits a large binary to consume disproportionate CPU and memory.
	if len(data) > MaxAnalysisSize {
		data = data[:MaxAnalysisSize]
	}

	// Extract strings
	strings := ExtractStrings(data, 6)
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// ✅ Handle empty slice
	if len(strings) == 0 {
		return &Result{
			IsPirated:  false,
			Confidence: 0,
			Findings:   make([]Finding, 0),
			RiskLevel:  "low",
		}, nil
	}

	// Concatenate for analysis
	total := 0
	for _, s := range strings {
		total += len(s)
	}
	if len(strings) > 1 {
		total += (len(strings) - 1) // newlines
	}
	textContent := make([]byte, total)
	pos := 0
	for i, s := range strings {
		if i > 0 {
			textContent[pos] = '\n'
			pos++
		}
		pos += copy(textContent[pos:], s)
	}

	// Run normal analysis on extracted strings
	// We analyze extracted strings as "text" to reuse the normal text pipeline.
	result, err := d.Analyze(ctx, path, textContent, types.FileTypeText)
	if err != nil {
		return nil, err
	}

	// Add entropy info
	entropy := CalculateEntropy(data)
	if IsLikelyEncrypted(data) {
		result.Findings = append(result.Findings, Finding{
			Type:        "encrypted",
			Source:      "entropy_analysis",
			Pattern:     "high_entropy",
			Location:    path,
			Confidence:  0.8,
			Description: fmt.Sprintf("High entropy (%.2f) suggests encrypted/compressed data", entropy),
		})
	}

	return result, nil
}

// ExtractStrings извлекает printable строки из бинарника
func ExtractStrings(data []byte, minLen int) []string {
	if minLen < 4 {
		minLen = 4
	}

	var results []string
	var current []rune

	for _, b := range data {
		r := rune(b)

		if isPrintable(r) {
			current = append(current, r)
		} else {
			if len(current) >= minLen {
				results = append(results, string(current))
			}
			current = current[:0]
		}
	}

	// Last chunk
	if len(current) >= minLen {
		results = append(results, string(current))
	}

	return results
}

func isPrintable(r rune) bool {
	return (r >= 0x20 && r < 0x7F) || unicode.IsPrint(r)
}

// CalculateEntropy вычисляет энтропию Шеннона
func CalculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	var freq [256]int
	for _, b := range data {
		freq[b]++
	}

	var entropy float64
	for _, count := range freq {
		if count == 0 {
			continue
		}
		p := float64(count) / float64(len(data))
		entropy -= p * math.Log2(p)
	}

	return entropy
}

// IsLikelyEncrypted проверяет, похоже ли на зашифрованные данные
func IsLikelyEncrypted(data []byte) bool {
	if len(data) < 64 {
		return false
	}

	entropy := CalculateEntropy(data)

	// High entropy (> 7.5) suggests encryption
	return entropy > 7.5
}
