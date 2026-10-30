// Package analyzer — entropy.go v5.0
// Shannon entropy + extended analysis:
//   - Zero-alloc byte entropy (fixed [256]int array)
//   - Normalized entropy (0.0–1.0)
//   - Extended stats (unique bytes, most common, chi-squared)
//   - String entropy & classification (base64/hex/obfuscated/plaintext)
//   - Sliding window entropy for binary data
//   - Batch string analysis for file-level scanning
//   - Obfuscation confidence scoring
package analyzer

import (
	"math"
	"sort"
	"strings"
	"unicode"
)

// ═══════════════════════════════════════════════════════════════════════════════
// CORE ENTROPY — byte-level, zero-alloc
// ═══════════════════════════════════════════════════════════════════════════════

// CalculateEntropy вычисляет энтропию Шеннона для данных.
// Возвращает значение в bits-per-byte (0.0 – 8.0).
// Zero-alloc: использует [256]int на стеке.
func CalculateEntropy(data []byte) float64 {
	dataLen := len(data)
	if dataLen < 16 {
		return 0.0
	}

	var freq [256]int
	for _, b := range data {
		freq[b]++
	}

	length := float64(dataLen)
	entropy := 0.0

	for _, count := range freq {
		if count > 0 {
			p := float64(count) / length
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// CalculateEntropyNormalized возвращает нормализованную энтропию (0.0 – 1.0).
// 1.0 = максимальная (случайные данные), 0.0 = минимальная (одинаковые байты).
func CalculateEntropyNormalized(data []byte) float64 {
	e := CalculateEntropy(data)
	if e <= 0 {
		return 0
	}
	return e / 8.0
}

// IsHighEntropy проверяет, являются ли данные высокоэнтропийными.
// Для зашифрованных/сжатых данных threshold обычно 7.0–7.5.
func IsHighEntropy(data []byte, threshold float64) bool {
	return CalculateEntropy(data) >= threshold
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXTENDED STATS — один проход, полная статистика
// ═══════════════════════════════════════════════════════════════════════════════

// EntropyStats — расширенная статистика энтропии.
type EntropyStats struct {
	Entropy           float64 // bits per byte (0–8)
	EntropyNormalized float64 // 0.0–1.0
	UniqueBytes       int     // количество уникальных байт (0–256)
	MostCommonByte    byte    // самый частый байт
	MostCommonCount   int     // сколько раз встречается
	MostCommonPct     float64 // процент самого частого (0.0–1.0)
	ChiSquared        float64 // χ² статистика vs uniform distribution
	IsRandom          bool    // χ² < порог для 255 df (p=0.05)
	DataLength        int
}

// CalculateEntropyStats вычисляет расширенную статистику за один проход.
func CalculateEntropyStats(data []byte) EntropyStats {
	dataLen := len(data)
	if dataLen < 16 {
		return EntropyStats{DataLength: dataLen}
	}

	var freq [256]int
	for _, b := range data {
		freq[b]++
	}

	length := float64(dataLen)
	expected := length / 256.0

	var (
		uniqueBytes     int
		mostCommonByte  byte
		mostCommonCount int
		entropy         float64
		chiSquared      float64
	)

	for i, count := range freq {
		if count > 0 {
			uniqueBytes++
			p := float64(count) / length
			entropy -= p * math.Log2(p)

			if count > mostCommonCount {
				mostCommonCount = count
				mostCommonByte = byte(i)
			}
		}

		// Chi-squared vs uniform
		diff := float64(count) - expected
		chiSquared += (diff * diff) / expected
	}

	// Для 255 df, p=0.05: χ² < ~293 → данные не отличаются от uniform
	// Для p=0.01: < ~310
	isRandom := chiSquared < 293.0

	return EntropyStats{
		Entropy:           entropy,
		EntropyNormalized: entropy / 8.0,
		UniqueBytes:       uniqueBytes,
		MostCommonByte:    mostCommonByte,
		MostCommonCount:   mostCommonCount,
		MostCommonPct:     float64(mostCommonCount) / length,
		ChiSquared:        chiSquared,
		IsRandom:          isRandom,
		DataLength:        dataLen,
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// STRING ENTROPY — для анализа строковых констант
// ═══════════════════════════════════════════════════════════════════════════════

// StringEntropy вычисляет энтропию строки на уровне символов (не байт).
// Учитывает реальный алфавит строки.
func StringEntropy(s string) float64 {
	if len(s) < 4 {
		return 0.0
	}

	freq := make(map[rune]int, 64)
	total := 0

	for _, r := range s {
		freq[r]++
		total++
	}

	if total == 0 {
		return 0.0
	}

	length := float64(total)
	entropy := 0.0

	for _, count := range freq {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}

	return entropy
}

// StringEntropyNormalized возвращает энтропию нормализованную по размеру алфавита.
// 0.0 = все символы одинаковые, 1.0 = максимально разнообразно.
func StringEntropyNormalized(s string) float64 {
	if len(s) < 4 {
		return 0.0
	}

	freq := make(map[rune]int, 64)
	total := 0
	for _, r := range s {
		freq[r]++
		total++
	}

	alphabetSize := len(freq)
	if alphabetSize <= 1 {
		return 0.0
	}

	length := float64(total)
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}

	maxEntropy := math.Log2(float64(alphabetSize))
	if maxEntropy <= 0 {
		return 0.0
	}

	return entropy / maxEntropy
}

// ═══════════════════════════════════════════════════════════════════════════════
// STRING CLASSIFICATION — определение типа строки
// ═══════════════════════════════════════════════════════════════════════════════

// StringClass описывает тип строки.
type StringClass int

const (
	StringClassPlainText  StringClass = iota // обычный текст
	StringClassIdentifier                    // code identifier (camelCase, snake_case)
	StringClassBase64                        // base64 encoded
	StringClassHex                           // hex encoded
	StringClassObfuscated                    // obfuscated/encrypted
	StringClassNumeric                       // mostly numbers
	StringClassPath                          // file path / URL
	StringClassUnknown                       // не удалось классифицировать
)

// String возвращает текстовое представление класса.
func (sc StringClass) String() string {
	switch sc {
	case StringClassPlainText:
		return "plaintext"
	case StringClassIdentifier:
		return "identifier"
	case StringClassBase64:
		return "base64"
	case StringClassHex:
		return "hex"
	case StringClassObfuscated:
		return "obfuscated"
	case StringClassNumeric:
		return "numeric"
	case StringClassPath:
		return "path"
	default:
		return "unknown"
	}
}

// StringAnalysis — результат анализа одной строки.
type StringAnalysis struct {
	Value             string
	Length            int
	Entropy           float64 // символьная энтропия
	EntropyNormalized float64
	Classification    StringClass
	ObfuscationScore  float64 // 0.0–1.0 — уверенность в обфускации
	UniqueChars       int
	AlphaRatio        float64 // доля букв
	DigitRatio        float64 // доля цифр
	UpperRatio        float64 // доля заглавных (от букв)
	SpecialRatio      float64 // доля спецсимволов
	HasSpaces         bool
	AvgWordLength     float64
}

// ClassifyString выполняет полный анализ и классификацию строки.
func ClassifyString(s string) StringAnalysis {
	analysis := StringAnalysis{
		Value:  s,
		Length: len(s),
	}

	if len(s) < 2 {
		analysis.Classification = StringClassUnknown
		return analysis
	}

	// ── Character statistics ──
	var (
		totalRunes   int
		alphaCount   int
		upperCount   int
		digitCount   int
		spaceCount   int
		specialCount int
	)

	charFreq := make(map[rune]int, 64)

	for _, r := range s {
		totalRunes++
		charFreq[r]++

		switch {
		case unicode.IsLetter(r):
			alphaCount++
			if unicode.IsUpper(r) {
				upperCount++
			}
		case unicode.IsDigit(r):
			digitCount++
		case unicode.IsSpace(r):
			spaceCount++
		default:
			specialCount++
		}
	}

	if totalRunes == 0 {
		analysis.Classification = StringClassUnknown
		return analysis
	}

	total := float64(totalRunes)
	analysis.UniqueChars = len(charFreq)
	analysis.AlphaRatio = float64(alphaCount) / total
	analysis.DigitRatio = float64(digitCount) / total
	analysis.SpecialRatio = float64(specialCount) / total
	analysis.HasSpaces = spaceCount > 0

	if alphaCount > 0 {
		analysis.UpperRatio = float64(upperCount) / float64(alphaCount)
	}

	// ── Entropy ──
	analysis.Entropy = StringEntropy(s)
	analysis.EntropyNormalized = StringEntropyNormalized(s)

	// ── Average word length ──
	words := strings.Fields(s)
	if len(words) > 0 {
		totalWordLen := 0
		for _, w := range words {
			totalWordLen += len(w)
		}
		analysis.AvgWordLength = float64(totalWordLen) / float64(len(words))
	}

	// ── Classification ──
	analysis.Classification = classifyByStats(analysis, s)
	analysis.ObfuscationScore = calculateObfuscationScore(analysis)

	return analysis
}

func classifyByStats(a StringAnalysis, s string) StringClass {
	// Path / URL
	if strings.HasPrefix(s, "/") || strings.HasPrefix(s, "http") ||
		strings.Contains(s, "://") || (strings.Contains(s, "/") && strings.Contains(s, ".")) {
		return StringClassPath
	}

	// Numeric
	if a.DigitRatio > 0.85 {
		return StringClassNumeric
	}

	// Hex check: only 0-9, a-f, A-F
	if a.Length >= 8 && isHexString(s) {
		return StringClassHex
	}

	// Base64 check
	if a.Length >= 8 && isBase64Like(s) {
		return StringClassBase64
	}

	// Plain text: has spaces, reasonable entropy, mostly alpha
	if a.HasSpaces && a.AlphaRatio > 0.6 && a.Entropy < 4.5 {
		return StringClassPlainText
	}

	// Identifier: camelCase or snake_case, no spaces
	if !a.HasSpaces && a.AlphaRatio > 0.7 && a.Length < 80 {
		return StringClassIdentifier
	}

	// High entropy + no spaces + mixed case = likely obfuscated
	if a.Entropy > 3.5 && !a.HasSpaces && a.UniqueChars > 15 {
		return StringClassObfuscated
	}

	return StringClassUnknown
}

func isHexString(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

func isBase64Like(s string) bool {
	// Must be mostly alphanumeric + /+ = padding
	validChars := 0
	paddingChars := 0

	for _, r := range s {
		switch {
		case (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			validChars++
		case r == '+' || r == '/':
			validChars++
		case r == '=':
			paddingChars++
		case r == '\n' || r == '\r':
			// ignore whitespace in base64
		default:
			return false
		}
	}

	total := validChars + paddingChars
	if total == 0 {
		return false
	}

	// Base64 strings are typically multiples of 4
	return float64(validChars)/float64(total) >= 0.95 && len(s)%4 <= 1
}

func calculateObfuscationScore(a StringAnalysis) float64 {
	score := 0.0

	// High entropy contributes
	if a.Entropy > 4.0 {
		score += (a.Entropy - 4.0) / 4.0 * 0.3 // max 0.3
	}

	// High unique char ratio
	if a.Length > 0 {
		uniqueRatio := float64(a.UniqueChars) / float64(a.Length)
		if uniqueRatio > 0.6 {
			score += 0.2
		}
	}

	// No spaces in long string
	if !a.HasSpaces && a.Length > 20 {
		score += 0.15
	}

	// Mixed case without being camelCase
	if a.UpperRatio > 0.2 && a.UpperRatio < 0.8 && a.Length > 10 {
		score += 0.1
	}

	// High special char ratio
	if a.SpecialRatio > 0.15 {
		score += 0.15
	}

	// Very high entropy normalized
	if a.EntropyNormalized > 0.85 {
		score += 0.1
	}

	if score > 1.0 {
		score = 1.0
	}
	return score
}

// ═══════════════════════════════════════════════════════════════════════════════
// BATCH ANALYSIS — для анализа всех строк файла
// ═══════════════════════════════════════════════════════════════════════════════

// BatchStringAnalysis — результат пакетного анализа строк.
type BatchStringAnalysis struct {
	TotalStrings     int
	AnalyzedStrings  int
	HighEntropyCount int
	ObfuscatedCount  int
	Base64Count      int
	HexCount         int

	// Top suspicious strings (sorted by obfuscation score)
	TopSuspicious []StringAnalysis

	// Average metrics
	AvgEntropy         float64
	AvgObfuscation     float64
	ObfuscationDensity float64 // obfuscated / total
}

// AnalyzeStrings выполняет пакетный анализ массива строк.
// minLength — минимальная длина строки для анализа.
// topN — сколько самых подозрительных вернуть.
func AnalyzeStrings(strings []string, minLength int, topN int) BatchStringAnalysis {
	result := BatchStringAnalysis{
		TotalStrings: len(strings),
	}

	if len(strings) == 0 {
		return result
	}

	if minLength < 4 {
		minLength = 4
	}

	var suspicious []StringAnalysis
	var totalEntropy, totalObfuscation float64

	for _, s := range strings {
		if len(s) < minLength {
			continue
		}

		result.AnalyzedStrings++
		analysis := ClassifyString(s)

		totalEntropy += analysis.Entropy
		totalObfuscation += analysis.ObfuscationScore

		switch analysis.Classification {
		case StringClassBase64:
			result.Base64Count++
		case StringClassHex:
			result.HexCount++
		case StringClassObfuscated:
			result.ObfuscatedCount++
		}

		if analysis.Entropy > 4.0 {
			result.HighEntropyCount++
		}

		if analysis.ObfuscationScore > 0.3 {
			suspicious = append(suspicious, analysis)
		}
	}

	if result.AnalyzedStrings > 0 {
		n := float64(result.AnalyzedStrings)
		result.AvgEntropy = totalEntropy / n
		result.AvgObfuscation = totalObfuscation / n
		result.ObfuscationDensity = float64(result.ObfuscatedCount) / n
	}

	// Sort suspicious by score descending
	sort.Slice(suspicious, func(i, j int) bool {
		return suspicious[i].ObfuscationScore > suspicious[j].ObfuscationScore
	})

	if len(suspicious) > topN {
		suspicious = suspicious[:topN]
	}
	result.TopSuspicious = suspicious

	return result
}

// ═══════════════════════════════════════════════════════════════════════════════
// SLIDING WINDOW — для бинарных данных (DEX, SO)
// ═══════════════════════════════════════════════════════════════════════════════

// EntropyWindow — результат энтропии для одного окна.
type EntropyWindow struct {
	Offset  int
	Entropy float64
}

// SlidingWindowEntropy вычисляет энтропию скользящим окном.
// windowSize — размер окна (обычно 256 или 512 байт).
// stepSize — шаг смещения (обычно windowSize/4).
func SlidingWindowEntropy(data []byte, windowSize, stepSize int) []EntropyWindow {
	if len(data) < windowSize || windowSize < 16 || stepSize < 1 {
		return nil
	}

	numWindows := (len(data)-windowSize)/stepSize + 1
	results := make([]EntropyWindow, 0, numWindows)

	for offset := 0; offset+windowSize <= len(data); offset += stepSize {
		window := data[offset : offset+windowSize]
		e := CalculateEntropy(window)

		results = append(results, EntropyWindow{
			Offset:  offset,
			Entropy: e,
		})
	}

	return results
}

// FindHighEntropyRegions находит непрерывные регионы с энтропией выше порога.
// Возвращает начало и конец каждого региона.
func FindHighEntropyRegions(data []byte, windowSize, stepSize int, threshold float64) [][2]int {
	windows := SlidingWindowEntropy(data, windowSize, stepSize)
	if len(windows) == 0 {
		return nil
	}

	var regions [][2]int
	inRegion := false
	regionStart := 0

	for _, w := range windows {
		if w.Entropy >= threshold {
			if !inRegion {
				regionStart = w.Offset
				inRegion = true
			}
		} else {
			if inRegion {
				regions = append(regions, [2]int{regionStart, w.Offset + windowSize})
				inRegion = false
			}
		}
	}

	// Close last region
	if inRegion {
		lastOffset := windows[len(windows)-1].Offset
		regions = append(regions, [2]int{regionStart, lastOffset + windowSize})
	}

	return regions
}

// ═══════════════════════════════════════════════════════════════════════════════
// IMPORT SORT (for AnalyzeStrings)
// ═══════════════════════════════════════════════════════════════════════════════

// sort is already imported above via "sort" in import block
// (Go will handle this — adding import to the import block at top)
