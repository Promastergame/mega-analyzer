package analyzer

import (
	"math"
	"regexp"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS — used by tests and other components
// ═══════════════════════════════════════════════════════════════════════════════

// NormalizeScore нормализует значение score в диапазон [0, 1].
func NormalizeScore(score, min, max float64) float64 {
	if min >= max {
		return 0.0
	}
	result := (score - min) / (max - min)
	if result < 0 {
		return 0.0
	}
	if result > 1 {
		return 1.0
	}
	return result
}

// CalculateComplexity вычисляет метрику сложности метода.
func CalculateComplexity(decisionPoints, callCount int) int {
	return decisionPoints + callCount/2
}

// IsObfuscatedName проверяет, похоже ли имя на обфусцированное.
func IsObfuscatedName(name string) bool {
	if len(name) == 0 {
		return false
	}
	if len(name) <= 2 {
		return true
	}
	// Short names with underscores or numbers are suspicious
	if len(name) <= 3 {
		return false
	}
	// Check for patterns like a_, a1, ab1, etc.
	if len(name) <= 4 {
		hasSpecial := strings.ContainsAny(name, "_0123456789")
		if hasSpecial {
			return true
		}
	}
	return false
}

// CalculateMethodRisk вычисляет риск метода на основе сложности и энтропии.
func CalculateMethodRisk(complexity int, entropy float64) float64 {
	// Normalize complexity to 0-1 range (assume max complexity ~20)
	complexityNorm := float64(complexity) / 20.0
	if complexityNorm > 1.0 {
		complexityNorm = 1.0
	}

	// Normalize entropy to 0-1 range (max entropy for bytes is 8.0)
	entropyNorm := entropy / 8.0
	if entropyNorm > 1.0 {
		entropyNorm = 1.0
	}

	// Weighted combination
	risk := 0.6*complexityNorm + 0.4*entropyNorm
	if risk > 1.0 {
		risk = 1.0
	}
	return risk
}

// ExtractClassName извлекает имя класса из пути к smali файлу.
func ExtractClassName(path string) string {
	// Normalize Windows paths
	path = strings.ReplaceAll(path, "\\", "/")

	// Remove .smali extension
	path = strings.TrimSuffix(path, ".smali")

	// Extract the class part after "smali/"
	idx := strings.Index(path, "smali/")
	if idx >= 0 {
		path = path[idx+6:] // skip "smali/"
	}

	return "L" + path + ";"
}

// IsNativeMethod проверяет, является ли smali-метод нативным.
func IsNativeMethod(line string) bool {
	return strings.Contains(line, ".method") && strings.Contains(line, "native")
}

var (
	ifPattern       = regexp.MustCompile(`^if-\w+`)
	packedSwitchPat = regexp.MustCompile(`^packed-switch`)
	sparseSwitchPat = regexp.MustCompile(`^sparse-switch`)
	catchPattern    = regexp.MustCompile(`^\.catch\s`)
)

// CountDecisionPoints подсчитывает точки ветвления в smali-коде.
func CountDecisionPoints(lines []string) int {
	count := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if ifPattern.MatchString(line) {
			count++
		} else if packedSwitchPat.MatchString(line) || sparseSwitchPat.MatchString(line) {
			count++
		} else if catchPattern.MatchString(line) {
			count++
		}
	}
	return count
}

// MethodCallInfo описывает один вызов метода.
type MethodCallInfo struct {
	InvokeType string // invoke-virtual, invoke-static, etc.
	Class      string // Ljava/lang/String;
	Method     string // ->length()I
	FullCall   string // full invoke line
}

var invokePattern = regexp.MustCompile(`^(invoke-\w+)\s+\{[^}]*\},\s+(L[^;]+;->\S+)`)

// ExtractMethodCalls извлекает вызовы методов из smali-кода.
func ExtractMethodCalls(lines []string) []MethodCallInfo {
	var calls []MethodCallInfo
	for _, line := range lines {
		line = strings.TrimSpace(line)
		matches := invokePattern.FindStringSubmatch(line)
		if len(matches) >= 3 {
			fullCall := matches[2]
			// Parse class and method
			parts := strings.SplitN(fullCall, "->", 2)
			if len(parts) == 2 {
				calls = append(calls, MethodCallInfo{
					InvokeType: matches[1],
					Class:      parts[0],
					Method:     parts[1],
					FullCall:   fullCall,
				})
			}
		}
	}
	return calls
}

// CalculateCorrelationScore вычисляет скор корреляции между двумя файлами
// на основе совпадения пакетов.
func CalculateCorrelationScore(file1, file2 string) float64 {
	// Normalize paths
	f1 := strings.ReplaceAll(file1, "\\", "/")
	f2 := strings.ReplaceAll(file2, "\\", "/")

	// Extract package paths
	pkg1 := extractPackage(f1)
	pkg2 := extractPackage(f2)

	if pkg1 == "" || pkg2 == "" {
		return 0.0
	}

	if pkg1 == pkg2 {
		return 1.0
	}

	// Calculate Jaccard similarity of package components
	parts1 := strings.Split(pkg1, "/")
	parts2 := strings.Split(pkg2, "/")

	intersection := 0
	union := len(parts1) + len(parts2)

	set1 := make(map[string]bool)
	for _, p := range parts1 {
		set1[p] = true
	}

	for _, p := range parts2 {
		if set1[p] {
			intersection++
		} else {
			union++
		}
	}

	if union == 0 {
		return 0.0
	}

	return float64(intersection) / float64(union)
}

// IsHighEntropyThreshold — convenience wrapper with default threshold 4.5.
func IsHighEntropyThreshold(data []byte) bool {
	return IsHighEntropy(data, 4.5)
}

// ShannonEntropy computes Shannon entropy of a string (for legacy compatibility).
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int)
	for _, r := range s {
		freq[r]++
	}
	total := float64(len(s))
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}
