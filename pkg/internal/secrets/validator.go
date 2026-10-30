package secrets

import (
	"fmt"
	"math"
	"regexp"
	"strings"
)

// Common placeholder regexes
var (
	rePlaceholderSeq = regexp.MustCompile(`(?i)^(?:123456789|abcdef|abc123|your_api_key|gcp_key|aws_secret|token_here|mysecret)`)
)

func isRepeatingString(s string) bool {
	if len(s) < 8 {
		return false
	}
	first := s[0]
	for i := 1; i < len(s); i++ {
		if s[i] != first {
			return false
		}
	}
	return true
}

// CalculateEntropy calculates the Shannon Entropy of a string.
// Higher entropy indicates more randomness (ideal for real cryptographic keys).
func CalculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}

	counts := make(map[rune]int)
	for _, r := range s {
		counts[r]++
	}

	entropy := 0.0
	length := float64(len(s))
	for _, count := range counts {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}

	return entropy
}

// TriageResult holds the categorized results of our offline validation.
type TriageResult struct {
	Severity string // "info", "low", "medium", "high", "critical"
	Verdict  string // "placeholder", "expired-looking", "real-looking", "unclear"
	Detail   string
}

// Triage inspects a secret candidate and its surrounding context to perform
// high-fidelity offline classification and cut down false positives.
func Triage(ruleID, value, context string) TriageResult {
	value = strings.TrimSpace(value)
	context = strings.ToLower(context)

	// 1. Check if the value is an obvious placeholder
	if len(value) < 6 {
		return TriageResult{
			Severity: "info",
			Verdict:  "placeholder",
			Detail:   "Credential candidate is too short to be a real token.",
		}
	}

	if isRepeatingString(value) || rePlaceholderSeq.MatchString(value) {
		return TriageResult{
			Severity: "info",
			Verdict:  "placeholder",
			Detail:   "Identified obvious placeholder string or pattern sequence.",
		}
	}

	// 2. Compute Entropy
	entropy := CalculateEntropy(value)

	// Low entropy check: real keys (Base64/Hex/Raw) almost always have high entropy.
	// Low entropy indicates standard english words or simple patterns.
	isLowEntropy := entropy < 3.2
	if isLowEntropy {
		// Verify if the string is just a static name or label
		return TriageResult{
			Severity: "low",
			Verdict:  "placeholder",
			Detail:   "Low Shannon entropy indicates this is likely a static label or placeholder rather than a real key.",
		}
	}

	// 3. Scan context for mock/test/sandbox keywords
	isTestContext := strings.Contains(context, "test") ||
		strings.Contains(context, "mock") ||
		strings.Contains(context, "sandbox") ||
		strings.Contains(context, "dummy") ||
		strings.Contains(context, "fake") ||
		strings.Contains(context, "demo") ||
		strings.Contains(context, "example")

	// 4. Scan context for expired/disabled keywords
	isExpiredContext := strings.Contains(context, "expired") ||
		strings.Contains(context, "old_key") ||
		strings.Contains(context, "revoked") ||
		strings.Contains(context, "disabled") ||
		strings.Contains(context, "deprecated") ||
		strings.Contains(context, "inactive")

	// 5. Select Severity based on Triage Category and Context
	defaultSeverity := "high"
	if strings.Contains(ruleID, "aws") || strings.Contains(ruleID, "github") || strings.Contains(ruleID, "slack") || strings.Contains(ruleID, "stripe") || strings.Contains(ruleID, "telegram") || strings.Contains(ruleID, "discord") || strings.Contains(ruleID, "openai") || strings.Contains(ruleID, "anthropic") || strings.Contains(ruleID, "private-key") {
		defaultSeverity = "critical"
	}

	if isExpiredContext {
		return TriageResult{
			Severity: "low",
			Verdict:  "expired-looking",
			Detail:   "Key candidate detected but context indicates it is expired, revoked, or disabled.",
		}
	}

	if isTestContext {
		return TriageResult{
			Severity: "medium",
			Verdict:  "placeholder",
			Detail:   "Identified high-entropy key within explicit mock/test or sandbox context.",
		}
	}

	// High-confidence finding
	detail := "Real-looking credential with high Shannon entropy (" + formatEntropy(entropy) + ") and no test/sandbox keywords."
	return TriageResult{
		Severity: defaultSeverity,
		Verdict:  "real-looking",
		Detail:   detail,
	}
}

func formatEntropy(e float64) string {
	return fmt.Sprintf("%.2f", e)
}
