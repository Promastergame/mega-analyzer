package verifier

import (
	"strconv"
	"strings"
)

// worse returns the more severe of two statuses, using the ordering
// passed < skipped < partial < failed. An empty status is treated as passed.
func worse(a, b Status) Status {
	if statusRank(b) > statusRank(a) {
		return b
	}
	return a
}

func statusRank(s Status) int {
	switch s {
	case "", StatusPassed:
		return 0
	case StatusSkipped:
		return 1
	case StatusPartial:
		return 2
	case StatusFailed:
		return 3
	default:
		return 0
	}
}

func sevRank(s Severity) int {
	switch s {
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// valuesMatch compares expected and actual leniently: case-insensitive and
// trimmed. Battery status and similar already share a vocabulary via the
// adapter's normalisation.
func valuesMatch(expected, actual string) bool {
	return strings.EqualFold(strings.TrimSpace(expected), strings.TrimSpace(actual))
}

func itoa(n int) string {
	if n == 0 {
		return ""
	}
	return strconv.Itoa(n)
}
