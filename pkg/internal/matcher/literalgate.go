package matcher

import (
	"regexp/syntax"
	"strings"
)

// ===============================================================================
// LITERAL GATE
//
// scanLines runs every candidate pattern's regex against every non-skippable
// line of a file. Profiling a full APK scan put ~24% of all CPU inside
// regexp.MatchString (mostly the backtracker), even though the overwhelming
// majority of those calls cannot possibly match.
//
// Most patterns require some literal substring to be present: "Lcom/android/
// vending/billing", "isPremium", "checkLicense". Extracting that mandatory
// literal from the compiled regex AST lets the loop reject a line with one
// SIMD-accelerated strings.Contains before paying for the regex engine.
//
// The gate is a NECESSARY condition derived from the pattern itself, so it can
// only skip lines the regex would have rejected anyway: findings are identical.
// Patterns with no provable literal (pure alternations, character classes)
// simply get an empty gate and behave exactly as before.
// ===============================================================================

// minGateLen is the shortest literal worth gating on. Shorter literals appear on
// nearly every line, so the Contains call would cost more than it saves.
const minGateLen = 3

// literalGate describes a mandatory substring of a pattern.
type literalGate struct {
	literal string
	fold    bool // literal is lowercase and must be searched in the lowercased line
}

// buildLiteralGate returns the longest substring that every string matching
// patternStr must contain. An empty literal means "no gate".
func buildLiteralGate(patternStr string) literalGate {
	re, err := syntax.Parse(patternStr, syntax.Perl)
	if err != nil {
		return literalGate{}
	}

	lit, fold := requiredLiteral(re.Simplify())
	if len(lit) < minGateLen {
		return literalGate{}
	}
	if fold {
		lit = strings.ToLower(lit)
	}
	return literalGate{literal: lit, fold: fold}
}

// requiredLiteral walks the regex AST and returns the longest literal run that
// must be present in any match, plus whether it was case-folded.
func requiredLiteral(re *syntax.Regexp) (string, bool) {
	if re == nil {
		return "", false
	}

	switch re.Op {
	case syntax.OpLiteral:
		fold := re.Flags&syntax.FoldCase != 0
		var b strings.Builder
		for _, r := range re.Rune {
			// Non-ASCII runes are excluded: the lowercased haystack is folded
			// with Unicode rules while the gate does a byte search, and the two
			// disagree on exotic runes. Dropping them loses an optimization,
			// never a finding.
			if r <= 0 || r > 127 {
				if b.Len() >= minGateLen {
					return b.String(), fold
				}
				b.Reset()
				continue
			}
			b.WriteByte(byte(r))
		}
		return b.String(), fold

	case syntax.OpCapture:
		if len(re.Sub) == 1 {
			return requiredLiteral(re.Sub[0])
		}

	case syntax.OpPlus:
		if len(re.Sub) == 1 {
			return requiredLiteral(re.Sub[0])
		}

	case syntax.OpRepeat:
		if re.Min >= 1 && len(re.Sub) == 1 {
			return requiredLiteral(re.Sub[0])
		}

	case syntax.OpConcat:
		// Every element is mandatory, so the longest child literal is required.
		best := ""
		bestFold := false
		for _, sub := range re.Sub {
			lit, fold := requiredLiteral(sub)
			if len(lit) > len(best) {
				best, bestFold = lit, fold
			}
		}
		return best, bestFold
	}

	return "", false
}
