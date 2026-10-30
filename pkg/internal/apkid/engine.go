package apkid

import (
	"bytes"

	dexpkg "mega-analyzer/pkg/internal/apkid/dex"
)

// ─── ruleEngine ──────────────────────────────────────────────────────────────

// ruleEngine evaluates rules against file content using a pre-built
// Aho-Corasick automaton for O(n) literal matching plus per-rule AND/OR logic.
type ruleEngine struct {
	// ac is built once over all content_literal patterns from allRules.
	// Pattern index i in ac.patterns maps to literalOwners[i] = list of
	// (ruleIndex, matcherIndex) pairs that reference that literal.
	ac           *ahoCorasick
	patToRuleIdx [][]ruleMatcher // len == len(ac.patterns)
}

type ruleMatcher struct {
	ruleIdx    int
	matcherIdx int
}

// newRuleEngine constructs a ruleEngine from the given rule list.
// Literals shared by several rules are deduplicated so the automaton holds
// each distinct byte string once, with a reverse index to every
// (rule, matcher) pair that references it.
func newRuleEngine(rules []Rule) *ruleEngine {
	e := &ruleEngine{}

	var lits [][]byte
	litIndex := map[string]int{}
	for ri, r := range rules {
		for mi, m := range r.Matchers {
			if m.Kind != KindContentLiteral {
				continue
			}
			s := m.Pattern
			idx, exists := litIndex[s]
			if !exists {
				idx = len(lits)
				litIndex[s] = idx
				lits = append(lits, []byte(s))
				e.patToRuleIdx = append(e.patToRuleIdx, nil)
			}
			e.patToRuleIdx[idx] = append(e.patToRuleIdx[idx], ruleMatcher{ri, mi})
		}
	}

	e.ac = newAhoCorasick(lits)
	return e
}

// ─── File evaluation ─────────────────────────────────────────────────────────

// EvalResult holds the outcome of evaluating one rule against one file.
type EvalResult struct {
	Rule     *Rule
	Evidence string
}

// EvalFile evaluates all rules against a single file and returns every rule
// that matched. entryName is the slash-separated path inside the archive (or
// filesystem path relative to root) and is used for KindEntryName matchers.
// dexInfo may be nil when parsing failed or the file is not a DEX.
func (e *ruleEngine) EvalFile(
	rules []Rule,
	kind string,
	entryName string,
	data []byte,
	dexInfo *dexpkg.DEXInfo,
) []EvalResult {
	scope := scopeOf(kind)

	// Run AC automaton once over content — get patternIndex → offset.
	acHits := e.ac.findAll(data)

	// Per-rule matched-matcher tracking for AllOf logic.
	// We process rules in one pass.
	var results []EvalResult

	for ri := range rules {
		r := &rules[ri]

		// Scope filter: skip rules that don't apply to this file type.
		if r.Scopes != ScopeAny && (r.Scopes&scope) == 0 {
			continue
		}

		// Special case: packer.encrypted_asset has no matchers — handled
		// externally by entropy check in scanner.
		if len(r.Matchers) == 0 {
			continue
		}

		ev, ok := e.evalRule(r, acHits, data, entryName, dexInfo)
		if ok {
			results = append(results, EvalResult{Rule: r, Evidence: ev})
		}
	}
	return results
}

// evalRule checks whether a single rule fires. Returns (evidence, true) on hit.
func (e *ruleEngine) evalRule(
	r *Rule,
	acHits map[int]int, // patternIndex → byte offset
	data []byte,
	entry string,
	dexInfo *dexpkg.DEXInfo,
) (string, bool) {
	if r.Logic == AllOf {
		return e.evalAllOf(r, acHits, data, entry, dexInfo)
	}
	return e.evalAnyOf(r, acHits, data, entry, dexInfo)
}

func (e *ruleEngine) evalAnyOf(
	r *Rule,
	acHits map[int]int,
	data []byte,
	entry string,
	dexInfo *dexpkg.DEXInfo,
) (string, bool) {
	for _, m := range r.Matchers {
		if ev, ok := e.evalMatcher(&m, acHits, data, entry, dexInfo); ok {
			return ev, true
		}
	}
	return "", false
}

func (e *ruleEngine) evalAllOf(
	r *Rule,
	acHits map[int]int,
	data []byte,
	entry string,
	dexInfo *dexpkg.DEXInfo,
) (string, bool) {
	evidences := make([]string, 0, len(r.Matchers))
	for _, m := range r.Matchers {
		ev, ok := e.evalMatcher(&m, acHits, data, entry, dexInfo)
		if !ok {
			return "", false
		}
		evidences = append(evidences, ev)
	}
	// Join evidence from all matchers for AllOf rules.
	combined := ""
	for i, ev := range evidences {
		if i > 0 {
			combined += " && "
		}
		combined += ev
	}
	return combined, true
}

// evalMatcher evaluates one Matcher and returns (evidence, hit).
func (e *ruleEngine) evalMatcher(
	m *Matcher,
	acHits map[int]int,
	data []byte,
	entry string,
	dexInfo *dexpkg.DEXInfo,
) (string, bool) {
	switch m.Kind {
	case KindContentLiteral:
		// Look up via AC hit map — O(1).
		pat := []byte(m.Pattern)
		// Find the pattern's index in the AC automaton.
		for pi, p := range e.ac.patterns {
			if bytes.Equal(p, pat) {
				if offset, hit := acHits[pi]; hit {
					// Extract a small snippet around the match.
					return snippetAt(data, offset, len(pat)), true
				}
				return "", false
			}
		}
		// Fallback: pattern not in AC (shouldn't happen for compiled engines).
		if i := bytes.Index(data, pat); i >= 0 {
			return snippetAt(data, i, len(pat)), true
		}
		return "", false

	case KindContentRegex:
		if m.compiled == nil {
			return "", false
		}
		if loc := m.compiled.FindIndex(data); loc != nil {
			return string(data[loc[0]:loc[1]]), true
		}
		return "", false

	case KindEntryName:
		if matcherContains(entry, m.Pattern) {
			return entry, true
		}
		return "", false

	case KindDexString:
		if dexInfo == nil {
			return "", false
		}
		for _, s := range dexInfo.StringPool {
			if containsStr(s, m.Pattern) {
				return s, true
			}
		}
		return "", false
	}
	return "", false
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// snippetAt extracts a context window of up to 80 bytes around offset.
func snippetAt(data []byte, offset, matchLen int) string {
	start := offset
	if start < 0 {
		start = 0
	}
	end := offset + matchLen + 20
	if end > len(data) {
		end = len(data)
	}
	return string(data[start:end])
}

// containsStr is a plain substring check (case-sensitive for DEX strings).
func containsStr(s, pattern string) bool {
	return len(pattern) > 0 && len(s) >= len(pattern) &&
		(s == pattern || len(s) > len(pattern) && stringContains(s, pattern))
}

func stringContains(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
