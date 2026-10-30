// Package sastrules implements a regex-driven SAST engine on top of
// MobSF-style YAML rules (ported to JSON for embedding).
//
// Pattern types supported (verbatim from libsast):
//
//   - "regex"          : single Pattern
//   - "regex_and"      : all of Patterns must match
//   - "regex_or"       : at least one of Patterns must match
//   - "regex_and_or"   : First must match AND at least one of Second
//   - "regex_and_not"  : all of Patterns must match AND none of NotPatterns
//
// A Rule fires once per scanned file when its pattern set evaluates true;
// the first hit's location is reported as the canonical match site.
package sastrules

import "time"

// Severity uses the same vocabulary as the rest of the project.
// MobSF's "warning" is mapped to "medium" at consumer level.
type Severity string

const (
	SevInfo     Severity = "info"
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

// PatternType enumerates the libsast pattern modes we support.
type PatternType string

const (
	PatRegex       PatternType = "regex"
	PatRegexAnd    PatternType = "regex_and"
	PatRegexOr     PatternType = "regex_or"
	PatRegexAndOr  PatternType = "regex_and_or"
	PatRegexAndNot PatternType = "regex_and_not"
)

// Rule is one SAST rule as it lives in the embedded JSON corpus.
type Rule struct {
	ID          string      `json:"id"`
	Title       string      `json:"title"`
	Severity    string      `json:"severity"`
	PatternType PatternType `json:"pattern_type"`

	Pattern     string   `json:"pattern,omitempty"`
	Patterns    []string `json:"patterns,omitempty"`
	NotPatterns []string `json:"not_patterns,omitempty"`
	First       string   `json:"first,omitempty"`
	Second      []string `json:"second,omitempty"`

	CVSS        float64 `json:"cvss,omitempty"`
	CWE         string  `json:"cwe,omitempty"`
	OWASPMobile string  `json:"owasp_mobile,omitempty"`
	MASVS       string  `json:"masvs,omitempty"`
	Ref         string  `json:"ref,omitempty"`
}

// RuleSet is one named bundle of rules (e.g. "android_security_rules").
type RuleSet struct {
	Name   string `json:"name"`
	Source string `json:"source,omitempty"`
	Rules  []Rule `json:"rules"`
}

// Match is a single rule hit on a file.
type Match struct {
	RuleID    string   `json:"rule_id"`
	RuleSet   string   `json:"rule_set"`
	Title     string   `json:"title"`
	Severity  Severity `json:"severity"`
	File      string   `json:"file"`
	Line      int      `json:"line,omitempty"`
	Column    int      `json:"column,omitempty"`
	Snippet   string   `json:"snippet,omitempty"`
	CVSS      float64  `json:"cvss,omitempty"`
	CWE       string   `json:"cwe,omitempty"`
	OWASP     string   `json:"owasp_mobile,omitempty"`
	MASVS     string   `json:"masvs,omitempty"`
	Reference string   `json:"reference,omitempty"`
}

// Report is the SAST scan output.
type Report struct {
	GeneratedAt  time.Time        `json:"generated_at"`
	Target       string           `json:"target"`
	FilesScanned int              `json:"files_scanned"`
	BytesScanned int64            `json:"bytes_scanned"`
	Matches      []Match          `json:"matches,omitempty"`
	BySeverity   map[Severity]int `json:"by_severity,omitempty"`
	ByRuleSet    map[string]int   `json:"by_ruleset,omitempty"`
	TopRules     []RuleSummary    `json:"top_rules,omitempty"`
	Score        int              `json:"score"`
	Verdict      string           `json:"verdict,omitempty"` // clean | weak | dangerous
}

type RuleSummary struct {
	RuleID   string   `json:"rule_id"`
	Title    string   `json:"title"`
	Severity Severity `json:"severity"`
	Hits     int      `json:"hits"`
}
