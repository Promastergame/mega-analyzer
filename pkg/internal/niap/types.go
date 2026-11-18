package niap

// Rule match statuses. A rule that cannot be checked automatically is
// "manual_review", NOT "failed" — pretending prose rules failed is how
// every app ends up "non-compliant".
const (
	StatusPassed = "passed"
	StatusFailed = "failed"
	StatusManual = "manual_review"
)

// Rule polarity values.
const (
	PolarityPositive = "positive" // match => passed (expected good pattern)
	PolarityNegative = "negative" // match => failed (anti-pattern detected)
)

// Rule is a single NIAP compliance rule.
//
// Matching semantics:
//   - Every pattern inside one choice group must match somewhere in the
//     target (AND within a group).
//   - choice_type "or" (default): any group matching is enough.
//   - choice_type "and"/"all": every group must match.
//   - Patterns are Go regexes evaluated per line; a line that also
//     matches any "exclude" regex is ignored.
//   - polarity "negative" inverts the outcome: a match means FAIL
//     (anti-pattern found), no match means PASS.
//   - manual: true marks the rule as not automatable (manual_review).
type Rule struct {
	ID         string     `json:"id"`
	Type       string     `json:"type"` // "code" or "manifest"
	ChoiceType string     `json:"choice_type"`
	Message    string     `json:"message"`
	Selection  string     `json:"selection,omitempty"`
	Choice     [][]string `json:"choice"`
	Exclude    []string   `json:"exclude,omitempty"`
	Else       string     `json:"else,omitempty"`
	Class      string     `json:"class,omitempty"`
	Polarity   string     `json:"polarity,omitempty"` // default "positive"
	Severity   int        `json:"severity,omitempty"` // score weight when failed; default 4
	Manual     bool       `json:"manual,omitempty"`   // rule requires manual review
}

// Match represents a rule evaluation result.
type Match struct {
	RuleID   string `json:"rule_id"`
	Message  string `json:"message"`
	Type     string `json:"type"`
	Matched  bool   `json:"matched"`
	Status   string `json:"status"` // passed | failed | manual_review
	Evidence string `json:"evidence,omitempty"`
}

// Report holds the NIAP compliance scan result.
type Report struct {
	GeneratedAt      string  `json:"generated_at"`
	Target           string  `json:"target"`
	TotalRules       int     `json:"total_rules"`
	Passed           int     `json:"passed"`
	Failed           int     `json:"failed"`
	ManualReview     int     `json:"manual_review"`
	CodeFilesScanned int     `json:"code_files_scanned"`
	CodeFilesSkipped int     `json:"code_files_skipped"`
	UnsupportedCode  int     `json:"unsupported_code"`
	Matches          []Match `json:"matches"`
	Score            int     `json:"score"`
	Verdict          string  `json:"verdict"`
}
