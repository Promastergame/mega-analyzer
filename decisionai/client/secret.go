package client

import (
	"context"
	"fmt"
)

// SecretFinding is one result of Mega-Analyzer's secrets scanner, already triaged by it.
// DecisionAI does not scan anything: it reads these verdicts and answers "false positive?"
// and "how severe?" with probabilities and a route. Fill it from secrets.ProviderFinding,
// secrets.VerifyStructure, secrets.Triage and the taint engine's sink.
type SecretFinding struct {
	RuleID      string  // ProviderFinding.RuleID, e.g. "secret/stripe-key"
	Provider    string  // ProviderFinding.Provider
	File        string  // where it was found
	Line        int     // ProviderFinding.Line
	Masked      string  // ProviderFinding.MaskedValue (never send the raw value)
	Severity    string  // info | low | medium | high | critical (scanner's own)
	Confidence  float64 // ProviderFinding.Confidence
	Verified    bool    // Verification.Verified
	Placeholder bool    // Verification.Placeholder
	Expired     bool    // Verification.Expired
	Validation  string  // Verification.Detail / ProviderFinding.Validation
	Verdict     string  // TriageResult.Verdict: placeholder | expired-looking | real-looking | unclear
	Junk        bool    // value judge (llmkeys) said "not a secret"
	Sink        string  // taint engine: log | network | file | ipc | none | "" (unknown)
	Library     *bool   // inside third-party code
}

// State returns the request state the finding-rule expert reads.
func (f SecretFinding) State() map[string]any {
	s := map[string]any{"rule_id": f.RuleID, "verified": f.Verified, "placeholder": f.Placeholder, "expired": f.Expired, "junk": f.Junk}
	put := func(k, v string) {
		if v != "" {
			s[k] = v
		}
	}
	put("provider", f.Provider)
	put("file", f.File)
	put("masked_value", f.Masked)
	put("severity", f.Severity)
	put("validation", f.Validation)
	put("verdict", f.Verdict)
	put("sink", f.Sink)
	if f.Line > 0 {
		s["line"] = f.Line
	}
	if f.Confidence > 0 {
		s["confidence"] = f.Confidence
	}
	if f.Library != nil {
		s["library"] = *f.Library
	}
	return s
}

// SecretQuestions are the standard questions about one secrets finding.
func SecretQuestions() map[string]Question {
	return map[string]Question{
		"is_false_positive": ForTask("false_positive", Noul("Это ложное срабатывание?",
			"Значение не секрет, заглушка или тестовый пример", "Значение похоже на реальный секрет")),
		"severity": ForTask("severity", Score("Насколько серьёзна находка?",
			Opt("0", "Информационная"), Opt("1", "Низкая"), Opt("2", "Средняя"), Opt("3", "Высокая"), Opt("4", "Критическая"))),
	}
}

// SecretVerdict is the typed result for one finding.
type SecretVerdict struct {
	FalsePositive, Severity Answer
	// Suppress is true only when "false positive" was answered auto with P >= 0.9.
	// Report when false: the finding stays in the report, nothing is silently dropped.
	Suppress bool
	// Escalate is true when the finding is real (auto, P(fp) <= 0.1) and severity is high or critical.
	Escalate bool
	Reasons  []string
}

// DecideSecret asks the secret questions for one finding.
func (c *Client) DecideSecret(ctx context.Context, f SecretFinding) (SecretVerdict, error) {
	resp, err := c.Decide(ctx, Request{State: f.State(), Questions: SecretQuestions()})
	if err != nil {
		return SecretVerdict{}, err
	}
	v := SecretVerdict{FalsePositive: resp.Answers["is_false_positive"], Severity: resp.Answers["severity"]}
	fp := v.FalsePositive
	switch {
	case fp.Route == "auto" && fp.Noul >= 0.9:
		v.Suppress = true
	case fp.Route == "auto" && fp.Noul <= 0.1 && v.Severity.Score >= 2.5:
		v.Escalate = true
	default:
		v.Reasons = append(v.Reasons, fmt.Sprintf("is_false_positive: route %s, p=%.2f", fp.Route, fp.Noul))
	}
	return v, nil
}
