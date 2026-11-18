package rules

import (
	"strconv"
	"strings"
)

type EvidenceSource struct {
	File    string `json:"file,omitempty"`
	Line    int    `json:"line,omitempty"`
	Class   string `json:"class,omitempty"`
	Method  string `json:"method,omitempty"`
	Snippet string `json:"snippet,omitempty"`
}

type ConditionEvidence struct {
	Type     string         `json:"type"`
	Expected string         `json:"expected"`
	Observed string         `json:"observed,omitempty"`
	Negated  bool           `json:"negated,omitempty"`
	Source   EvidenceSource `json:"source"`
}

func onlyPermissionEvidence(items []ConditionEvidence) bool {
	if len(items) == 0 {
		return false
	}
	for _, item := range items {
		if item.Type != "permission" || item.Negated {
			return false
		}
	}
	return true
}

func contextValues(ctx *ConditionContext, kind string) []string {
	switch kind {
	case "permission":
		return ctx.Permissions
	case "api_call":
		return ctx.APICalls
	case "pattern":
		return ctx.Patterns
	case "string":
		return ctx.Strings
	case "class":
		return ctx.Classes
	case "method":
		return ctx.Methods
	}
	return nil
}

// This runs only after a rule matches. It records the actual input values
// that satisfied it, including members of a composite, in stable order.
func (e *Engine) ruleEvidenceLocked(rule *Rule, ctx *ConditionContext, seen map[string]bool) []ConditionEvidence {
	if seen[rule.ID] {
		return nil
	}
	seen[rule.ID] = true
	var out []ConditionEvidence
	for _, cond := range rule.Conditions {
		if !e.EvaluateCondition(cond, ctx) {
			continue
		}
		if cond.Operator == "not" {
			out = append(out, ConditionEvidence{Type: cond.Type, Expected: cond.Value, Negated: true})
			continue
		}
		if cond.Type == "combo" {
			for _, value := range cond.Values {
				for _, kind := range []string{"permission", "api_call", "pattern", "string", "class", "method"} {
					if witness, ok := conditionWitness(ctx, kind, value, cond.Exact, cond.MatchMode); ok {
						out = append(out, witness)
						break
					}
				}
			}
		} else if witness, ok := conditionWitness(ctx, cond.Type, cond.Value, cond.Exact, cond.MatchMode); ok {
			out = append(out, witness)
		}
	}
	for _, id := range rule.Requires {
		if member := e.ruleByID[id]; member != nil {
			out = append(out, e.ruleEvidenceLocked(member, ctx, seen)...)
		}
	}
	// Two conditions can be satisfied by the same call site ("Debug.
	// isDebuggerConnected" and "android.os.Debug" both match one invoke).
	// Rendering both witnesses double-counts a single fact in the report.
	// Deduplicate on the cited evidence identity; distinct call sites survive.
	deduped := out[:0]
	seenWitness := make(map[string]struct{}, len(out))
	for _, w := range out {
		key := w.Type + "|" + w.Expected + "|" + w.Observed + "|" + w.Source.File + "|" + strconv.Itoa(w.Source.Line)
		if _, dup := seenWitness[key]; dup {
			continue
		}
		seenWitness[key] = struct{}{}
		deduped = append(deduped, w)
	}
	return deduped
}

func conditionWitness(ctx *ConditionContext, kind, value string, exact bool, mode string) (ConditionEvidence, bool) {
	w := ConditionEvidence{Type: kind, Expected: value}
	if kind == "fact" && ctx.Facts[value] {
		w.Observed, w.Source = value, ctx.Sources[kind][value]
		return w, true
	}
	items := contextValues(ctx, kind)
	// The witness must be the item that satisfied the condition. A looser
	// (case-insensitive substring) search reported unrelated snippets, e.g. a
	// SmtpTransport constructor as the "Socket" witness.
	for _, item := range items {
		if exact && item == value || !exact && containsCondition([]string{item}, value, mode) {
			w.Observed, w.Source = item, ctx.Sources[kind][item]
			return w, true
		}
	}
	want := strings.ToLower(value)
	for _, item := range items {
		if exact && strings.EqualFold(item, value) || !exact && containsCondition([]string{strings.ToLower(item)}, want, mode) {
			w.Observed, w.Source = item, ctx.Sources[kind][item]
			return w, true
		}
	}
	return w, false
}
