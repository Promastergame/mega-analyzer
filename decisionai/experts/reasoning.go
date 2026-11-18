package experts

import (
	"fmt"
	"strings"

	"decisionai/reasoning"
	"decisionai/s1"
)

// Reasoning executes explicitly requested factual entailment. Unrecognised
// tasks still reach the existing mathematical and neural backends.
type Reasoning struct{}

func (Reasoning) Name() string { return "reasoning-proof" }

func (Reasoning) Answer(state any, stateText string, q s1.ExpertQuestion) (s1.ExpertAnswer, bool) {
	explicit := q.Task == s1.TaskReasoning
	if (q.Task != "" && !explicit) || (!explicit && q.Type != s1.TypeNoul) {
		return s1.ExpertAnswer{}, false
	}
	if !explicit {
		for _, option := range q.Options {
			if strings.TrimSpace(option.Text) != "" {
				return s1.ExpertAnswer{}, false
			}
		}
	}
	var queries []reasoning.Atom
	var indices []int
	if q.Type == s1.TypeNoul {
		claim, ok := reasoning.ParseClaim(q.Instr)
		if q.Claim != nil {
			claim, ok = *q.Claim, true
		}
		if !ok {
			return s1.ExpertAnswer{}, false
		}
		if q.Polarity == "negative" {
			claim.Negated = !claim.Negated
		}
		queries = append(queries, claim)
	} else {
		for i, option := range q.Options {
			if option.Key == q.AbstainKey {
				continue
			}
			if claim, ok := reasoning.ParseClaim(option.Text); ok {
				queries, indices = append(queries, claim), append(indices, i)
			}
		}
		if len(queries) == 0 {
			return s1.ExpertAnswer{}, false
		}
		if len(queries) != len(q.Options)-boolInt(q.AbstainKey != "") {
			return reasoningUnknown(q, nil, "unsupported_reasoning_option", "Не все варианты удалось разобрать как проверяемые утверждения."), true
		}
	}
	w := reasoning.New()
	structured, err := w.FromJSON(state)
	if err != nil {
		return reasoningUnknown(q, nil, "invalid_reasoning_facts", "Факты или правила заданы некорректно: "+err.Error()), true
	}
	if !structured {
		text := scopedText(state, stateText)
		queries = w.ReadText(text, queries)
	}
	if !explicit {
		// Legacy callers need no new task field for a complete relation question,
		// but unrelated prose must not activate this narrow factual solver.
		related := false
		for _, step := range w.Steps {
			for _, query := range queries {
				for _, entity := range []string{query.Subject, query.Object} {
					if entity != "" && (entity == step.Claim.Subject || entity == step.Claim.Object) {
						related = true
					}
				}
			}
		}
		if !related {
			return s1.ExpertAnswer{}, false
		}
	}
	w.Solve()
	trace := w.Explain(queries[0])
	if w.Limited {
		return reasoningUnknown(q, trace, "reasoning_budget_exceeded", "Вывод остановлен по лимиту: "+w.LimitReason+". Сократите набор фактов или правил."), true
	}
	if q.Type == s1.TypeNoul {
		switch trace.Status {
		case "supported", "refuted":
			p := 1.0
			if trace.Status == "refuted" {
				p = 0
			}
			a := s1.ExpertAnswer{Probs: []float64{p}, Calibrated: true, Reasoning: trace, Evidence: proofEvidence(trace)}
			return a, true
		case "conflict":
			return reasoningUnknown(q, trace, "conflicting_facts", "Источники одновременно подтверждают и опровергают утверждение."), true
		default:
			return reasoningUnknown(q, trace, "missing_reasoning_facts", "Из приведённых фактов утверждение не следует. Отсутствие доказательства не означает «нет»."), true
		}
	}
	winner := -1
	for i, query := range queries {
		candidate := w.Explain(query)
		if candidate.Status == "conflict" {
			return reasoningUnknown(q, candidate, "conflicting_facts", "Найдено противоречие в фактах для одного из вариантов."), true
		}
		if candidate.Status == "supported" {
			if winner >= 0 {
				trace.Status = "ambiguous"
				return reasoningUnknown(q, trace, "multiple_supported_choices", "Факты подтверждают несколько вариантов. Нужен однозначный вопрос."), true
			}
			winner, trace = indices[i], candidate
		}
	}
	if winner < 0 {
		return reasoningUnknown(q, trace, "missing_reasoning_facts", "Ни один вариант не подтверждён приведёнными фактами."), true
	}
	p := make([]float64, len(q.Options))
	p[winner] = 1
	return s1.ExpertAnswer{Probs: p, Calibrated: true, Reasoning: trace, Evidence: proofEvidence(trace)}, true
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func reasoningUnknown(q s1.ExpertQuestion, trace *reasoning.Trace, reason, detail string) s1.ExpertAnswer {
	a := uncertain(q, reason, detail)
	a.Reasoning = trace
	if trace != nil {
		a.Evidence = append(a.Evidence, proofEvidence(trace)...)
	}
	if q.Type == s1.TypeChoice && q.AbstainKey != "" {
		for i, option := range q.Options {
			a.Probs[i] = 0
			if option.Key == q.AbstainKey {
				a.Probs[i] = 1
			}
		}
	}
	a.Checks = []s1.NextCheck{{ID: "resolve_reasoning_facts", Title: "Уточнить исходные факты", Why: detail, Kind: "evidence"}}
	return a
}

func proofEvidence(trace *reasoning.Trace) []string {
	var evidence []string
	for _, step := range trace.Proof {
		if len(evidence) >= 16 {
			break
		}
		evidence = append(evidence, fmt.Sprintf("Шаг %d: %s · %s", step.ID+1, reasoning.FormatClaim(step.Claim), step.Source))
	}
	return evidence
}
