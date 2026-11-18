package s1

import "decisionai/reasoning"

func requiresReasoningProof(q compiled) bool {
	if q.Task != TaskReasoning {
		return false
	}
	if q.Claim != nil {
		return true
	}
	if q.Type == TypeNoul {
		_, ok := reasoning.ParseClaim(q.Instr)
		return ok
	}
	for _, option := range q.Options {
		if option.Key == q.AbstainKey {
			continue
		}
		if _, ok := reasoning.ParseClaim(option.Text); ok {
			return true
		}
	}
	return false
}

func unavailableReasoningAnswer(q compiled) Answer {
	a := Answer{Type: q.Type, Source: "reasoning-proof", Abstained: true, Reason: "reasoning_expert_unavailable", Route: "human",
		Evidence: []string{"Локальный модуль вывода по фактам отключён или недоступен."}}
	if q.Type == TypeNoul {
		value := .5
		a.Noul = &value
	} else {
		for _, option := range q.Options {
			p := 1.0 / float64(len(q.Options))
			if q.AbstainKey != "" {
				p = 0
				if option.Key == q.AbstainKey {
					p = 1
					a.Choice = option.Key
				}
			}
			a.Probabilities = append(a.Probabilities, KV{Key: option.Key, P: p})
		}
	}
	return a
}
