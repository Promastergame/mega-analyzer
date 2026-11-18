package semai

import (
	"fmt"
	"math"

	"decisionai/gnn"
)

// Comparison of two places: «на сколько в коробке больше, чем в вазе?», «больше ли в коробке,
// чем в вазе?». Earlier the engine answered about the change of the first place only.

func init() {
	notPlace["начале"] = true
	notPlace["самом"] = true
}

func hasThan(question string) bool {
	for _, t := range tokens(question) {
		if t == "чем" {
			return true
		}
	}
	return false
}

// compareAnswer compares the end values of two places: a is the place before «чем», b after it.
func compareAnswer(m *gnn.Model, clauses []EventClause, parts []EventTarget, ans *FactAnswer, kind string, post []postOp) *FactAnswer {
	var tots []EventTotal
	conf := 1.0
	for _, t := range parts {
		et, ok := entityTotal(m, clauses, t)
		if !ok {
			ans.Answer = "unknown"
			ans.Confidence = 0.5
			ans.Reasoning = append(ans.Reasoning, "Сколько было вначале "+et.Target+" — в условии не сказано, поэтому сравнить нельзя.")
			return ans
		}
		conf *= et.ScenarioP
		tots = append(tots, et)
	}
	a, b := *tots[0].End, *tots[1].End
	first := tots[0]
	first.Others = tots[1:]
	ans.Total = &first
	cmp := fmt.Sprintf("Сравниваем: %s (%s) и %s (%s)", trimNum(a), tots[0].Target, trimNum(b), tots[1].Target)
	ans.Reasoning = append(ans.Reasoning, cmp)
	switch kind {
	case "diff", "count":
		d := math.Abs(a - b)
		ans.Reasoning = append(ans.Reasoning, fmt.Sprintf("Разница: |%s − %s| = %s", trimNum(a), trimNum(b), trimNum(d)))
		ans.Answer = trimNum(applyPost(d, post, &ans.Reasoning))
		ans.Who = []string{ans.Answer}
	default:
		ok := false
		switch kind {
		case "more":
			ok = a > b
		case "less":
			ok = a < b
		case "same":
			ok = a == b
		case "changed":
			ok = a != b
		}
		ans.Answer = "no"
		if ok {
			ans.Answer = "yes"
		}
	}
	ans.Confidence = math.Round(math.Max(conf, 0.5)*1000) / 1000
	return ans
}
