package s1

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
)

// Multi-step skill plans: "проанализируй продажи и построй график" needs
// data-analysis and then inline-charts. The request is split at sequence
// connectors, every clause is routed on its own, and a plan is returned
// only when at least two clauses land confidently on different skills.

// PlanMinP is the minimum clause-level probability of a plan step;
// PlanMinLex the minimum lexical score, so a step is never a pure guess.
var PlanMinP = 0.5
var PlanMinLex = 2.0

// PlanMinRunnerUp: a clause runner-up may become a step when the winner is
// already planned, if it is still clearly supported.
var PlanMinRunnerUp = 0.15

var clauseSeps = []string{
	", а потом ", " а потом ", ", а затем ", " а затем ", ", потом ", " потом ", ", затем ", " затем ",
	" и потом ", " и затем ", ", после этого ", " после этого ", ", и ", " и ", ", а ", ", then ", " then ",
	" and then ", ", and ", " and ", "; ", " + ", ". ", " -> ", " → ",
}

func splitClauses(text string) []string {
	t := " " + strings.Join(strings.Fields(text), " ") + " "
	low := strings.ToLower(t)
	var cuts [][2]int
	for i := 0; i < len(low); {
		hit := 0
		for _, s := range clauseSeps {
			if strings.HasPrefix(low[i:], s) && len(s) > hit {
				hit = len(s)
			}
		}
		if hit > 0 {
			cuts = append(cuts, [2]int{i, i + hit})
			i += hit
			continue
		}
		i++
	}
	var out []string
	prev := 0
	for _, c := range append(cuts, [2]int{len(t), len(t)}) {
		seg := strings.TrimSpace(t[prev:c[0]])
		if len(strings.Fields(seg)) >= 2 {
			out = append(out, seg)
		} else if seg != "" && len(out) > 0 {
			out[len(out)-1] += " " + seg
		}
		prev = c[1]
	}
	return out
}

func (e *Engine) skillPlan(ctx context.Context, state string, q compiled, main Answer) []PlanStep {
	clauses := splitClauses(state)
	if len(clauses) < 2 || len(clauses) > 6 {
		return nil
	}
	sub := *e
	sub.NoPlan = true
	var steps []PlanStep
	seen := map[string]bool{}
	for _, c := range clauses {
		body, _ := json.Marshal(map[string]any{"state": c, "questions": map[string]any{
			"s": map[string]any{"type": TypeChoice, "task": TaskSkillRouting, "instructions": q.Instr}}})
		var rq Request
		if json.Unmarshal(body, &rq) != nil {
			return nil
		}
		resp, err := sub.DecideContext(ctx, rq)
		if err != nil {
			return nil
		}
		a := resp.Answers["s"]
		if a.Abstained || a.Choice == "" || a.Choice == SkillOtherKey {
			continue
		}
		// best unseen skill for this clause: the winner, or the runner-up when the
		// winner is already a step ("выжимка созвона и письмо с итогами")
		ps := append(Probs(nil), a.Probabilities...)
		sort.SliceStable(ps, func(i, j int) bool { return ps[i].P > ps[j].P })
		pick, p := "", 0.0
		for rank, kv := range ps {
			if rank > 1 || kv.Key == SkillOtherKey {
				break
			}
			if seen[kv.Key] {
				continue
			}
			minP := PlanMinP
			if rank == 1 {
				minP = PlanMinRunnerUp
			}
			lex, _ := e.Skills.LexScores(c, []string{kv.Key})
			if kv.P >= minP && lex[0] >= PlanMinLex {
				pick, p = kv.Key, kv.P
			}
			break
		}
		if pick == "" {
			continue
		}
		seen[pick] = true
		st := PlanStep{Skill: pick, Clause: c, P: round4(p)}
		if path, ok := e.Skills.PathOf(pick); ok {
			st.File = path
		}
		steps = append(steps, st)
	}
	if len(steps) < 2 {
		return nil
	}
	return steps
}
