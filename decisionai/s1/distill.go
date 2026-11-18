package s1

import "strings"

// PlanOption is one answer option as the engine scores it: the hypothesis text
// the backend judges against every state chunk, or Escape for abstain options
// that are resolved without the backend.
type PlanOption struct {
	Key    string `json:"key"`
	Hyp    string `json:"hyp,omitempty"`
	Escape bool   `json:"escape,omitempty"`
}

// QuestionPlan mirrors the engine's per-question scoring plan. It is the unit
// of the distillation dataset (scripts/distill): a student model is trained on
// exactly the (chunk, hypothesis) pairs and aggregation the engine will use.
type QuestionPlan struct {
	ID      string       `json:"id"`
	Type    string       `json:"type"`
	Task    string       `json:"task,omitempty"`
	HasCrit bool         `json:"has_criteria"`
	Options []PlanOption `json:"options"`
	ChunkIndices []int   `json:"chunk_indices,omitempty"`
}

// hypothesisFor returns the backend hypothesis for option o, or escape=true.
func hypothesisFor(q compiled, o Option) (string, bool) {
	if q.Type == TypeNoul && strings.TrimSpace(o.Text) == "" {
		return "", true
	}
	if q.Type == TypeChoice && ((q.AbstainKey != "" && o.Key == q.AbstainKey) || (q.AbstainKey == "" && isEscape(o))) {
		return "", true
	}
	if q.Type != TypeNoul {
		return optionHypothesis(q.Instr, o), false
	}
	return o.Text, false
}

// Plans compiles a request into the chunks and scoring plans the engine would use.
func (e *Engine) Plans(r Request) ([]string, []QuestionPlan, error) {
	state, qs, err := r.compile()
	if err != nil {
		return nil, nil, err
	}
	if err := e.expandSkills(state, &qs); err != nil {
		return nil, nil, err
	}
	chunks, selected, _ := e.contextChunks(state, qs)
	out := make([]QuestionPlan, 0, len(qs))
	for qi, q := range qs {
		qp := QuestionPlan{ID: q.ID, Type: q.Type, Task: q.Task, HasCrit: q.HasCrit}
		qp.ChunkIndices = selected[qi]
		if q.Type == TypeNoul && !q.HasCrit {
			qp.Options = []PlanOption{{Key: "true", Hyp: statement(q.Instr)}, {Key: "false", Escape: true}}
		} else {
			for _, o := range q.Options {
				h, esc := hypothesisFor(q, o)
				qp.Options = append(qp.Options, PlanOption{Key: o.Key, Hyp: h, Escape: esc})
			}
		}
		out = append(out, qp)
	}
	return chunks, out, nil
}
