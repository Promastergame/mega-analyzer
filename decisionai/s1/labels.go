package s1

import "fmt"

// ValidateLabelled checks a complete training/evaluation record without running
// inference. Dynamic skill questions use this engine's registry.
func (e *Engine) ValidateLabelled(l Labelled) error {
	state, questions, err := l.Request.compile()
	if err != nil {
		return err
	}
	if err := e.expandSkills(state, &questions); err != nil {
		return err
	}
	if len(l.Labels) != len(questions) {
		return fmt.Errorf("labels must cover exactly the %d declared questions", len(questions))
	}
	for _, q := range questions {
		raw, ok := l.Labels[q.ID]
		if !ok {
			return fmt.Errorf("missing label for question %q", q.ID)
		}
		a := Answer{Type: q.Type}
		for _, option := range q.Options {
			a.keys = append(a.keys, option.Key)
		}
		if _, err := targetFor(a, raw); err != nil {
			return fmt.Errorf("%s: %w", q.ID, err)
		}
	}
	return nil
}
