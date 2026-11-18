package experts

import (
	"encoding/json"

	"decisionai/games"
	"decisionai/s1"
)

type Game struct{}

func (Game) Name() string { return "game-search" }
func (Game) Answer(state any, _ string, q s1.ExpertQuestion) (s1.ExpertAnswer, bool) {
	if q.Task != s1.TaskGame || q.Type != s1.TypeChoice {
		return s1.ExpertAnswer{}, false
	}
	answer := s1.ExpertAnswer{Probs: make([]float64, len(q.Options)), Calibrated: true}
	abstain := func(reason string) (s1.ExpertAnswer, bool) {
		for i := range answer.Probs {
			answer.Probs[i] = 1
		}
		answer.Abstained = true
		answer.Reason = reason
		return answer, true
	}
	// The game schema is explicit: unrelated numbers or prose never become moves.
	b, err := json.Marshal(state)
	if err != nil {
		return abstain("Invalid game state")
	}
	var s games.State
	if err := json.Unmarshal(b, &s); err != nil {
		return abstain("Expected structured game state")
	}
	d, err := games.Solve(s)
	if err != nil {
		return abstain(err.Error())
	}
	if d.Action == "" {
		return abstain(d.Reason)
	}
	answer.Calibrated = !d.Heuristic
	for i, o := range q.Options {
		if o.Key == d.Action {
			answer.Probs[i] = 1
			answer.Evidence = []string{d.Reason}
			return answer, true
		}
	}
	return abstain("Best legal move " + d.Action + " is absent from the declared choices")
}
