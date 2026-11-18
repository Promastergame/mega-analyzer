package s1

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"decisionai/vision"
)

// DecideContext first translates images into visible evidence, then uses the
// existing typed decision engine. Text-only requests retain their original path.
func (e *Engine) DecideContext(ctx context.Context, r Request) (Response, error) {
	if len(r.Images) == 0 {
		return e.decideTextContext(ctx, r)
	}
	start := time.Now()
	if err := ctx.Err(); err != nil {
		return Response{}, err
	}
	state, qs, err := r.compile()
	if err != nil {
		return Response{}, err
	}
	if err := vision.Validate(r.Images); err != nil {
		return Response{}, err
	}
	if e.Vision == nil {
		return Response{}, fmt.Errorf("image reader is not configured")
	}
	var prompt strings.Builder
	prompt.WriteString("Describe the supplied images in relation to this state and these questions. Include visible text, positions, and uncertainty.\nState:\n")
	prompt.WriteString(state)
	for _, q := range qs {
		prompt.WriteString("\nQuestion: " + q.Instr)
	}
	description, err := e.Vision.Describe(ctx, prompt.String(), r.Images)
	if err != nil {
		return Response{}, err
	}
	if err := vision.ValidateDescription(description); err != nil {
		return Response{}, err
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(r.State, &obj) != nil || obj == nil {
		obj = map[string]json.RawMessage{"state": r.State}
	}
	if _, exists := obj["image_observation"]; exists {
		return Response{}, fmt.Errorf("state.image_observation is reserved for vision output")
	}
	obj["image_observation"], _ = json.Marshal(description)
	r.State, err = json.Marshal(obj)
	if err != nil {
		return Response{}, err
	}
	r.Images = nil
	// Image-derived evidence is fallible. Do not let deterministic text experts
	// or escalation turn it into an automatic action or cache it as ground truth.
	sub := *e
	sub.Escalate = nil
	resp, err := sub.decideTextContext(ctx, r)
	if err != nil {
		return Response{}, err
	}
	for id, a := range resp.Answers {
		if a.Route == "auto" {
			a.Route = "review"
		}
		a.Evidence = append(a.Evidence, "Image observation: "+description)
		resp.Answers[id] = a
	}
	resp.Warnings = append(resp.Warnings, "Image analysis has limited recognition coverage; verify the visible evidence before acting.")
	resp.Usage.ModelCalls++
	resp.ElapsedMs = float64(time.Since(start).Microseconds()) / 1000
	return resp, nil
}
