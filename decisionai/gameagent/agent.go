// Package gameagent connects observed game state to bounded MCP actions.
package gameagent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"decisionai/games"
	"decisionai/mcpclient"
	"decisionai/vision"
)

type Tools interface {
	CheckCall(mcpclient.Call) error
	CallTool(context.Context, mcpclient.Call) (mcpclient.Result, error)
}
type Config struct {
	Server            mcpclient.Config          `json:"server"`
	Observe           mcpclient.Call            `json:"observe"`
	Actions           map[string]mcpclient.Call `json:"actions"`
	MoveTool          string                    `json:"move_tool,omitempty"`
	Game              string                    `json:"game"`
	Player            string                    `json:"player,omitempty"`
	MaxSteps          int                       `json:"max_steps,omitempty"`
	ImageLayout       *vision.Layout            `json:"image_layout,omitempty"`
	MinStepIntervalMS int                       `json:"min_step_interval_ms,omitempty"`
	ObservationMode   string                    `json:"observation_mode,omitempty"`
}
type Step struct {
	Source   string         `json:"source"`
	State    games.State    `json:"state"`
	Decision games.Decision `json:"decision"`
	Tool     string         `json:"tool,omitempty"`
}
type Report struct {
	Status  string `json:"status"`
	Steps   []Step `json:"steps"`
	Actions int    `json:"actions"`
}

func Run(ctx context.Context, tools Tools, v vision.Describer, c Config) (Report, error) {
	r := Report{Status: "stopped", Steps: []Step{}}
	if c.ObservationMode == "" {
		c.ObservationMode = "image"
	}
	if c.ObservationMode != "image" && c.ObservationMode != "structured" {
		return r, fmt.Errorf("observation_mode must be image or structured")
	}
	if !games.Supported(c.Game) {
		return r, fmt.Errorf("unsupported game %q", c.Game)
	}
	if c.Player != "" {
		valid := (c.Game == "tic_tac_toe" && (c.Player == "X" || c.Player == "O")) || (c.Game == "russian_checkers" && (c.Player == "white" || c.Player == "black"))
		if !valid {
			return r, fmt.Errorf("player must be X/O for tic_tac_toe or white/black for russian_checkers")
		}
	}
	if c.MaxSteps == 0 {
		c.MaxSteps = 32
	}
	if c.MaxSteps < 1 || c.MaxSteps > 256 {
		return r, fmt.Errorf("max_steps must be 1..256")
	}
	if c.MinStepIntervalMS == 0 {
		c.MinStepIntervalMS = 500
	}
	if c.MinStepIntervalMS < 1 || c.MinStepIntervalMS > 60000 {
		return r, fmt.Errorf("min_step_interval_ms must be 1..60000")
	}
	if err := tools.CheckCall(c.Observe); err != nil {
		return r, err
	}
	if (len(c.Actions) == 0) == (c.MoveTool == "") {
		return r, fmt.Errorf("configure either actions or move_tool")
	}
	for _, call := range c.Actions {
		if err := tools.CheckCall(call); err != nil {
			return r, err
		}
	}
	seen := map[string]bool{}
	var lastAction time.Time
	for {
		if !lastAction.IsZero() {
			wait := time.Until(lastAction.Add(time.Duration(c.MinStepIntervalMS) * time.Millisecond))
			if wait > 0 {
				timer := time.NewTimer(wait)
				select {
				case <-timer.C:
				case <-ctx.Done():
					timer.Stop()
					return r, ctx.Err()
				}
			}
		}
		if err := ctx.Err(); err != nil {
			return r, err
		}
		observation, err := tools.CallTool(ctx, c.Observe)
		if err != nil {
			return r, fmt.Errorf("observe: %w", err)
		}
		var s games.State
		if c.ObservationMode == "image" {
			s, err = decodeImageObservation(ctx, observation, v, c.Game, c.ImageLayout)
		} else {
			s, err = decodeObservation(ctx, observation, v, c.Game)
		}
		if err != nil {
			return r, err
		}
		if s.Game != c.Game {
			return r, fmt.Errorf("observed game %q does not match configured %q", s.Game, c.Game)
		}
		d, err := games.SolveContext(ctx, s)
		if err != nil {
			return r, fmt.Errorf("invalid observed state: %w", err)
		}
		r.Steps = append(r.Steps, Step{State: s, Decision: d, Source: c.ObservationMode})
		if d.Terminal {
			r.Status = "terminal"
			return r, nil
		}
		if d.Action == "" {
			r.Status = d.Outcome
			return r, nil
		}
		if c.Player != "" {
			next := s.Player
			board := strings.Join(s.Board, "")
			if s.Game == "tic_tac_toe" {
				next = "X"
				if strings.Count(board, "X") > strings.Count(board, "O") {
					next = "O"
				}
			}
			if next != c.Player {
				r.Status = "waiting_for_opponent"
				return r, nil
			}
		}
		key, _ := json.Marshal(s)
		if seen[string(key)] {
			r.Status = "no_progress"
			return r, nil
		}
		seen[string(key)] = true
		if r.Actions >= c.MaxSteps {
			r.Status = "step_limit"
			return r, nil
		}
		call, ok := c.Actions[d.Action]
		if c.MoveTool != "" {
			call = mcpclient.Call{Name: c.MoveTool, Arguments: map[string]any{"decision": d}}
			ok = true
		}
		if !ok {
			return r, fmt.Errorf("no permitted MCP mapping for %q", d.Action)
		}
		if err := tools.CheckCall(call); err != nil {
			return r, fmt.Errorf("invalid move tool arguments: %w", err)
		}
		r.Steps[len(r.Steps)-1].Tool = call.Name
		// Never replay a failed or timed-out action; its actual outcome is unknown.
		if _, err := tools.CallTool(ctx, call); err != nil {
			return r, fmt.Errorf("action %s failed (outcome unknown, no retry): %w", d.Action, err)
		}
		r.Actions++
		lastAction = time.Now()
	}
}

// Image mode never consults structuredContent or JSON text, even on failure.
func decodeImageObservation(ctx context.Context, r mcpclient.Result, v vision.Describer, game string, layout *vision.Layout) (games.State, error) {
	if r.IsError {
		return games.State{}, fmt.Errorf("observation tool reported isError")
	}
	images := r.Images()
	if len(images) == 0 {
		return games.State{}, fmt.Errorf("image observation requires a screenshot; structured state is disabled")
	}
	for i := range images {
		images[i].Layout = layout
	}
	reader, ok := v.(interface {
		ReadGame(context.Context, string, []vision.Image) (games.State, error)
	})
	if !ok {
		return games.State{}, fmt.Errorf("image observation requires a game image reader")
	}
	return reader.ReadGame(ctx, game, images)
}

func decodeObservation(ctx context.Context, r mcpclient.Result, v vision.Describer, game string) (games.State, error) {
	if r.IsError {
		return games.State{}, fmt.Errorf("observation tool reported isError")
	}
	if b := bytes.TrimSpace(r.Structured); len(b) > 0 && string(b) != "null" {
		return decodeState(b)
	}
	for _, c := range r.Content {
		if c.Type == "text" && strings.HasPrefix(strings.TrimSpace(c.Text), "{") {
			return decodeState([]byte(c.Text))
		}
	}
	images := r.Images()
	if len(images) == 0 {
		return games.State{}, fmt.Errorf("observation needs structuredContent, JSON text, or image content")
	}
	if v == nil {
		return games.State{}, fmt.Errorf("screenshot observation requires an image reader")
	}
	if err := vision.Validate(images); err != nil {
		return games.State{}, err
	}
	if local, ok := v.(interface {
		ReadGame(context.Context, string, []vision.Image) (games.State, error)
	}); ok {
		return local.ReadGame(ctx, game, images)
	}
	prompt := `Read the current game board. Return ONLY a JSON object, no markdown. For tic_tac_toe: {"game":"tic_tac_toe","board":["X..",".O.","..."],"player":"X"}, three rows of X, O, .; player is the side to move, X starts. For maze: {"game":"maze","grid":["S..",".#G"]}, rectangular rows, S player, G goal, # wall, X hazard, . empty, * player at goal. The configured game is ` + game + `. If any cell is unreadable or the game is different, return {"error":"uncertain board"}. Do not guess.`
	text, err := v.Describe(ctx, prompt, images)
	if err != nil {
		return games.State{}, err
	}
	return decodeState([]byte(text))
}

func decodeState(b []byte) (games.State, error) {
	if len(b) > 64<<10 {
		return games.State{}, fmt.Errorf("observed state exceeds 64 KiB")
	}
	var s games.State
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&s); err != nil {
		return s, fmt.Errorf("invalid observation JSON: %w", err)
	}
	if d.More() {
		return s, fmt.Errorf("trailing observation data")
	}
	if s.Game == "" {
		return s, fmt.Errorf("observation is missing game")
	}
	return s, nil
}
