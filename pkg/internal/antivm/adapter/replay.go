package adapter

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
)

// ReplayAdapter replays a previously captured DeviceState instead of talking to
// a real device. It is used for regression testing: capture an after.json from
// a real run, then re-verify profiles against it offline. Writes are recorded
// but do not mutate the replayed state, so verification reflects exactly what
// the captured device reported.
type ReplayAdapter struct {
	state    DeviceState
	evidence Evidence
	// Applied records the configs that were "applied" during replay.
	Applied []TestConfig
}

var _ DeviceAdapter = (*ReplayAdapter)(nil)

// NewReplayAdapter builds a replay adapter from an in-memory state.
func NewReplayAdapter(state DeviceState) *ReplayAdapter {
	return &ReplayAdapter{state: state}
}

// LoadReplay reads a DeviceState from a JSON file (e.g. a session's after.json).
func LoadReplay(path string) (*ReplayAdapter, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read replay state %s: %w", path, err)
	}
	var st DeviceState
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("parse replay state %s: %w", path, err)
	}
	return &ReplayAdapter{state: st}, nil
}

func (r *ReplayAdapter) Start(ctx context.Context) error       { return nil }
func (r *ReplayAdapter) WaitForBoot(ctx context.Context) error { return nil }
func (r *ReplayAdapter) Stop(ctx context.Context) error        { return nil }

func (r *ReplayAdapter) ReadState(ctx context.Context) (DeviceState, error) {
	return r.state, nil
}

// ApplyTestConfig records the config but does not alter replayed state — the
// point of replay is to verify against captured reality, not to simulate writes.
func (r *ReplayAdapter) ApplyTestConfig(ctx context.Context, cfg TestConfig) (ApplyResult, error) {
	r.Applied = append(r.Applied, cfg)
	var res ApplyResult
	for _, p := range cfg.Props {
		res.Succeeded = append(res.Succeeded, "setprop "+p.Key)
	}
	for _, c := range cfg.Commands {
		res.Succeeded = append(res.Succeeded, c.Cmd)
	}
	return res, nil
}

func (r *ReplayAdapter) CollectEvidence(ctx context.Context) (Evidence, error) {
	return r.evidence, nil
}

// SetEvidence attaches evidence to be returned by CollectEvidence.
func (r *ReplayAdapter) SetEvidence(ev Evidence) { r.evidence = ev }
