package adapter

import (
	"context"
	"fmt"
)

// MockAdapter is an in-memory DeviceAdapter for unit tests. It records applied
// operations and returns programmable state, so modules and the planner can be
// tested without an emulator. Behaviour is controlled by the exported fields.
type MockAdapter struct {
	// State is what ReadState returns. ApplyTestConfig mutates State.Props so a
	// module's Apply→Verify round trip works against the mock.
	State DeviceState
	// EvidenceData is what CollectEvidence returns.
	EvidenceData Evidence

	// Injected failures for negative testing. If set, the matching method
	// returns this error.
	StartErr    error
	BootErr     error
	ReadErr     error
	ApplyErr    error
	EvidenceErr error
	StopErr     error

	// FailProps causes ApplyTestConfig to report these prop keys as failed
	// (transport succeeds, but the individual command "fails").
	FailProps map[string]bool

	// Call counters for assertions.
	Started, Booted, Stopped bool
	ApplyCount               int
}

// NewMockAdapter returns a mock with initialised maps.
func NewMockAdapter() *MockAdapter {
	return &MockAdapter{
		State:        NewDeviceState(),
		EvidenceData: Evidence{Props: map[string]string{}, Files: map[string]bool{}},
	}
}

func (m *MockAdapter) Start(ctx context.Context) error {
	if m.StartErr != nil {
		return m.StartErr
	}
	m.Started = true
	return nil
}

func (m *MockAdapter) WaitForBoot(ctx context.Context) error {
	if m.BootErr != nil {
		return m.BootErr
	}
	m.Booted = true
	return nil
}

func (m *MockAdapter) ReadState(ctx context.Context) (DeviceState, error) {
	if m.ReadErr != nil {
		return DeviceState{}, m.ReadErr
	}
	return m.State, nil
}

func (m *MockAdapter) ApplyTestConfig(ctx context.Context, cfg TestConfig) (ApplyResult, error) {
	m.ApplyCount++
	if m.ApplyErr != nil {
		return ApplyResult{}, m.ApplyErr
	}
	if m.State.Props == nil {
		m.State.Props = map[string]string{}
	}
	var res ApplyResult
	for _, p := range cfg.Props {
		if m.FailProps[p.Key] {
			res.Failed = append(res.Failed, CmdError{Cmd: "setprop " + p.Key, Err: "mock failure"})
			continue
		}
		m.State.Props[p.Key] = p.Value // reflect the write so Verify sees it
		res.Succeeded = append(res.Succeeded, "setprop "+p.Key)
	}
	for _, c := range cfg.Commands {
		res.Succeeded = append(res.Succeeded, c.Cmd)
	}
	return res, nil
}

func (m *MockAdapter) CollectEvidence(ctx context.Context) (Evidence, error) {
	if m.EvidenceErr != nil {
		return Evidence{}, m.EvidenceErr
	}
	m.EvidenceData.Collected = true
	return m.EvidenceData, nil
}

func (m *MockAdapter) Stop(ctx context.Context) error {
	if m.StopErr != nil {
		return m.StopErr
	}
	m.Stopped = true
	return nil
}

// ensure interface compliance
var _ DeviceAdapter = (*MockAdapter)(nil)

// String is a small aid for test failure messages.
func (m *MockAdapter) String() string {
	return fmt.Sprintf("MockAdapter{started=%v booted=%v stopped=%v applies=%d}",
		m.Started, m.Booted, m.Stopped, m.ApplyCount)
}
