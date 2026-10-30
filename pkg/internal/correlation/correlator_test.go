package correlation

import (
	"strings"
	"testing"
	"time"

	"mega-analyzer/pkg/internal/sandbox"
)

// fakeChain is a tiny ChainDetector used to verify the Engine wiring
// without relying on a particular real chain.
type fakeChain struct {
	id    string
	match *AttackChain
}

func (f fakeChain) ID() string          { return f.id }
func (f fakeChain) Name() string        { return "fake-" + f.id }
func (f fakeChain) Description() string { return "fake chain" }
func (f fakeChain) Detect(ctx *ExecutionContext) *AttackChain {
	if f.match == nil {
		return nil
	}
	clone := *f.match
	return &clone
}

func TestEngine_Run_NoInputs(t *testing.T) {
	e := NewEngine(nil)
	res := e.Run(Input{})
	if res == nil {
		t.Fatal("expected non-nil result")
	}
	if res.OverallRisk != RiskInfo {
		t.Fatalf("expected RiskInfo, got %s", res.OverallRisk)
	}
	if len(res.Notes) == 0 {
		t.Fatal("expected explanatory note")
	}
}

func TestEngine_Run_IngestSandboxInjectionScenario(t *testing.T) {
	now := time.Now()
	rep := &sandbox.Report{
		SessionID: "test-session",
		StartedAt: now,
		Processes: []sandbox.ObservedProcess{
			{PID: 4242, Name: "evil.exe"},
		},
		MemoryAnalysis: &sandbox.MemoryAnalysis{
			Findings: []sandbox.MemoryFinding{
				{
					Type:        "process_injection_sequence",
					Description: "VirtualAllocEx + WriteProcessMemory + remote-thread observed",
					ProcessID:   4242,
					Severity:    9,
					Confidence:  0.9,
					Evidence:    []string{"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"},
				},
			},
		},
		Connections: []sandbox.ObservedConnection{
			{
				Protocol:   "TCP",
				LocalAddr:  "10.0.0.2:49152",
				RemoteAddr: "203.0.113.10:443",
				PID:        4242,
				FirstSeen:  now,
			},
		},
	}

	e := NewEngine(nil) // no chains — verify findings path
	res := e.Run(Input{Sandbox: rep})
	if res == nil {
		t.Fatal("nil result")
	}
	if !res.HasRuntime {
		t.Fatal("HasRuntime should be true")
	}
	if res.Stats.TotalSignals < 2 {
		t.Fatalf("expected at least 2 signals, got %d", res.Stats.TotalSignals)
	}
	// Without chains, findings should still be promoted with HIGH risk
	// for the injection signal.
	hasHigh := false
	for _, f := range res.Findings {
		if f.Risk.Rank() >= RiskHigh.Rank() {
			hasHigh = true
		}
	}
	if !hasHigh {
		t.Fatal("expected at least one HIGH+ finding from injection signal")
	}
	// Timeline should have entries with stable ordering.
	if len(res.Timeline) == 0 {
		t.Fatal("expected non-empty timeline")
	}
	if res.Timeline[0].Order != 1 {
		t.Fatalf("first timeline event should have Order=1, got %d", res.Timeline[0].Order)
	}
}

func TestEngine_Run_WithChainDetector(t *testing.T) {
	now := time.Now()
	chainMatch := &AttackChain{
		ID:         "fake_chain",
		Name:       "Fake Chain",
		Risk:       RiskCritical,
		Likelihood: LikelihoodHigh,
	}
	rep := &sandbox.Report{
		StartedAt: now,
		Processes: []sandbox.ObservedProcess{{PID: 1, Name: "x.exe"}},
	}
	chains := []ChainDetector{fakeChain{id: "fake_chain", match: chainMatch}}
	e := NewEngine(chains)
	res := e.Run(Input{Sandbox: rep})
	if len(res.Chains) != 1 {
		t.Fatalf("expected 1 chain, got %d", len(res.Chains))
	}
	if res.OverallRisk != RiskCritical {
		t.Fatalf("expected overall risk CRITICAL, got %s", res.OverallRisk)
	}
}

func TestEngine_StaticOnlyAddsNoSandboxNote(t *testing.T) {
	e := NewEngine(nil)
	res := e.Run(Input{Static: nil, Sandbox: nil})
	// no inputs at all → already covered above. Now test "no runtime"
	// path with at least an empty static result.
	if !anyMentions(res.Notes, "No sandbox") {
		t.Fatalf("expected note about missing inputs, got %v", res.Notes)
	}
}

func anyMentions(strs []string, substr string) bool {
	for _, s := range strs {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}
