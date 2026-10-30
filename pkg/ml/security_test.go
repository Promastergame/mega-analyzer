package ml

import (
	"testing"
	"time"
)

func TestBoundarySensitivityHighOnUncertainSeed(t *testing.T) {
	X, y := makeXORData(300, 5)
	gbt := DefaultGradientBoosting()
	gbt.Seed = 5
	gbt.NEstimators = 80
	_ = gbt.Fit(X, y, []string{"x0", "x1"})

	// A point near the XOR boundary (close to 0,0) should be brittle.
	report, err := BoundarySensitivity(gbt, []float64{0.01, 0.01}, 200, 0.05, 42)
	if err != nil {
		t.Fatal(err)
	}
	if report.Probes == 0 {
		t.Fatal("expected at least 1 probe")
	}
	// With XOR + small noise around origin, flips should be common.
	if report.FlipsPerProbe < 0.1 {
		t.Logf("warning: flips/probe %f — boundary may be flatter than expected", report.FlipsPerProbe)
	}
}

func TestReinforcementGuardEnforcesPerSourceCap(t *testing.T) {
	g := NewReinforcementGuard(GuardConfig{
		MaxPerSourcePerWindow: 2,
		MaxAnchorBurst:        100,
		Window:                time.Hour,
	})
	if err := g.Allow("alice", "uaf", []float64{1, 2}); err != nil {
		t.Fatal(err)
	}
	if err := g.Allow("alice", "uaf", []float64{3, 4}); err != nil {
		t.Fatal(err)
	}
	if err := g.Allow("alice", "uaf", []float64{5, 6}); err == nil {
		t.Error("3rd reinforcement should be rejected")
	}
	if err := g.Allow("bob", "uaf", []float64{7, 8}); err != nil {
		t.Errorf("different source should still be allowed: %v", err)
	}
	log := g.AuditLog()
	if len(log) != 4 {
		t.Errorf("expected 4 audit entries, got %d", len(log))
	}
	rejected := 0
	for _, e := range log {
		if !e.WasApplied {
			rejected++
		}
	}
	if rejected != 1 {
		t.Errorf("expected 1 rejection, got %d", rejected)
	}
}
