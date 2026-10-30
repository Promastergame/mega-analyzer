package ml

import (
	"math/rand"
	"testing"
)

func TestPSIClassifiesStableVsDrifted(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	ref := make([]float64, 1000)
	for i := range ref {
		ref[i] = rng.NormFloat64()
	}
	bins, err := BuildFeatureBins(ref, 10)
	if err != nil {
		t.Fatal(err)
	}

	// Same distribution — PSI should be near 0.
	stable := make([]float64, 1000)
	for i := range stable {
		stable[i] = rng.NormFloat64()
	}
	psi, err := PSI(bins, stable)
	if err != nil {
		t.Fatal(err)
	}
	if PSIVerdict(psi) != "stable" {
		t.Errorf("matching distribution should be stable, got psi=%f verdict=%s",
			psi, PSIVerdict(psi))
	}

	// Shifted distribution — PSI should flag drift.
	drifted := make([]float64, 1000)
	for i := range drifted {
		drifted[i] = rng.NormFloat64() + 3.0
	}
	psi, _ = PSI(bins, drifted)
	if PSIVerdict(psi) == "stable" {
		t.Errorf("shifted distribution should not be stable, got psi=%f verdict=%s",
			psi, PSIVerdict(psi))
	}
}

func TestPageHinkleyDetectsMeanShift(t *testing.T) {
	ph := NewPageHinkley(0.005, 0.5)

	// Phase 1: 100 stable observations near 0.5.
	rng := rand.New(rand.NewSource(2))
	for i := 0; i < 100; i++ {
		if ph.Update(0.5 + 0.01*rng.NormFloat64()) {
			t.Errorf("alert fired during stable phase at i=%d", i)
		}
	}
	// Phase 2: shift mean to 0.9 — must fire.
	fired := false
	for i := 0; i < 200; i++ {
		if ph.Update(0.9 + 0.01*rng.NormFloat64()) {
			fired = true
			break
		}
	}
	if !fired {
		t.Errorf("Page-Hinkley failed to detect mean shift")
	}
}
