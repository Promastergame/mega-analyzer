package correlation

import "testing"

func TestComputeLikelihood(t *testing.T) {
	cases := []struct {
		name string
		f    LikelihoodFactors
		want Likelihood
	}{
		{"empty", LikelihoodFactors{}, LikelihoodLow},
		{"reachable only", LikelihoodFactors{Reachable: true}, LikelihoodLow},
		{"reachable+controllable", LikelihoodFactors{Reachable: true, Controllable: true}, LikelihoodMedium},
		{"observed only", LikelihoodFactors{ObservedAtRuntime: true}, LikelihoodMedium},
		{"observed+reach", LikelihoodFactors{ObservedAtRuntime: true, Reachable: true}, LikelihoodHigh},
		{"all three", LikelihoodFactors{Reachable: true, Controllable: true, ObservedAtRuntime: true}, LikelihoodHigh},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ComputeLikelihood(c.f)
			if got != c.want {
				t.Fatalf("ComputeLikelihood(%+v) = %s, want %s", c.f, got, c.want)
			}
		})
	}
}

func TestFactorsFromSignals_RuntimeNetworkSetsReach(t *testing.T) {
	signals := []*Signal{
		{
			Kind: KindNetwork,
			Type: TypeOutboundConnection,
			// non-zero severity so it's not skipped
			Severity: 5,
		},
	}
	f := FactorsFromSignals(signals)
	if !f.ObservedAtRuntime {
		t.Fatal("expected ObservedAtRuntime = true")
	}
	if !f.Reachable {
		t.Fatal("expected Reachable = true (outbound network is reach-relevant)")
	}
}

func TestMergeFactors_Union(t *testing.T) {
	a := LikelihoodFactors{Reachable: true, ReachReason: "exported"}
	b := LikelihoodFactors{Controllable: true, ControlReason: "user input"}
	merged := MergeFactors(a, b)
	if !merged.Reachable || !merged.Controllable {
		t.Fatalf("merged should have both: %+v", merged)
	}
	if merged.ReachReason != "exported" || merged.ControlReason != "user input" {
		t.Fatalf("reasons should be preserved: %+v", merged)
	}
}
