package correlation

// ComputeLikelihood maps a triple of (Reachable, Controllable, Observed)
// into LOW/MEDIUM/HIGH.
//
// The model the user asked for:
//   - reachable          — accessible from outside / used as endpoint
//   - controllable       — attacker can influence the data
//   - observed_at_runtime — actually fired during sandbox run
//
// We deliberately weight the runtime observation higher than the static
// reach/control predictions: a thing we *saw happen* is more credible
// than a thing we *think could happen*.
//
// Scoring (sum of weights):
//
//	observed_at_runtime → +2
//	reachable           → +1
//	controllable        → +1
//
// >= 3   → HIGH
// == 2   → MEDIUM
// <= 1   → LOW
//
// We never produce a LikelihoodNone — even one weak factor is "LOW",
// which is honest about the fact that we still found *something*.
func ComputeLikelihood(f LikelihoodFactors) Likelihood {
	score := 0
	if f.ObservedAtRuntime {
		score += 2
	}
	if f.Reachable {
		score++
	}
	if f.Controllable {
		score++
	}

	switch {
	case score >= 3:
		return LikelihoodHigh
	case score == 2:
		return LikelihoodMedium
	default:
		return LikelihoodLow
	}
}

// MergeFactors picks the "stronger" set of factors, used when a Finding
// is built from several Signals that each contribute different reach /
// control / runtime evidence.
func MergeFactors(a, b LikelihoodFactors) LikelihoodFactors {
	out := a
	if b.Reachable {
		out.Reachable = true
		if out.ReachReason == "" {
			out.ReachReason = b.ReachReason
		}
	}
	if b.Controllable {
		out.Controllable = true
		if out.ControlReason == "" {
			out.ControlReason = b.ControlReason
		}
	}
	if b.ObservedAtRuntime {
		out.ObservedAtRuntime = true
		if out.RuntimeEvidence == "" {
			out.RuntimeEvidence = b.RuntimeEvidence
		}
	}
	return out
}

// FactorsFromSignals derives LikelihoodFactors from a bundle of Signals
// using sensible defaults:
//
//   - any runtime Signal sets ObservedAtRuntime
//   - signals tagged TagReachable or KindNetwork outbound set Reachable
//   - signals tagged TagControllable set Controllable
//
// Callers can still override any field afterwards.
func FactorsFromSignals(signals []*Signal) LikelihoodFactors {
	var f LikelihoodFactors
	for _, s := range signals {
		if s == nil {
			continue
		}
		if s.IsRuntime() {
			f.ObservedAtRuntime = true
			if f.RuntimeEvidence == "" {
				f.RuntimeEvidence = s.Title
			}
		}
		if s.HasTag(TagReachable) || s.HasTag(TagExported) {
			f.Reachable = true
			if f.ReachReason == "" {
				if s.HasTag(TagExported) {
					f.ReachReason = "exported component"
				} else {
					f.ReachReason = "reachable from external context"
				}
			}
		}
		if s.HasTag(TagControllable) {
			f.Controllable = true
			if f.ControlReason == "" {
				f.ControlReason = "attacker-influenced data"
			}
		}
		// network signals are inherently reach-relevant: an outbound
		// connection means the endpoint is at least *reached*.
		if s.Kind == KindNetwork && (s.Type == TypeOutboundConnection ||
			s.Type == TypePublicEgress) {
			f.Reachable = true
			if f.ReachReason == "" {
				f.ReachReason = "outbound connection observed"
			}
		}
	}
	return f
}
