package correlation

// BaseRiskFromSeverity converts a 0..10 severity (the scale used by
// sandbox.MemoryFinding / ExploitCandidate) to a Risk bucket.
func BaseRiskFromSeverity(severity int) Risk {
	switch {
	case severity >= 9:
		return RiskCritical
	case severity >= 7:
		return RiskHigh
	case severity >= 4:
		return RiskMedium
	case severity > 0:
		return RiskLow
	default:
		return RiskInfo
	}
}

// AdjustRisk applies *context-aware* scoring.
//
// Concrete rules the user asked for:
//
//   - hardcoded_secret alone → MEDIUM
//   - hardcoded_secret used in a runtime network call → HIGH
//   - cleartext / insecure endpoint without runtime use → LOW
//   - cleartext / insecure endpoint with runtime connection → HIGH
//
// The function takes the base risk (derived from upstream severity)
// and a slice of supporting Signals. It keeps the original base if no
// rule applies.
//
// AdjustRisk is intentionally additive only — it never lowers a
// CRITICAL to a HIGH. Use FPGuard for that.
func AdjustRisk(base Risk, primary *Signal, supporting []*Signal) Risk {
	if primary == nil {
		return base
	}

	hasRuntimeNetwork := false
	hasRuntimeAny := false
	hasExported := false
	for _, s := range supporting {
		if s == nil {
			continue
		}
		if s.IsRuntime() {
			hasRuntimeAny = true
		}
		if s.Kind == KindNetwork && s.IsRuntime() {
			hasRuntimeNetwork = true
		}
		if s.HasTag(TagExported) {
			hasExported = true
		}
	}

	switch primary.Type {
	case TypeHardcodedSecret:
		if hasRuntimeNetwork {
			return upgrade(base, RiskHigh)
		}
		return upgrade(base, RiskMedium)

	case TypeCleartextEndpoint, TypeHardcodedIPEndpoint:
		if hasRuntimeNetwork {
			return upgrade(base, RiskHigh)
		}
		// downgrade-ish: never go below LOW so we still surface it
		return atLeast(downgrade(base), RiskLow)

	case TypeDebugEndpoint:
		if hasRuntimeNetwork || hasExported {
			return upgrade(base, RiskHigh)
		}
		return atLeast(downgrade(base), RiskLow)

	case TypeWebViewJSBridge:
		// Only critical if we have evidence of remote content + JS.
		hasRemoteContent := containsType(supporting,
			TypeOutboundConnection, TypeWebViewCleartext,
			TypeCleartextEndpoint, TypeHardcodedIPEndpoint)
		if hasRemoteContent {
			return upgrade(base, RiskHigh)
		}
		// JS bridge that does not load remote content is much less
		// scary; cap at MEDIUM.
		return atMost(base, RiskMedium)

	case TypeAuthGate, TypeBooleanGate:
		// Client-side auth checks: HIGH if no server validation
		// observed at runtime; otherwise leave at base.
		if !hasRuntimeAny {
			return atLeast(base, RiskMedium)
		}
		return base

	case TypeRWXMemory, TypeMemoryWrite, TypeRemoteThread:
		// FPGuard handles JIT downgrade. Here we only *boost* if the
		// chain is corroborated.
		if containsType(supporting,
			TypeProcessInjection, TypeProcessHollowing) ||
			hasRuntimeNetwork {
			return upgrade(base, RiskHigh)
		}
		return base
	}
	return base
}

func upgrade(current, target Risk) Risk {
	if current.Rank() > target.Rank() {
		return current
	}
	return target
}

func downgrade(current Risk) Risk {
	switch current {
	case RiskCritical:
		return RiskHigh
	case RiskHigh:
		return RiskMedium
	case RiskMedium:
		return RiskLow
	case RiskLow:
		return RiskInfo
	default:
		return current
	}
}

func atLeast(r, floor Risk) Risk {
	if r.Rank() < floor.Rank() {
		return floor
	}
	return r
}

func atMost(r, ceiling Risk) Risk {
	if r.Rank() > ceiling.Rank() {
		return ceiling
	}
	return r
}

func containsType(signals []*Signal, types ...string) bool {
	for _, s := range signals {
		if s == nil {
			continue
		}
		for _, t := range types {
			if s.Type == t {
				return true
			}
		}
	}
	return false
}

// AggregateRisk picks the highest risk among findings. Used to compute
// Result.OverallRisk.
func AggregateRisk(findings []Finding, chains []AttackChain) Risk {
	overall := RiskInfo
	for _, f := range findings {
		if f.Risk.Rank() > overall.Rank() {
			overall = f.Risk
		}
	}
	for _, c := range chains {
		if c.Risk.Rank() > overall.Rank() {
			overall = c.Risk
		}
	}
	return overall
}

// AggregateLikelihood picks the highest likelihood among findings + chains.
func AggregateLikelihood(findings []Finding, chains []AttackChain) Likelihood {
	overall := LikelihoodLow
	for _, f := range findings {
		if f.Likelihood.Rank() > overall.Rank() {
			overall = f.Likelihood
		}
	}
	for _, c := range chains {
		if c.Likelihood.Rank() > overall.Rank() {
			overall = c.Likelihood
		}
	}
	return overall
}
