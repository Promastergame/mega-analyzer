package vulnscan

import "context"

// maxInvasiveness derives the risk budget from the scanner configuration.
// Destructive checks are only unlocked when the operator asserts ownership of
// the target (LabMode or IOwnThisTarget).
func (e *Engine) maxInvasiveness() Invasiveness {
	if e.Scanner != nil && (e.Scanner.Config.LabMode || e.Scanner.Config.IOwnThisTarget) {
		return InvDestructive
	}
	return InvSafe
}

// RunActiveChecks drives the full active pipeline over discovered forms:
// discovery streams surfaces, an AIMD-governed worker pool runs every
// registered active check (topologically ordered, invasiveness-filtered)
// against each surface, and the raw findings are deduplicated, defence-gap
// analysed, and correlated into the final report set.
//
// This is the concrete, compile-safe realisation of the Discovery -> Injection
// -> Analysis -> Reporting pipeline. It is fully additive: the legacy
// Scanner.Scan() is untouched.
func (e *Engine) RunActiveChecks(ctx context.Context, forms []Form) ([]Finding, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	candidates := FilterByInvasiveness(RegisteredChecks(), e.maxInvasiveness())
	ordered, err := TopoSortChecks(candidates)
	if err != nil {
		return nil, NewScanError(PhaseActive, ErrFatal, "", err)
	}

	var active []CheckDescriptor
	for _, c := range ordered {
		if c.Phase == PhaseActive && c.Run != nil {
			active = append(active, c)
		}
	}

	checkFn := func(ctx context.Context, surface AttackSurface) []Finding {
		var out []Finding
		for _, c := range active {
			select {
			case <-ctx.Done():
				return out
			default:
			}
			out = append(out, c.Run(e.Scanner, &surface)...)
		}
		return out
	}

	surfaces := e.StreamSurfaces(ctx, forms)
	results := e.RunInjection(ctx, surfaces, checkFn)

	var raw []Finding
	for res := range results {
		raw = append(raw, res.Findings...)
	}

	e.Telemetry.StartPhase(string(PhaseCorrelation))
	raw = DeduplicateFindings(raw)
	raw = ApplyDefenceGapAnalysis(raw)
	if meta := Correlate(raw, e.Rules); len(meta) > 0 {
		raw = append(raw, meta...)
	}
	if paths := SynthesizeAttackPaths(raw); len(paths) > 0 {
		raw = append(raw, paths...)
	}
	e.Telemetry.EndPhase(string(PhaseCorrelation))

	if e.ConfidenceThreshold > 0 {
		var kept []Finding
		for _, f := range raw {
			if f.Correlated || f.MeetsThreshold(e.ConfidenceThreshold) {
				kept = append(kept, f)
			}
		}
		raw = kept
	}

	SortFindings(raw)
	return raw, nil
}
