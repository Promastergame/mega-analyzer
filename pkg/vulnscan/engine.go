package vulnscan

import (
	"context"
	"sort"
	"strings"
	"sync"
)

// Engine is the pipeline-oriented orchestrator that layers the elite
// architecture on top of the existing Scanner. It owns the ledger, telemetry,
// AIMD concurrency controller, request sanitizer, and correlation rules, and
// exposes a streaming Discovery -> Injection -> Analysis -> Reporting flow.
//
// It is deliberately additive: the legacy Scanner.Scan() keeps working, while
// callers who want the new behaviour construct an Engine around a Scanner.
type Engine struct {
	Scanner   *Scanner
	Ledger    *Ledger
	Telemetry *ScanTelemetry
	AIMD      *AIMDController
	Sanitizer *RequestSanitizer
	Rules     []CorrelationRule

	// ConfidenceThreshold filters low-signal findings out of the final report.
	ConfidenceThreshold float64
}

// NewEngine builds an Engine with sensible defaults derived from the scanner's
// configuration.
func NewEngine(s *Scanner) *Engine {
	maxConc := s.Config.MaxWorkers
	if maxConc < 1 {
		maxConc = 4
	}
	baseHost := ""
	if s.BaseURL != nil {
		baseHost = s.BaseURL.Host
	}
	threshold := s.Config.ConfidenceThreshold
	e := &Engine{
		Scanner:             s,
		Ledger:              NewLedger(4096),
		Telemetry:           NewScanTelemetry(),
		AIMD:                NewAIMDController(maxConc/2+1, maxConc),
		Sanitizer:           NewRequestSanitizer(s.Config, baseHost),
		Rules:               DefaultCorrelationRules(),
		ConfidenceThreshold: threshold,
	}
	// Wire the engine's controllers into the request gateway so ALL scanner
	// traffic (legacy pipeline included) gets scope enforcement, telemetry,
	// and AIMD backpressure feedback on 429/5xx.
	if s.Gateway != nil {
		s.Gateway.Sanitizer = e.Sanitizer
		s.Gateway.Telemetry = e.Telemetry
		s.Gateway.AIMD = e.AIMD
	}
	return e
}

// EnrichAndCorrelate is the analysis-pipeline entry point that turns a flat
// list of legacy Vulnerabilities into scored, standards-tagged, correlated,
// and deduplicated Findings. This is the bridge that upgrades the output of
// every existing check without rewriting them.
func (e *Engine) EnrichAndCorrelate(vulns []Vulnerability) []Finding {
	findings := FindingsFromVulns(vulns)
	findings = DeduplicateFindings(findings)
	findings = ApplyDefenceGapAnalysis(findings)

	if meta := Correlate(findings, e.Rules); len(meta) > 0 {
		findings = append(findings, meta...)
	}

	// Attack-path synthesis over the finding graph (primitive findings only;
	// the graph builder ignores correlated meta-findings).
	if paths := SynthesizeAttackPaths(findings); len(paths) > 0 {
		findings = append(findings, paths...)
	}

	// Threshold filtering (meta-findings are always kept).
	if e.ConfidenceThreshold > 0 {
		var kept []Finding
		for _, f := range findings {
			if f.Correlated || f.MeetsThreshold(e.ConfidenceThreshold) {
				kept = append(kept, f)
			}
		}
		findings = kept
	}

	SortFindings(findings)
	for i := range findings {
		findings[i].FusionIntelligence = runVulnscanFusionIntelligence(&findings[i])
	}
	if e.Telemetry != nil {
		for range findings {
			e.Telemetry.OnFinding()
		}
	}
	return findings
}

// StreamSurfaces yields attack surfaces on a channel as they are produced,
// enabling the injection stage to begin before discovery completes.
func (e *Engine) StreamSurfaces(ctx context.Context, forms []Form) <-chan AttackSurface {
	out := make(chan AttackSurface)
	go func() {
		defer close(out)
		e.Telemetry.StartPhase(string(PhaseDiscovery))
		defer e.Telemetry.EndPhase(string(PhaseDiscovery))
		for _, as := range AttackSurfacesFromForms(forms) {
			select {
			case <-ctx.Done():
				return
			case out <- as:
			}
		}
	}()
	return out
}

// InjectionResult pairs a surface with the raw findings produced against it.
type InjectionResult struct {
	Surface  AttackSurface
	Findings []Finding
}

// RunInjection fans out per-surface check execution across an AIMD-governed
// worker pool, honouring context cancellation. checkFn is supplied by the
// caller (typically wrapping existing Scanner check methods) so this stage has
// no hard dependency on any specific check.
//
// Shutdown contract: cancelling ctx (or closing surfaces) guarantees every
// worker exits and out is closed, so no goroutines leak even if the producer
// never closes surfaces. Callers must drain out or cancel ctx.
func (e *Engine) RunInjection(ctx context.Context, surfaces <-chan AttackSurface, checkFn func(context.Context, AttackSurface) []Finding) <-chan InjectionResult {
	out := make(chan InjectionResult)
	var wg sync.WaitGroup

	workers := e.AIMD.Concurrency()
	if workers < 1 {
		workers = 1
	}

	go func() {
		e.Telemetry.StartPhase(string(PhaseActive))
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					// Receive with a ctx escape hatch: a plain range would
					// pin the worker forever if the producer never closes
					// surfaces after cancellation.
					var surface AttackSurface
					select {
					case <-ctx.Done():
						return
					case s, ok := <-surfaces:
						if !ok {
							return
						}
						surface = s
					}
					if err := e.AIMD.Acquire(ctx); err != nil {
						return
					}
					func() {
						// Both defers run even if checkFn panics, so a panic
						// neither kills the process nor shrinks the AIMD pool
						// permanently.
						defer func() {
							if r := recover(); r != nil {
								e.Scanner.log("[!] check panic on surface %s: %v", surface.ID, r)
							}
						}()
						defer e.AIMD.Release()
						e.Telemetry.SetSurface(surface.ID)
						findings := checkFn(ctx, surface)
						e.AIMD.OnSuccess()
						select {
						case <-ctx.Done():
							return
						case out <- InjectionResult{Surface: surface, Findings: findings}:
						}
					}()
				}
			}()
		}
		wg.Wait()
		e.Telemetry.EndPhase(string(PhaseActive))
		close(out)
	}()
	return out
}

// findingSeverityRank orders severities from most to least critical for reporting.
func findingSeverityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 0
	case SeverityHigh:
		return 1
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 3
	default:
		return 4
	}
}

// SortFindings orders findings by severity, then confidence (desc), then ID.
func SortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		ri, rj := findingSeverityRank(findings[i].Severity), findingSeverityRank(findings[j].Severity)
		if ri != rj {
			return ri < rj
		}
		if findings[i].Confidence != findings[j].Confidence {
			return findings[i].Confidence > findings[j].Confidence
		}
		return findings[i].ID < findings[j].ID
	})
}

// DeduplicateFindings collapses findings that share the same identity
// (ID + URL + parameter), keeping the highest-confidence representative and
// merging signals. Replaces ad-hoc duplicate output.
func DeduplicateFindings(findings []Finding) []Finding {
	type key struct{ id, url, param string }
	index := make(map[key]int)
	var out []Finding
	for _, f := range findings {
		k := key{strings.ToLower(f.ID), f.URL, f.Parameter}
		if pos, ok := index[k]; ok {
			if f.Confidence > out[pos].Confidence {
				signals := append(out[pos].Signals, f.Signals...)
				f.Signals = dedupeStrings(signals)
				out[pos] = f
			} else {
				out[pos].Signals = dedupeStrings(append(out[pos].Signals, f.Signals...))
			}
			continue
		}
		index[k] = len(out)
		out = append(out, f)
	}
	return out
}

func dedupeStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
