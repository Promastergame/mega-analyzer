package main

import (
	"mega-analyzer/pkg/internal/sandbox"
	"mega-analyzer/pkg/internal/types"
	"mega-analyzer/pkg/ncer"
)

// feedNcerConsequence converts a finished sandbox Report's behavior
// indicators into types.AnomalyFinding values and attaches them to
// collector, so Reconcile can derive DConsequence (see
// ncer.ConsequenceScore) from the same severities the HTML/JSON report's
// behavior section already surfaces. A no-op when BehaviorAnalysis is nil
// (e.g. non-Windows sandbox runs, where behavior classification isn't
// wired) or has no indicators.
func feedNcerConsequence(collector *ncer.Collector, report *sandbox.Report) {
	if report == nil || report.BehaviorAnalysis == nil || len(report.BehaviorAnalysis.Indicators) == 0 {
		return
	}

	findings := make([]types.AnomalyFinding, 0, len(report.BehaviorAnalysis.Indicators))
	for _, ind := range report.BehaviorAnalysis.Indicators {
		findings = append(findings, types.AnomalyFinding{
			Description: ind.Description,
			Severity:    indicatorSeverity(ind.Severity),
			BypassType:  ind.Type,
			Score:       float64(ind.Severity) / 10.0,
		})
	}
	collector.SetAnomalyFindings(findings)
}

// indicatorSeverity maps sandbox.BehaviorIndicator's 1-10 integer severity
// scale onto types.Severity's four-level enum. The split points mirror
// exploit_analysis.go/behavior_classifier.go's own convention of reserving
// 9-10 for the most critical MITRE techniques (ransomware behavior,
// credential dumping) observed in this codebase.
func indicatorSeverity(s int) types.Severity {
	switch {
	case s >= 9:
		return types.SeverityCritical
	case s >= 7:
		return types.SeverityHigh
	case s >= 4:
		return types.SeverityMedium
	default:
		return types.SeverityLow
	}
}
