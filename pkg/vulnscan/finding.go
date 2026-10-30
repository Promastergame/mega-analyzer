package vulnscan

import (
	"mega-analyzer/pkg/ml/fusion"
	"strings"
)

// ConfidenceTier buckets a numeric confidence score into the human-facing
// tiers professional scanners report (Confirmed / Probable / Suspect).
type ConfidenceTier string

const (
	TierConfirmed ConfidenceTier = "Confirmed"
	TierProbable  ConfidenceTier = "Probable"
	TierSuspect   ConfidenceTier = "Suspect"
)

// TierForScore maps a 0..1 confidence into a tier.
func TierForScore(score float64) ConfidenceTier {
	switch {
	case score >= 0.8:
		return TierConfirmed
	case score >= 0.5:
		return TierProbable
	default:
		return TierSuspect
	}
}

// Finding is the enriched, standards-compliant successor to Vulnerability.
// It embeds the legacy Vulnerability (so existing producers keep working) and
// layers on confidence, CWE/OWASP/CVSS metadata, and correlation provenance.
type Finding struct {
	Vulnerability

	CWE        []int    `json:"cwe,omitempty"`
	OWASP      []string `json:"owasp,omitempty"`
	CVSS       float64  `json:"cvss"`
	CVSSVector string   `json:"cvss_vector,omitempty"`

	Confidence float64        `json:"confidence"`
	Tier       ConfidenceTier `json:"tier"`
	Signals    []string       `json:"signals,omitempty"`

	// Correlation provenance.
	Correlated         bool           `json:"correlated"`
	Sources            []string       `json:"sources,omitempty"`
	FusionIntelligence *fusion.Report `json:"fusion_intelligence,omitempty"`
}

// neutralPriorConfidence is the starting confidence for findings without any
// evidence signal. It is deliberately neutral (Probable tier): severity must
// NOT inject confidence — confidence is earned by evidence, never assumed.
const neutralPriorConfidence = 0.5

// FindingFromVuln lifts a legacy Vulnerability into a Finding and enriches it
// with taxonomy metadata. Confidence is derived from the evidence signals
// inferred from the finding's Evidence field; findings without recognizable
// evidence start at a neutral prior instead of a severity-derived floor.
func FindingFromVuln(v Vulnerability) Finding {
	f := Finding{Vulnerability: v}
	EnrichWithTaxonomy(&f)
	if signals := inferSignalsFromEvidence(v); len(signals) > 0 {
		ApplyConfidence(&f, signals...)
	} else if f.Confidence == 0 {
		f.Confidence = neutralPriorConfidence
		f.Tier = TierForScore(f.Confidence)
	}
	f.FusionIntelligence = runVulnscanFusionIntelligence(&f)
	return f
}

// FindingsFromVulns converts and enriches a batch of legacy vulnerabilities.
func FindingsFromVulns(vulns []Vulnerability) []Finding {
	out := make([]Finding, 0, len(vulns))
	for _, v := range vulns {
		out = append(out, FindingFromVuln(v))
	}
	return out
}

// inferSignalsFromEvidence maps the structured evidence strings produced by
// the detectors onto confidence signals. This keeps legacy producers
// evidence-graded until they emit signals natively. Matching is done on the
// stable evidence phrases the checks emit, not on free text.
func inferSignalsFromEvidence(v Vulnerability) []string {
	e := strings.ToLower(v.Evidence)
	if e == "" {
		return nil
	}
	var sigs []string

	if strings.Contains(e, "oast") || strings.Contains(e, "received interaction") {
		sigs = append(sigs, SigOASTCallback)
	}
	if strings.Contains(e, "reflected verbatim") {
		sigs = append(sigs, SigReflectedVerbatim)
		// Reflection inside script blocks or attributes executes on render.
		if strings.Contains(e, "scriptblock") || strings.Contains(e, "htmlattribute") {
			sigs = append(sigs, SigExecutableContext)
		}
	}
	if strings.Contains(e, "evaluated marker") || strings.Contains(e, "persists") ||
		strings.Contains(e, "successfully read system file") {
		sigs = append(sigs, SigReflectedVerbatim, SigDifferentialOnly)
	}
	if strings.Contains(e, "absent from") || strings.Contains(e, "differential") {
		sigs = append(sigs, SigDifferentialOnly)
	}
	if strings.Contains(e, "error fingerprint") || strings.Contains(e, "database error") {
		sigs = append(sigs, SigErrorSignature)
	}
	if strings.Contains(e, "benign input does not") {
		sigs = append(sigs, SigDifferentialOnly)
	}

	return dedupeSignals(sigs)
}

// dedupeSignals removes duplicate signal entries, preserving order, so a
// finding is never double-credited for the same evidence.
func dedupeSignals(sigs []string) []string {
	seen := make(map[string]bool, len(sigs))
	out := sigs[:0]
	for _, s := range sigs {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
