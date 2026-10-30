package binzap

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// Severity represents the severity level of a finding.
type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// severityRank gives an ordering weight (higher = more severe) used for sorting.
func severityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// Confidence represents how confident the scanner is about a finding.
type Confidence string

const (
	ConfidenceLow       Confidence = "LOW"
	ConfidenceMedium    Confidence = "MEDIUM"
	ConfidenceHigh      Confidence = "HIGH"
	ConfidenceConfirmed Confidence = "CONFIRMED"
)

// Finding represents a single security issue or anomaly discovered during scanning.
//
// The core fields (RuleID, Severity, Message, File, Line, Evidence, Confidence)
// are preserved for backward compatibility. The remaining fields carry the
// richer, evidence-based metadata required by a production analyzer: CWE
// mapping, remediation guidance, exploitability, provenance of the detection
// and, for taint findings, the full source-to-sink attack path.
type Finding struct {
	RuleID     string     `json:"rule_id"`
	RuleName   string     `json:"rule_name,omitempty"`
	Severity   Severity   `json:"severity"`
	Confidence Confidence `json:"confidence,omitempty"`
	Message    string     `json:"message"`
	File       string     `json:"file"`
	Line       int        `json:"line"`
	Column     int        `json:"column,omitempty"`
	Evidence   string     `json:"evidence,omitempty"`

	// Enriched metadata (INC5). All optional so existing producers keep working.
	CWE            string   `json:"cwe,omitempty"`
	Category       string   `json:"category,omitempty"`
	Remediation    string   `json:"remediation,omitempty"`
	Exploitability string   `json:"exploitability,omitempty"`
	DataSource     string   `json:"detected_by,omitempty"`
	AttackPath     []string `json:"attack_path,omitempty"`
	Fingerprint    string   `json:"fingerprint,omitempty"`
}

// ComputeFingerprint returns a stable, location-tolerant identity for the
// finding so results can be de-duplicated and compared against a baseline
// across runs. The line number is intentionally excluded so that unrelated
// edits above the finding do not change its identity.
func (f Finding) ComputeFingerprint() string {
	h := sha256.New()
	h.Write([]byte(f.RuleID))
	h.Write([]byte{0})
	h.Write([]byte(f.File))
	h.Write([]byte{0})
	h.Write([]byte(strings.TrimSpace(f.Evidence)))
	h.Write([]byte{0})
	h.Write([]byte(f.CWE))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// WithFingerprint returns a copy of the finding with Fingerprint populated.
func (f Finding) WithFingerprint() Finding {
	f.Fingerprint = f.ComputeFingerprint()
	return f
}

// SortFindings orders findings by severity (desc), then file, then line. It
// mutates and returns the slice for convenience.
func SortFindings(findings []Finding) []Finding {
	sort.SliceStable(findings, func(i, j int) bool {
		ri, rj := severityRank(findings[i].Severity), severityRank(findings[j].Severity)
		if ri != rj {
			return ri > rj
		}
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		return findings[i].Line < findings[j].Line
	})
	return findings
}

// DedupeFindings removes findings that share the same fingerprint, keeping the
// first occurrence. Missing fingerprints are computed on the fly.
func DedupeFindings(findings []Finding) []Finding {
	seen := make(map[string]struct{}, len(findings))
	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		fp := f.Fingerprint
		if fp == "" {
			fp = f.ComputeFingerprint()
		}
		if _, ok := seen[fp]; ok {
			continue
		}
		seen[fp] = struct{}{}
		f.Fingerprint = fp
		out = append(out, f)
	}
	return out
}
