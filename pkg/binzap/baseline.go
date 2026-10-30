package binzap

import (
	"encoding/json"
	"os"
	"time"
)

// Baseline records the fingerprints of previously-accepted findings so that
// subsequent scans can suppress known issues and surface only what is new
// (INC10). It also supports explicit suppressions by fingerprint or rule ID
// (false-positive management).
type Baseline struct {
	GeneratedAt   string          `json:"generated_at"`
	Tool          string          `json:"tool"`
	Version       string          `json:"version"`
	Fingerprints  map[string]bool `json:"fingerprints"`
	SuppressRules map[string]bool `json:"suppress_rules,omitempty"`
}

// NewBaseline returns an empty baseline.
func NewBaseline() *Baseline {
	return &Baseline{
		Tool:          "BinZAP",
		Version:       BinZAPVersion,
		Fingerprints:  map[string]bool{},
		SuppressRules: map[string]bool{},
	}
}

// NewBaselineFromFindings builds a baseline snapshot from a set of findings.
func NewBaselineFromFindings(findings []Finding) *Baseline {
	b := NewBaseline()
	b.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	for _, f := range findings {
		fp := f.Fingerprint
		if fp == "" {
			fp = f.ComputeFingerprint()
		}
		b.Fingerprints[fp] = true
	}
	return b
}

// LoadBaseline reads a baseline JSON file. A missing file yields an empty
// baseline (not an error) so first runs work seamlessly.
func LoadBaseline(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return NewBaseline(), nil
		}
		return nil, err
	}
	b := NewBaseline()
	if err := json.Unmarshal(data, b); err != nil {
		return nil, err
	}
	if b.Fingerprints == nil {
		b.Fingerprints = map[string]bool{}
	}
	if b.SuppressRules == nil {
		b.SuppressRules = map[string]bool{}
	}
	return b, nil
}

// Save writes the baseline to disk atomically.
func (b *Baseline) Save(path string) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// SuppressRule marks an entire rule as suppressed (false-positive management).
func (b *Baseline) SuppressRule(ruleID string) {
	if b.SuppressRules == nil {
		b.SuppressRules = map[string]bool{}
	}
	b.SuppressRules[ruleID] = true
}

// IsSuppressed reports whether a finding should be hidden by this baseline.
func (b *Baseline) IsSuppressed(f Finding) bool {
	if b.SuppressRules[f.RuleID] {
		return true
	}
	fp := f.Fingerprint
	if fp == "" {
		fp = f.ComputeFingerprint()
	}
	return b.Fingerprints[fp]
}

// Apply returns only the findings not suppressed by the baseline.
func (b *Baseline) Apply(findings []Finding) []Finding {
	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if b.IsSuppressed(f) {
			continue
		}
		out = append(out, f)
	}
	return out
}
