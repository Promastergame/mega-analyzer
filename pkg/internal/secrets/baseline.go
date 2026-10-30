package secrets

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
)

// Baseline is a local allowlist of accepted findings ("known, reviewed, stop
// reporting these"). It stores only one-way SHA-256 fingerprints - never the
// secret value itself - so the baseline document is safe to keep next to the
// code. Persistence is entirely up to the caller: Marshal and LoadBaseline
// work on plain bytes, no files or network are touched by this package.
type Baseline struct {
	Version      int      `json:"version"`
	Fingerprints []string `json:"fingerprints"`

	set map[string]struct{}
}

// FindingFingerprint derives a stable, non-reversible id for a finding.
func FindingFingerprint(f ProviderFinding) string {
	sum := sha256.Sum256([]byte(f.RuleID + "\x00" + f.Value))
	return hex.EncodeToString(sum[:16])
}

// NewBaseline builds a baseline that accepts every given finding.
func NewBaseline(findings []ProviderFinding) *Baseline {
	b := &Baseline{Version: 1, set: make(map[string]struct{})}
	for _, f := range findings {
		b.add(FindingFingerprint(f))
	}
	return b
}

// LoadBaseline parses a baseline previously produced by Marshal.
func LoadBaseline(data []byte) (*Baseline, error) {
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, err
	}
	if b.Version == 0 {
		return nil, errors.New("baseline: missing version")
	}
	b.set = make(map[string]struct{}, len(b.Fingerprints))
	for _, fp := range b.Fingerprints {
		b.set[fp] = struct{}{}
	}
	return &b, nil
}

// Marshal renders the baseline as deterministic JSON bytes.
func (b *Baseline) Marshal() ([]byte, error) {
	sort.Strings(b.Fingerprints)
	return json.MarshalIndent(b, "", "  ")
}

// Contains reports whether the finding was already accepted.
func (b *Baseline) Contains(f ProviderFinding) bool {
	if b == nil || b.set == nil {
		return false
	}
	_, ok := b.set[FindingFingerprint(f)]
	return ok
}

// Add accepts a finding into the baseline.
func (b *Baseline) Add(f ProviderFinding) { b.add(FindingFingerprint(f)) }

func (b *Baseline) add(fp string) {
	if b.set == nil {
		b.set = make(map[string]struct{})
	}
	if _, ok := b.set[fp]; ok {
		return
	}
	b.set[fp] = struct{}{}
	b.Fingerprints = append(b.Fingerprints, fp)
}

// Filter returns only findings that are not present in the baseline.
func (b *Baseline) Filter(findings []ProviderFinding) []ProviderFinding {
	if b == nil || len(b.set) == 0 {
		return findings
	}
	out := make([]ProviderFinding, 0, len(findings))
	for _, f := range findings {
		if !b.Contains(f) {
			out = append(out, f)
		}
	}
	return out
}
