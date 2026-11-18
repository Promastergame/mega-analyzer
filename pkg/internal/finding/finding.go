// Package finding defines the stable, typed reporting contract. It is kept
// independent from legacy analyzer types so detectors can migrate gradually.
package finding

type Kind string

const (
	KindVulnerability Kind = "vulnerability"
	KindInventory     Kind = "inventory"
	KindHardening     Kind = "hardening"
	KindMalware       Kind = "malware"
)

type Finding struct {
	SchemaVersion int          `json:"schema_version"`
	ID            string       `json:"id"`
	Fingerprint   string       `json:"fingerprint"`
	RuleID        string       `json:"rule_id"`
	Kind          Kind         `json:"kind"`
	Category      string       `json:"category"`
	Title         string       `json:"title"`
	Description   string       `json:"description,omitempty"`
	Severity      string       `json:"severity"`
	Confidence    float64      `json:"confidence"`
	CWE           []string     `json:"cwe,omitempty"`
	MASVS         []string     `json:"masvs,omitempty"`
	Locations     []Location   `json:"locations,omitempty"`
	Evidence      []Evidence   `json:"evidence,omitempty"`
	Explanation   *Explanation `json:"explanation,omitempty"`
	Steps         []Step       `json:"steps,omitempty"`
	Provenance    []Provenance `json:"provenance,omitempty"`
	Occurrences   int          `json:"occurrences"`
}

// Explanation separates what the input establishes from conditions that still
// need checking. Status describes the evidence, not observed device execution.
type Explanation struct {
	Status      string   `json:"status"`
	Summary     string   `json:"summary"`
	Conditions  []string `json:"conditions,omitempty"`
	Limitations []string `json:"limitations,omitempty"`
	NextChecks  []string `json:"next_checks,omitempty"`
}

type Location struct {
	File   string `json:"file"`
	Line   int    `json:"line,omitempty"`
	Column int    `json:"column,omitempty"`
	Class  string `json:"class,omitempty"`
	Method string `json:"method,omitempty"`
}

// Step is one ordered instruction/method transition in an evidence path.
type Step struct {
	File   string `json:"file,omitempty"`
	Method string `json:"method"`
	Type   string `json:"type"`
	Line   int    `json:"line,omitempty"`
}

type Provenance struct {
	RunID          string `json:"run_id,omitempty"`
	Engine         string `json:"engine"`
	Detector       string `json:"detector,omitempty"`
	RuleID         string `json:"rule_id"`
	SourceArtifact string `json:"source_artifact,omitempty"`
	ArtifactSHA256 string `json:"artifact_sha256,omitempty"`
}
