// Package analysis implements BinZAP's real static analysis: control-flow,
// intra-procedural data-flow and source-to-sink taint tracking over the ir
// package. It is dependency-free (stdlib only) and has no knowledge of the
// binzap Finding type, so it can be tested and reused in isolation. binzap
// adapts analysis.Finding into its own Finding type.
package analysis

// Severity mirrors the standard levels; kept as its own type to avoid a cycle
// with the binzap package.
type Severity string

const (
	SevInfo     Severity = "INFO"
	SevLow      Severity = "LOW"
	SevMedium   Severity = "MEDIUM"
	SevHigh     Severity = "HIGH"
	SevCritical Severity = "CRITICAL"
)

// SourceKind categorizes where tainted data originates.
type SourceKind string

const (
	KindUserInput  SourceKind = "user-input"
	KindNetwork    SourceKind = "network"
	KindFile       SourceKind = "file"
	KindIPC        SourceKind = "ipc"
	KindCredential SourceKind = "credential"
	KindSeed       SourceKind = "seed"
)

// Source describes a taint source (a method whose result is attacker-influenced
// or otherwise sensitive).
type Source struct {
	ID     string
	Kind   SourceKind
	Substr string // matched against the invoke method reference
	Label  string
}

// Sink describes a dangerous operation and how to report reaching it.
type Sink struct {
	ID          string
	Substr      string
	CWE         string
	Severity    Severity
	Category    string
	Title       string
	Remediation string
}

// Finding is analysis' own result type (source-to-sink taint result).
type Finding struct {
	RuleID         string
	Title          string
	CWE            string
	Severity       Severity
	Confidence     string
	Category       string
	File           string
	Line           int
	Column         int
	Evidence       string
	Remediation    string
	Exploitability string
	DetectedBy     string
	Path           []string
}
