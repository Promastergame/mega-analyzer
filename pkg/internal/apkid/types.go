package apkid

import "time"

// SchemaVersion identifies the shape of Report for downstream consumers.
const SchemaVersion = "2"

// Category groups detections by intent.
type Category string

const (
	// CategoryCompiler — toolchain that produced the DEX (dx, d8, dexlib, jack…).
	CategoryCompiler Category = "compiler"
	// CategoryObfuscator — name / control-flow obfuscators (ProGuard, R8, DexGuard…).
	CategoryObfuscator Category = "obfuscator"
	// CategoryPacker — runtime DEX packers / protectors (Bangcle, Qihoo, Legu…).
	CategoryPacker Category = "packer"
	// CategoryAntiVM — emulator / sandbox detection logic.
	CategoryAntiVM Category = "anti_vm"
	// CategoryAntiDebug — debugger / ptrace detection.
	CategoryAntiDebug Category = "anti_debug"
	// CategoryAntiDisasm — anti-static-analysis tricks.
	CategoryAntiDisasm Category = "anti_disasm"
	// CategoryManipulator — apps that ship dynamic-loading capability.
	CategoryManipulator Category = "manipulator"
)

// Match is a single fingerprint hit.
type Match struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Category    Category `json:"category"`
	Description string   `json:"description,omitempty"`
	// File the signature matched against (relative path inside the target).
	// Nested-archive members are prefixed as "outer.apk!inner/path".
	File string `json:"file,omitempty"`
	// Confidence in [0.0, 1.0]. 1.0 = unique, dedicated signature.
	Confidence float64 `json:"confidence"`
	// Evidence is a short snippet that triggered the match (rune-safe).
	Evidence string `json:"evidence,omitempty"`
}

// Stats captures what actually happened during a scan so that a "clean"
// report can be distinguished from a report where files were skipped.
type Stats struct {
	FilesScanned   int           `json:"files_scanned"`
	FilesSkipped   int           `json:"files_skipped"`
	BytesScanned   int64         `json:"bytes_scanned"`
	ArchivesOpened int           `json:"archives_opened"`
	Duration       time.Duration `json:"duration_ns"`
}

// Report is the top-level fingerprint report.
type Report struct {
	SchemaVersion string    `json:"schema_version"`
	RulesVersion  string    `json:"rules_version,omitempty"`
	GeneratedAt   time.Time `json:"generated_at"`
	Target        string    `json:"target"`
	// PrimaryCompiler is a best-effort guess at the toolchain.
	PrimaryCompiler string `json:"primary_compiler,omitempty"`
	// Categories aggregates match IDs by Category for quick summaries.
	Categories map[Category][]string `json:"categories,omitempty"`
	// Matches is the full list, sorted by descending confidence.
	Matches []Match `json:"matches,omitempty"`
	// Summary is a short single-line digest.
	Summary string `json:"summary,omitempty"`
	// Score 0..100 — how "suspicious" the build chain looks. Computed from the
	// set of UNIQUE matched rules (not per-file), so multidex apps are not
	// double-counted.
	Score int `json:"score"`
	// Warnings surfaces non-fatal problems (unreadable entries, parse errors,
	// budget exhaustion). A trustworthy "clean" result has no warnings.
	Warnings []string `json:"warnings,omitempty"`
	// Stats records scan coverage.
	Stats Stats `json:"stats"`
}
