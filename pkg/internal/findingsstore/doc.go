// Package findingsstore provides a local SQLite-backed persistence and search
// subsystem for security analysis findings.
//
// It stores all findings from each scan as an immutable snapshot, supports
// full-text search (FTS5) across historical findings, tracks security score
// dynamics between APK versions, and computes diffs between scans.
//
// The package operates entirely locally using a single findings.db file,
// requires no network access or external servers, and uses the pure-Go
// SQLite driver (modernc.org/sqlite) with no CGO dependency.
//
// Key capabilities:
//   - Atomic scan persistence with batch inserts
//   - Full-text search via FTS5 index on title, text, method_name, class_name
//   - Structured Query DSL for field-based filtering with logical operators
//   - Immutable scan snapshots ensuring historical data integrity
//   - Security score computation and timeline tracking
//   - Diff engine for comparing findings between scans
//   - Markdown diff report generation
//
// Integration: accepts data from correlation.Result and converts
// correlation.Finding into the internal storage format.
package findingsstore
