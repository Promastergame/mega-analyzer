// p4_path_fp.go — specialization-wins deduplication for traversal findings
// (Phase 4 / P23c).
//
// STATUS: exact copy of the verified file (go vet clean).
//
// Destination: pkg/internal/pipeline/p4_path_fp.go
//
// Two rules describe the same defect at different precision levels:
//
//   - VulnZipSlipDetector (vuln_detectors.go:613) reports types.CategoryZipSlip
//     at the exact write site inside the extraction loop, after checking that
//     no traversal filter guards it.
//   - the summary data-flow engine reports the generic "path_traversal"
//     category for the same ZipEntry.getName() -> File/FileOutputStream chain,
//     with the sink line rather than the guarded write.
//
// Emitting both doubles the report for one issue and, in eval terms, produced a
// false positive on every zip-extraction case (path_traversal precision 0.25 —
// 1 TP against 3 FP). The specialized detector is strictly more informative, so
// the generic flow is dropped for files it already covers.
//
// This never hides a defect: if VulnZipSlipDetector stays silent (no zip_slip
// match on the file), every data-flow traversal finding is kept.

package pipeline

import "mega-analyzer/pkg/internal/types"

// dataflowPathTraversalCategory is the summary-engine category name
// (dataflow/models.go:124-134).
const dataflowPathTraversalCategory = "path_traversal"

// filesWithZipSlip returns the set of files where the specialized zip-slip
// detector already reported a finding. Returns nil when there are none, which
// keeps the common path allocation-free.
func (p *Pipeline) filesWithZipSlip() map[string]bool {
	if p == nil || p.result == nil {
		return nil
	}
	var out map[string]bool
	mark := func(path string) {
		if path == "" {
			return
		}
		if out == nil {
			out = make(map[string]bool, 4)
		}
		out[path] = true
	}
	for path, file := range p.result.Files {
		if file == nil {
			continue
		}
		for i := range file.Matches {
			if file.Matches[i].Category == types.CategoryZipSlip {
				mark(path)
				break
			}
		}
	}
	for i := range p.result.RuleMatches {
		if p.result.RuleMatches[i].Category == types.CategoryZipSlip {
			mark(p.result.RuleMatches[i].File)
		}
	}
	return out
}
