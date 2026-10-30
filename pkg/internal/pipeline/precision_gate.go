package pipeline

import (
	"strings"
	"sync/atomic"

	"mega-analyzer/pkg/internal/precisiongate"
	"mega-analyzer/pkg/internal/types"
)

// precisionSuppressedTotal counts matches suppressed by the precision gate
// across the run. Logged once from logScanBreakdown.
var precisionSuppressedTotal atomic.Int64

// gateFileMatches filters proven false-positive matches in place (before they
// reach counters, reports and the GNN dataset) and returns how many were
// suppressed. It is called from collectResult, the single funnel every
// detector match passes through.
func gateFileMatches(analysis *types.FileAnalysis) int {
	if analysis == nil || len(analysis.Matches) == 0 {
		return 0
	}
	kept := analysis.Matches[:0]
	for i := range analysis.Matches {
		if precisionGateKeeps(analysis.Path, &analysis.Matches[i]) {
			kept = append(kept, analysis.Matches[i])
		}
	}
	suppressed := len(analysis.Matches) - len(kept)
	analysis.Matches = kept
	if suppressed > 0 {
		precisionSuppressedTotal.Add(int64(suppressed))
	}
	return suppressed
}

// precisionGateKeeps adapts one types.Match to a precisiongate.Candidate.
//
// Field semantics differ per detector, so the adapter is defensive:
//   - keyword: m.Text (the matched literal for keyword detectors; the
//     surrounding window for semantic detectors), falling back to m.Pattern.
//   - window: the widest of ResolvedContext/Context that actually CONTAINS
//     the keyword; otherwise the keyword itself. Descriptive Context values
//     (e.g. "Piracy: <description>") never pass the containment check, so
//     they can never trigger a bogus token-boundary drop.
func precisionGateKeeps(path string, m *types.Match) bool {
	kw := m.Text
	if kw == "" {
		kw = m.Pattern
	}
	if strings.TrimSpace(kw) == "" {
		return true
	}
	window := kw
	lkw := strings.ToLower(kw)
	for _, w := range []string{m.ResolvedContext, m.Context} {
		if len(w) > len(kw) && strings.Contains(strings.ToLower(w), lkw) {
			window = w
			break
		}
	}
	v := precisiongate.Evaluate(precisiongate.Candidate{
		Category: string(m.Category),
		Keyword:  kw,
		FilePath: path,
		Context:  precisionContextForPath(path),
		Line:     window,
	})
	return v.Keep
}

// precisionContextForPath maps an analysis path (real or dexClassVirtualPath
// "smali/...") to a precisiongate context.
func precisionContextForPath(p string) precisiongate.Context {
	lp := strings.ToLower(strings.ReplaceAll(p, "\\", "/"))
	base := lp
	if i := strings.LastIndex(lp, "/"); i >= 0 {
		base = lp[i+1:]
	}
	switch {
	case base == "androidmanifest.xml":
		return precisiongate.ManifestCtx
	case strings.HasSuffix(lp, ".smali") || strings.HasSuffix(lp, ".java") ||
		strings.HasSuffix(lp, ".kt") || strings.HasSuffix(lp, ".dex") ||
		strings.Contains(lp, ".dex/") || strings.Contains(lp, ".dex::"):
		return precisiongate.CodeCtx
	case strings.HasSuffix(lp, ".so"):
		return precisiongate.NativeCtx
	case strings.HasSuffix(lp, ".xml") && (strings.HasPrefix(lp, "res/") || strings.Contains(lp, "/res/")):
		return precisiongate.ResourceCtx
	default:
		return precisiongate.AssetCtx
	}
}
