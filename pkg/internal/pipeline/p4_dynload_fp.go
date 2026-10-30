// p4_dynload_fp.go — presence-only DYNAMIC_LOAD suppression
// (Phase 4 / P18c, eval known_gap "d-private-path-trap").
//
// STATUS: exact copy of the verified file (go vet clean, unit + -race clean,
// eval FP for DYNAMIC_LOAD eliminated).
//
// Destination: pkg/internal/pipeline/p4_dynload_fp.go
//
// Two independent producers report CategoryDynamicLoad ("DYNAMIC_LOAD") from a
// substring alone:
//
//  1. the byte matcher, pkg/internal/matcher/patterns.go:571
//     {Category: types.CategoryDynamicLoad, Pattern: `DexClassLoader`, Priority: 7, IsCritical: true, ...}
//     Its emitted match carries Pattern = rule description ("Dynamic DEX
//     loading") and Text = the source line (matcher_v2.go:932-943), so the
//     loader class name has to be looked for in BOTH fields. Matching only on
//     Pattern was the reason the first two attempts of this patch had no
//     effect.
//  2. the threat-signal layer: SignalDexClassLoader / SignalDexFileLoad fire on
//     the textual Ldalvik/system/DexClassLoader; reference and then feed
//     cross-file correlations (RUNTIME_LOAD_CHAIN / RUNTIME_LOAD_PARTIAL,
//     threat_aggregator.go:428) whose category is CategoryDynamicCodeLoad ==
//     CategoryDynamicLoad.
//
// VulnDynamicLoadDetector (vuln_dynload_smali.go:58) resolves the actual operand
// of every load call site and deliberately stays silent for a literal
// app-private path such as "/data/data/<pkg>/code_cache/patch.dex" — the
// standard hot-patch layout. Both presence producers overrode that correct AST
// verdict, so a resolved-and-cleared file still surfaced a critical finding.
//
// Rule: the operand resolver is authoritative whenever the file actually parsed
// into a smali class. If re-running it over the parsed AST yields no
// dynamic-load evidence, the presence-only artifacts are dropped:
//   - matched pattern hits are removed from analysis.Matches;
//   - the dex-loader signals are removed from FileSignals before aggregation,
//     so no correlation can resurrect the category APK-wide.
//
// Untouched: AST-backed matches (d-external-dex, d-intent-driven-dex), in-memory
// DEX (always critical), dlopen/loadLibrary findings, unparsed files
// (smali_compact streams, native libs, resources) and every other signal on the
// same file.

package pipeline

import (
	"strings"

	"mega-analyzer/pkg/internal/types"
)

// dynLoadEvidenceAST marks matches emitted by the operand-resolving detector.
const dynLoadEvidenceAST = "smali_ast_dataflow"

// dynLoadPresencePatterns mirrors the loader patterns in matcher/patterns.go
// that fire on class-name presence alone.
var dynLoadPresencePatterns = []string{
	"dexclassloader",
	"pathclassloader",
	"dalvik.system.dexfile",
	"dalvik/system/dexfile",
}

// dynLoadRefutedSignals are presence signals the resolver can disprove.
// SignalInMemoryDexClassLoader is intentionally absent: the AST detector always
// flags in-memory loading, so it can never be the refuted one.
var dynLoadRefutedSignals = []SignalType{SignalDexClassLoader, SignalDexFileLoad}

func isPresenceOnlyDynLoad(m *types.Match) bool {
	if m.Category != types.CategoryDynamicLoad || m.EvidenceType == dynLoadEvidenceAST {
		return false
	}
	for _, field := range [2]string{m.Text, m.Pattern} {
		if field == "" {
			continue
		}
		lowered := strings.ToLower(field)
		for _, p := range dynLoadPresencePatterns {
			if strings.Contains(lowered, p) {
				return true
			}
		}
	}
	return false
}

// dynLoadASTRefutes reports whether the parsed AST proves there is no
// dynamic-load finding in this file. Only ever consulted for files that already
// carry a presence hit, so the extra resolver pass is negligible.
func dynLoadASTRefutes(ctx *FileDetectContext) bool {
	if ctx == nil || ctx.FileType != types.FileTypeSmali || ctx.Class == nil {
		return false // no AST ⇒ nothing is proven ⇒ keep the signal
	}
	probe := types.FileAnalysis{Path: ctx.Path}
	for i := range ctx.Class.Methods {
		detectDynamicLoadInMethod(&ctx.Class.Methods[i], ctx.Class, &probe)
		if len(probe.Matches) > 0 {
			return false
		}
	}
	return true
}

// suppressRefutedDexLoaderSignals runs inside the threat-signal detector, right
// before file signals are merged into the APK-wide aggregator
// (threat_detectors.go:178-183).
func suppressRefutedDexLoaderSignals(ctx *FileDetectContext, fs *FileSignals) {
	if fs == nil || len(fs.Signals) == 0 {
		return
	}
	if !fs.HasAny(dynLoadRefutedSignals...) {
		return
	}
	if !dynLoadASTRefutes(ctx) {
		return
	}
	for _, sig := range dynLoadRefutedSignals {
		hit, ok := fs.Signals[sig]
		if !ok {
			continue
		}
		if hit != nil {
			fs.Score -= hit.Weight
		}
		delete(fs.Signals, sig)
	}
	if fs.Score < 0 {
		fs.Score = 0
	}
}

// suppressPresenceOnlyDynamicLoad runs after the detector chain, once both the
// byte matcher and the AST detector have contributed their matches
// (workers.go, right after p.runDetectors).
func suppressPresenceOnlyDynamicLoad(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	if ctx == nil || analysis == nil || ctx.FileType != types.FileTypeSmali {
		return
	}
	// No AST ⇒ no authoritative verdict ⇒ keep the conservative signal.
	if ctx.Class == nil || len(analysis.Matches) == 0 {
		return
	}

	astProof, presenceOnly := false, false
	for i := range analysis.Matches {
		m := &analysis.Matches[i]
		if m.Category != types.CategoryDynamicLoad {
			continue
		}
		if m.EvidenceType == dynLoadEvidenceAST {
			astProof = true
			continue
		}
		if isPresenceOnlyDynLoad(m) {
			presenceOnly = true
		}
	}
	if astProof || !presenceOnly {
		return
	}

	kept := analysis.Matches[:0]
	for i := range analysis.Matches {
		if isPresenceOnlyDynLoad(&analysis.Matches[i]) {
			continue
		}
		kept = append(kept, analysis.Matches[i])
	}
	analysis.Matches = kept
}
