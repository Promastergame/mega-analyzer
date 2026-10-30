package apkloader

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
	"strings"

	"mega-analyzer/pkg/internal/crackpoint"
	"mega-analyzer/pkg/internal/fpfilter"
	"mega-analyzer/pkg/internal/types"
	llmkeys "mega-analyzer/pkg/ml/llm_but_this_ml_lol"
)

// fpValidator reuses the same placeholder/entropy heuristics the APK pipeline
// applies to Match-based findings, as a secondary filter on top of llmkeys —
// it catches placeholder/example/mangled-symbol shapes llmkeys lets through.
var fpValidator = fpfilter.NewSecretValidator()

// contextKeywords are credential-suggestive substrings looked for in the raw
// byte window around a candidate secret. Their presence raises numeric-PIN
// candidates to Medium severity (see numericPinFindings).
var contextKeywords = []string{
	"password", "passwd", "pwd", "api_key", "apikey", "secret",
	"token", "pin", "auth", "credential",
}

// ═══════════════════════════════════════════════════════════════════════════════
// NATIVE CRACK POINTS + OFFLINE SECRET CLASSIFICATION  (Rust-free)
// ═══════════════════════════════════════════════════════════════════════════════
//
// Native binaries (PE/ELF/Mach-O) have no Dalvik CFG, so crack-point detection
// runs over imported/exported symbols and extracted strings via the
// format-agnostic symbol scanner. This works on every build — it does NOT need
// the Rust scan-native bridge. It flags anti-debug / anti-tamper / root /
// license-gate indicators (ptrace, IsDebuggerPresent, /system/bin/su, …).

// DetectNativeCrackPoints scans a native binary's symbols and strings for
// protection gates and returns them in the slim report type.
func DetectNativeCrackPoints(data []byte, binName string) []types.CrackPoint {
	if len(data) == 0 {
		return nil
	}
	finder := crackpoint.NewFinder()
	res := finder.FindCrackPointsInSymbols(nativeSymbolRefs(data, binName), binName, crackpoint.PlatformNative)
	return convertCrackPoints(res, binName)
}

// NativeSecretFindings runs the offline credential classifier over the binary's
// printable strings, surfacing embedded keys/tokens as artifact findings. When
// reveal is true, findings also carry the unmasked value in PayloadFull; when
// false (the default), only the masked Payload is populated so nothing
// sensitive round-trips through the report unless explicitly requested.
//
// includeNumericPin controls whether the pure-Go short-numeric-PIN heuristic
// (numericPinFindings below) also runs. The Rust scan-native engine's
// scan_numeric_candidates (rust/crates/omnisec-scan-native/src/strings.rs)
// covers the same signal with a superset of the logic here — it additionally
// recovers PINs merged into linker string-tail tables — so callers should
// pass includeNumericPin=true ONLY when the Rust scan did not run (build
// without the cgo bridge, or the scan failed). Running both unconditionally
// used to double-report every short digit run with two different severities.
func NativeSecretFindings(data []byte, binName string, reveal bool, includeNumericPin bool) []types.ArtifactFinding {
	if len(data) == 0 {
		return nil
	}
	var out []types.ArtifactFinding
	seen := make(map[string]bool)
	for _, occ := range extractStringOccurrences(data, 8) {
		v := strings.TrimSpace(occ.val)
		if v == "" || len(v) > 512 || seen[v] {
			continue
		}
		// llmkeys.Classify has its own hard floor at 12 chars (family/PEM matches
		// need even longer bodies), so no gate here can make it evaluate shorter
		// values — this mirrors the digit-table-merge discovery already recorded
		// in MACHINE_CODE_IMPROVEMENT_PLAN.md: short secrets need a dedicated
		// heuristic (numericPinFindings below), not a lowered threshold on this
		// generic entropy/family classifier.
		if len(v) < 12 {
			continue
		}
		window := secretContextWindow(data, occ.offset, len(occ.val), 48)
		cs := llmkeys.ClassifyContext(v, "", window)
		// Only surface a known credential family or a high-confidence token —
		// not the medium-entropy tier.
		if !cs.IsSecret || (cs.Family == "" && cs.Confidence < 0.8) {
			continue
		}
		if fp := fpValidator.Validate(&types.Match{Text: v, Context: window}); !fp.IsReal && strings.Contains(fp.Reason, "placeholder") {
			continue
		}
		seen[v] = true
		masked := maskNativeSecret(v)
		reason := "Embedded credential detected by offline classifier"
		if cs.Family != "" {
			reason += " (" + cs.Family + " family)"
		}
		reason += ". " + cs.Reason
		finding := types.ArtifactFinding{
			Path:     binName,
			Severity: crackPointSeverity(cs.Confidence),
			Reason:   reason,
			Payload:  masked,
			Stages:   []string{"native", "secret", "llmkeys"},
		}
		if reveal {
			finding.PayloadFull = v
		}
		out = append(out, finding)
	}
	if includeNumericPin {
		out = append(out, numericPinFindings(data, binName, seen, reveal)...)
	}
	return out
}

// maxNumericPinFindings caps the fallback numeric-PIN heuristic so a binary
// dense with short digit runs (version strings, offsets, build IDs) cannot
// blow up the report. Mirrors MAX_NUMERIC_FINDINGS in the Rust counterpart.
const maxNumericPinFindings = 16

// numericPinFindings scans standalone numeric strings (3-8 digits, isolated
// by non-printable bytes rather than embedded in a longer identifier) as
// PIN/password candidates. A bare digit run is far too common on its own
// (build IDs, offsets, version numbers) to flag above Low severity; it is
// only raised to Medium when a credential-suggestive keyword sits in the
// surrounding byte window — matching the Rust engine's severity policy for
// the same signal (scan_numeric_candidates in strings.rs) so a binary
// doesn't get a different verdict depending on whether it was built with
// the cgo bridge.
//
// This is a fallback-only heuristic (see includeNumericPin on
// NativeSecretFindings): unlike the Rust implementation it does not attempt
// linker string-tail-merge recovery, so it is strictly less capable and
// should not run alongside the Rust scan.
func numericPinFindings(data []byte, binName string, seen map[string]bool, reveal bool) []types.ArtifactFinding {
	var out []types.ArtifactFinding
	var skipped int
	for _, occ := range extractStringOccurrences(data, 3) {
		v := occ.val
		if len(v) > 8 || seen[v] || !isAllDigits(v) {
			continue
		}
		seen[v] = true
		if len(out) >= maxNumericPinFindings {
			skipped++
			continue
		}
		window := secretContextWindow(data, occ.offset, len(v), 48)
		sev := types.SeverityLow
		reason := "Standalone numeric string, candidate PIN/password"
		if hasContextKeyword(window) {
			sev = types.SeverityMedium
			reason = "Standalone numeric string near a credential-suggestive keyword — likely PIN/password"
		}
		finding := types.ArtifactFinding{
			Path:     binName,
			Severity: sev,
			Reason:   reason,
			Payload:  maskNativeSecret(v),
			Stages:   []string{"native", "secret", "numeric-pin"},
		}
		if reveal {
			finding.PayloadFull = v
		}
		out = append(out, finding)
	}
	if skipped > 0 {
		out = append(out, types.ArtifactFinding{
			Path:     binName,
			Severity: types.SeverityInfo,
			Reason:   fmt.Sprintf("%d additional numeric-PIN candidate(s) omitted to keep the report readable (cap: %d)", skipped, maxNumericPinFindings),
			Stages:   []string{"native", "secret", "numeric-pin", "truncated"},
		})
	}
	return out
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// strOcc is a printable string extracted from raw bytes together with the
// byte offset it started at, needed for context-window proximity checks.
type strOcc struct {
	val    string
	offset int
}

// extractStringOccurrences is like extractStrings but also records each
// string's starting byte offset.
func extractStringOccurrences(data []byte, minLen int) []strOcc {
	var out []strOcc
	var cur []byte
	start := 0
	for i, b := range data {
		if b >= 0x20 && b < 0x7f {
			if len(cur) == 0 {
				start = i
			}
			cur = append(cur, b)
			continue
		}
		if len(cur) >= minLen {
			out = append(out, strOcc{val: string(cur), offset: start})
		}
		cur = cur[:0]
	}
	if len(cur) >= minLen {
		out = append(out, strOcc{val: string(cur), offset: start})
	}
	return out
}

// secretContextWindow returns up to windowBytes of raw text on either side of
// [offset, offset+length), with non-printable bytes replaced by spaces, for
// use as both the llmkeys.ClassifyContext surrounding text and the local
// keyword-proximity check.
func secretContextWindow(data []byte, offset, length, windowBytes int) string {
	lo := offset - windowBytes
	if lo < 0 {
		lo = 0
	}
	hi := offset + length + windowBytes
	if hi > len(data) {
		hi = len(data)
	}
	raw := data[lo:hi]
	b := make([]byte, len(raw))
	for i, c := range raw {
		if c >= 0x20 && c < 0x7f {
			b[i] = c
		} else {
			b[i] = ' '
		}
	}
	return string(b)
}

func hasContextKeyword(window string) bool {
	low := strings.ToLower(window)
	for _, kw := range contextKeywords {
		if strings.Contains(low, kw) {
			return true
		}
	}
	return false
}

// nativeSymbolRefs collects imported symbols, exported/dynamic symbols, linked
// libraries and printable strings as crack-point symbols. Symbol extraction is
// best-effort per format; string extraction always runs (so unparseable or fat
// binaries still yield string-based gates like jailbreak markers).
func nativeSymbolRefs(data []byte, binName string) []crackpoint.SymbolRef {
	var syms []crackpoint.SymbolRef
	add := func(name string, kind crackpoint.SymbolKind) {
		name = strings.TrimSpace(name)
		if name == "" {
			return
		}
		syms = append(syms, crackpoint.SymbolRef{Name: name, Kind: kind, Class: binName, Raw: name})
	}

	switch {
	case len(data) >= 4 && bytes.Equal(data[:4], []byte{0x7f, 'E', 'L', 'F'}):
		if f, err := elf.NewFile(bytes.NewReader(data)); err == nil {
			if imps, err := f.ImportedSymbols(); err == nil {
				for _, s := range imps {
					add(s.Name, crackpoint.SymbolImport)
				}
			}
			if dyn, err := f.DynamicSymbols(); err == nil {
				for _, s := range dyn {
					add(s.Name, crackpoint.SymbolExport)
				}
			}
			f.Close()
		}
	case len(data) >= 2 && data[0] == 'M' && data[1] == 'Z':
		if f, err := pe.NewFile(bytes.NewReader(data)); err == nil {
			if imps, err := f.ImportedSymbols(); err == nil {
				for _, s := range imps {
					add(s, crackpoint.SymbolImport)
				}
			}
			f.Close()
		}
	case isMachOMagic(data):
		if f, err := macho.NewFile(bytes.NewReader(data)); err == nil {
			if imps, err := f.ImportedSymbols(); err == nil {
				for _, s := range imps {
					add(s, crackpoint.SymbolImport)
				}
			}
			if libs, err := f.ImportedLibraries(); err == nil {
				for _, l := range libs {
					add(l, crackpoint.SymbolDylib)
				}
			}
			f.Close()
		}
	}

	for _, s := range extractStrings(data, 5) {
		if len(s) == 0 || len(s) > 200 {
			continue
		}
		add(s, crackpoint.SymbolString)
	}
	return syms
}

// convertCrackPoints maps the crackpoint engine result into []types.CrackPoint.
func convertCrackPoints(res *crackpoint.AnalysisResult, file string) []types.CrackPoint {
	if res == nil || len(res.CrackPoints) == 0 {
		return nil
	}
	out := make([]types.CrackPoint, 0, len(res.CrackPoints))
	for _, cp := range res.CrackPoints {
		out = append(out, types.CrackPoint{
			Location:   types.SourceLocation{File: file, Method: cp.MethodName},
			ClassName:  cp.ClassName,
			Method:     cp.MethodName,
			Category:   cp.Category,
			Confidence: cp.Confidence,
			Impact:     cp.Impact,
			Suggestion: cp.SuggestedAction,
			PatchRisk:  cp.PatchRisk,
		})
	}
	return out
}

// crackPointSeverity maps a crack-point confidence to an artifact severity.
func crackPointSeverity(confidence float64) types.Severity {
	switch {
	case confidence >= 0.85:
		return types.SeverityHigh
	case confidence >= 0.6:
		return types.SeverityMedium
	default:
		return types.SeverityLow
	}
}

func maskNativeSecret(s string) string {
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + strings.Repeat("*", 6) + s[len(s)-2:]
}

// crackPointArtifact renders a crack point as a compact artifact finding so it
// surfaces in reports even when result.CrackPoint is not built.
func crackPointArtifact(cp types.CrackPoint, stage string) types.ArtifactFinding {
	return types.ArtifactFinding{
		Path:     cp.Location.File,
		Severity: crackPointSeverity(cp.Confidence),
		Reason: fmt.Sprintf("Crack point [%s]: %s (confidence %.2f) — %s",
			cp.Category, cp.Method, cp.Confidence, cp.Suggestion),
		Stages: []string{stage, "crackpoint"},
	}
}
