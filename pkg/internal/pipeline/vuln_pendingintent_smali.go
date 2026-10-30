// pkg/internal/pipeline/vuln_pendingintent_smali.go
//
// AST-based mutable-PendingIntent detection (audit item P0-3 / B1).
//
// The legacy detector had two fatal flaws:
//
//  1. Its byte patterns encode decompiled-Java syntax (`pendingintent.getactivity(`)
//     that never occurs in smali, where the call renders as
//     `invoke-static {...}, Landroid/app/PendingIntent;->getActivity(...)` —
//     the detector was dead for the primary input format.
//  2. Its FLAG_IMMUTABLE check was FILE-WIDE: a single safe call site (or an
//     unrelated `0x04000000` literal anywhere in the class) suppressed
//     findings for every unsafe call site in the same file — the classic
//     false negative for mixed safe/unsafe usage.
//
// This detector resolves the flags register of EACH PendingIntent factory
// call site inside its own method, using a small integer-constant tracker
// (const*/or-int propagation, destination invalidation on every other write).
//
//   flags & FLAG_IMMUTABLE (0x04000000)          → safe, no finding
//   flags & FLAG_MUTABLE  (0x02000000)           → explicit mutable (critical)
//   known const without either                   → missing immutability (critical)
//   flags register not resolvable                → medium-confidence finding

package pipeline

import (
	"strconv"
	"strings"

	"mega-analyzer/pkg/internal/types"
)

const (
	piFlagImmutable int64 = 0x04000000 // PendingIntent.FLAG_IMMUTABLE (API 23+)
	piFlagMutable   int64 = 0x02000000 // PendingIntent.FLAG_MUTABLE   (API 31+)
)

// piFactoryMethods are the PendingIntent factory entry points whose `flags`
// parameter governs mutability.
var piFactoryMethods = map[string]bool{
	"getActivity":   true,
	"getActivities": true,
	"getService":    true,
	"getBroadcast":  true,
}

func detectPendingIntentFromAST(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	class := ctx.Class
	if class == nil {
		return
	}
	for i := range class.Methods {
		detectPendingIntentInMethod(&class.Methods[i], class, analysis)
	}
}

func detectPendingIntentInMethod(m *types.SmaliMethod, class *types.SmaliClass, analysis *types.FileAnalysis) {
	if len(m.Body) == 0 {
		return
	}

	// Integer-constant provenance per register.
	ints := make(map[string]int64, 16)

	for bodyIdx, raw := range m.Body {
		line := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
		if line == "" || strings.HasPrefix(line, ".") || strings.HasPrefix(line, ":") {
			continue
		}
		lineNumber := m.LineStart + bodyIdx

		if strings.HasPrefix(line, "invoke-") {
			call, ok := parseCryptoInvoke(line) // same `{regs}, Lclass;->method` shape
			if !ok {
				continue
			}
			if call.classDesc == "Landroid/app/PendingIntent;" && piFactoryMethods[call.method] {
				evalPendingIntentCallSite(call, ints, m, class, analysis, lineNumber)
			}
			continue
		}

		// Non-invoke instruction: resolve destination register, then either
		// feed the constant tracker or invalidate stale values.
		dest := parseDestRegister(line)
		if dest == "" {
			continue
		}

		switch {
		case strings.HasPrefix(line, "const"):
			// const, const/4, const/16, const/high16 (wide variants excluded
			// below — flags are 32-bit ints and never live in wide pairs).
			if strings.HasPrefix(line, "const-wide") {
				delete(ints, dest)
				continue
			}
			if v, ok := parseSmaliIntOperand(line); ok {
				ints[dest] = v
			} else {
				delete(ints, dest)
			}

		case strings.HasPrefix(line, "or-int"):
			if v, ok := evalOrInt(line, ints); ok {
				ints[dest] = v
			} else {
				delete(ints, dest)
			}

		default:
			// Any other write (move*, move-result*, iget*, aget*, add-int*,
			// invoke result not yet landed, ...) makes prior constants stale.
			delete(ints, dest)
		}
	}
}

// evalPendingIntentCallSite resolves the `flags` parameter register of one
// PendingIntent factory call and emits a finding when immutability is absent.
func evalPendingIntentCallSite(
	call cryptoInvoke,
	ints map[string]int64,
	m *types.SmaliMethod,
	class *types.SmaliClass,
	analysis *types.FileAnalysis,
	lineNumber int,
) {
	flagsReg := pendingIntentFlagsRegister(call)
	if flagsReg == "" {
		return
	}

	emit := func(desc, evidence string, critical bool, confidence string) {
		match := newMatch(
			types.CategoryPendingIntentVuln, analysis.Path, lineNumber,
			desc, evidence, critical,
		)
		match.MethodName = m.Name
		match.ClassName = class.Name
		match.Confidence = confidence
		match.EvidenceType = "smali_ast_dataflow"
		if !critical {
			match.Severity = types.SeverityMedium
		}
		analysis.Matches = append(analysis.Matches, match)
	}

	flags, resolved := ints[flagsReg]
	switch {
	case resolved && flags&piFlagImmutable != 0:
		// Correct usage — explicitly immutable.
		return
	case resolved && flags&piFlagMutable != 0:
		emit("PendingIntent created with FLAG_MUTABLE — any app receiving this intent "+
			"can modify its extras/action before delivery (intent redirection, CWE-927). "+
			"Use FLAG_IMMUTABLE unless mutability is required (e.g. inline reply)",
			"PendingIntent;->"+call.method+" FLAG_MUTABLE", true, "high")
	case resolved:
		emit("PendingIntent created without FLAG_IMMUTABLE (flags=0x"+
			strconv.FormatInt(flags, 16)+") — the mutable intent can be intercepted and "+
			"rewritten by malicious apps (CWE-927). Required on API 31+",
			"PendingIntent;->"+call.method+" missing FLAG_IMMUTABLE", true, "high")
	default:
		emit("PendingIntent created with a flags value that cannot be resolved to a "+
			"constant — verify FLAG_IMMUTABLE is set (mutable intents are exploitable, CWE-927)",
			"PendingIntent;->"+call.method+" unresolved flags", false, "medium")
	}
}

// pendingIntentFlagsRegister maps the `flags` parameter of the invoked
// factory signature to its register in the invoke list.
func pendingIntentFlagsRegister(call cryptoInvoke) string {
	// Extract the parameter descriptor list from the raw target text.
	open := strings.IndexByte(call.raw, '(')
	if open < 0 {
		return ""
	}
	params := splitDexParams(call.raw[open+1:])

	// Locate the LAST int parameter (the flags argument is the only trailing
	// `I` in every factory overload).
	flagIdx := -1
	for i, p := range params {
		if p == "I" {
			flagIdx = i
		}
	}
	if flagIdx < 0 || flagIdx >= len(call.registers) {
		return ""
	}
	return call.registers[flagIdx]
}

// splitDexParams splits a dex parameter descriptor list like
// `Landroid/content/Context;I[Landroid/content/Intent;` into single params.
func splitDexParams(s string) []string {
	var out []string
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == 'L':
			end := strings.IndexByte(s[i:], ';')
			if end < 0 {
				return out
			}
			out = append(out, s[i:i+end+1])
			i += end + 1
		case c == '[':
			j := i
			for j < len(s) && s[j] == '[' {
				j++
			}
			if j < len(s) && s[j] == 'L' {
				end := strings.IndexByte(s[j:], ';')
				if end < 0 {
					return out
				}
				out = append(out, s[i:j+end+1])
				i = j + end + 1
			} else if j < len(s) {
				out = append(out, s[i:j+1])
				i = j + 1
			} else {
				return out
			}
		default:
			out = append(out, string(c))
			i++
		}
	}
	return out
}

// parseSmaliIntOperand parses the trailing constant of `const* vX, VALUE`.
func parseSmaliIntOperand(line string) (int64, bool) {
	comma := strings.LastIndexByte(line, ',')
	if comma < 0 {
		return 0, false
	}
	tok := strings.TrimSpace(line[comma+1:])
	tok = strings.TrimSuffix(tok, "L")
	v, err := strconv.ParseInt(tok, 0, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// evalOrInt evaluates or-int constant propagation:
// `or-int vA, vB, vC`, `or-int/2addr vA, vB`, `or-int/lit8|lit16 vA, vB, LIT`.
func evalOrInt(line string, ints map[string]int64) (int64, bool) {
	comma := strings.IndexByte(line, ',')
	if comma < 0 {
		return 0, false
	}
	op := strings.Fields(line[:comma])[0]
	rest := strings.Split(line[comma+1:], ",")
	for i := range rest {
		rest[i] = strings.TrimSpace(rest[i])
	}

	switch {
	case strings.HasSuffix(op, "/lit8"), strings.HasSuffix(op, "/lit16"):
		if len(rest) != 2 {
			return 0, false
		}
		src, ok1 := ints[rest[0]]
		lit, err := strconv.ParseInt(strings.TrimSuffix(rest[1], "L"), 0, 64)
		if !ok1 || err != nil {
			return 0, false
		}
		return src | lit, true
	case strings.HasSuffix(op, "/2addr"):
		if len(rest) != 1 {
			return 0, false
		}
		// Destination doubles as first operand.
		dest := strings.Fields(line[:comma])[1]
		a, ok1 := ints[dest]
		b, ok2 := ints[rest[0]]
		if !ok1 || !ok2 {
			return 0, false
		}
		return a | b, true
	default:
		if len(rest) != 2 {
			return 0, false
		}
		a, ok1 := ints[rest[0]]
		b, ok2 := ints[rest[1]]
		if !ok1 || !ok2 {
			return 0, false
		}
		return a | b, true
	}
}
