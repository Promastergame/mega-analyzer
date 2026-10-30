package ml

import (
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// BODY-PRESERVING PATCH BUILDER
//
// The whole-body stub (buildStubMethodSmart) DISCARDS the original instructions —
// it emits a fresh header + `.locals` + a single return. That "gut the method"
// behaviour drops side effects (logging, metrics, lazy init, field writes) and,
// for object factories mislabeled as return_void, force-returns null and crashes
// the caller.
//
// This builder is the least-destructive alternative: whenever the real method
// body is available it PATCHES IN PLACE and keeps every original instruction.
//   - void method, return_void  → inject `return-void` as the first instruction
//     (the rest of the body stays, physically present but unreached).
//   - primitive value return    → force the returned register in place via
//     overrideReturnsSafe (the proven offset-safe engine), side effects intact.
//   - anything else (objects/arrays/wide, or an incoherent return_void on a
//     value-returning method) → preserve the method verbatim rather than gut it
//     to a crash-prone null.
//
// It satisfies the hard contract "патчить что-то, а не ПОЛНОСТЬЮ удалять": the
// body is never thrown away when we actually have it.
// ═══════════════════════════════════════════════════════════════════════════════

// buildBodyPreservingPatch produces patched smali that keeps the original body.
// ok=false means no usable body was available (signature-only point), so the
// caller should fall back to a whole-body stub.
func buildBodyPreservingPatch(body []string, rt string, kind returnKind) (string, bool) {
	if !hasExecutableBody(body) {
		return "", false
	}

	switch {
	case kind == kindVoid && rt == "V":
		// Genuine void method: neutralise it with an early return-void, keeping
		// the whole body. Offset-safe (see injectEarlyReturnVoid).
		return injectEarlyReturnVoid(body), true

	case isPrimitiveValueReturn(rt):
		// Primitive result: force it in place, preserving side effects. If the
		// requested kind has no coherent primitive value (e.g. a return_void
		// mislabel landed on an int getter), or there is no `return vX` site to
		// override, keep the method verbatim rather than gut it.
		v, ok := forcedPrimitiveValue(kind, rt)
		if !ok {
			return joinMethodBody(body), true
		}
		out, count, _ := overrideReturnsSafe(body, v)
		if count == 0 {
			return joinMethodBody(body), true
		}
		return strings.TrimRight(out, "\n"), true

	case kind == kindZero && (strings.TrimSpace(rt) == "J" || strings.TrimSpace(rt) == "D"):
		// Wide zero (free price): const-wide 0 is always encodable, unlike
		// MAX which needs relayout analysis. Require full coverage — a
		// partially zeroed price is unpredictable, verbatim is honest.
		sites := 0
		for _, line := range body {
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) == 2 && fields[0] == "return-wide" { sites++ }
		}
		out, count, _ := overrideWideReturnsSafe(body, 0)
		if sites == 0 || count != sites {
			return joinMethodBody(body), true
		}
		return strings.TrimRight(out, "\n"), true

	default:
		// Object/array/wide return, or return_void requested on a non-void
		// method (scorer mislabel). There is no offset-safe, crash-free way to
		// FORCE such a return without discarding the body, and nulling a real
		// factory return (View/Message/AdSessionContext/…) crashes its callers.
		// Preserve the method verbatim.
		return joinMethodBody(body), true
	}
}

// injectEarlyReturnVoid returns the method with `return-void` inserted as the
// first executable instruction, preserving the ENTIRE original body verbatim
// (header, `.registers`/`.locals`/`.param`/… directives, and every instruction).
// The method becomes an immediate no-op while its instructions stay physically
// present — "patch, don't delete".
//
// Offset-safety: the inserted `return-void` takes code-unit offset 0, so every
// original instruction shifts uniformly by +1 unit. Dalvik branch deltas are
// RELATIVE, so both endpoints of every branch (and every switch/array payload
// and try/catch range) move together and each delta stays valid with no
// recompute — strictly safer than a mid-body insert.
func injectEarlyReturnVoid(body []string) string {
	insertAt := -1
	indent := "    "
	for i, line := range body {
		if _, ok := insnLine(strings.TrimSpace(line)); ok {
			insertAt = i
			if lead := leadingWhitespace(line); lead != "" {
				indent = lead
			}
			break
		}
	}
	if insertAt < 0 {
		// No executable instruction (already trivial): insert before .end method.
		insertAt = endMethodIndex(body)
	}

	out := make([]string, 0, len(body)+1)
	out = append(out, body[:insertAt]...)
	out = append(out, indent+"return-void")
	out = append(out, body[insertAt:]...)
	return strings.TrimRight(strings.Join(out, "\n"), "\n")
}

// hasExecutableBody reports whether body carries at least one real instruction
// (not just a header/directives). A signature-only point has none, so the caller
// must synthesise a stub instead.
func hasExecutableBody(body []string) bool {
	for _, line := range body {
		if _, ok := insnLine(strings.TrimSpace(line)); ok {
			return true
		}
	}
	return false
}

// joinMethodBody renders the body lines back to a single smali string with no
// trailing blank line.
func joinMethodBody(body []string) string {
	return strings.TrimRight(strings.Join(body, "\n"), "\n")
}

// endMethodIndex returns the index of the `.end method` line, or len(body) if
// absent.
func endMethodIndex(body []string) int {
	for i, line := range body {
		if strings.HasPrefix(strings.TrimSpace(line), ".end method") {
			return i
		}
	}
	return len(body)
}

// leadingWhitespace returns the leading spaces/tabs of a line.
func leadingWhitespace(line string) string {
	return line[:len(line)-len(strings.TrimLeft(line, " \t"))]
}

// isPrimitiveValueReturn reports whether rt is a single 32-bit primitive that
// overrideReturnsSafe can force through a plain `return vX`. Float (F) is
// excluded on purpose: forcing an integer bit-pattern into a float return is
// semantically wrong, so those are preserved verbatim instead. Wide (J/D) and
// objects are likewise excluded.
func isPrimitiveValueReturn(rt string) bool {
	switch strings.TrimSpace(rt) {
	case "Z", "I", "S", "B", "C", "F":
		return true
	}
	return false
}

// forcedPrimitiveValue maps a return kind to the 32-bit value to force for a
// primitive return. ok=false when the kind has no coherent primitive value
// (e.g. kindVoid landing on an int getter via a scorer mislabel) — the caller
// then preserves the method verbatim rather than inventing a value.
// Float is type-aware: integer MAX bits decode as NaN, so F gets Float.MAX.
func forcedPrimitiveValue(kind returnKind, rt string) (int32, bool) {
	switch kind {
	case kindTrue:
		return 1, true
	case kindFalse:
		return 0, true
	case kindZero:
		return 0, true
	case kindMaxInt:
		if strings.TrimSpace(rt) == "F" {
			return 0x7f7fffff, true
		}
		return 0x7fffffff, true
	case kindDefault:
		// No coherent forced value: kindDefault is the "neutral" intent
		// (const_replace, unknown patch types). Forcing MAX here once
		// corrupted int returns (const_replace produced 0x7fffffff).
		// The caller preserves the method verbatim instead.
		return 0, false
	default: // kindVoid on a value return is incoherent
		return 0, false
	}
}
