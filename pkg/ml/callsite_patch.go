package ml

import (
	"fmt"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// CALL-SITE PATCHING
//
// Sometimes patching the callee is the wrong move: the security method lives in
// a shared library, is called from many places with different expectations, or
// is verified by an integrity check of its own bytecode. In those cases it is
// safer to neutralise a specific *call site* in the caller — replace the
// `invoke ...; move-result vX` pair with a constant, leaving the rest of the
// caller untouched.
//
// This file provides a self-contained, testable utility. It does not require a
// full cross-method model: the caller passes the caller's body and the callee
// signature (or a substring of it) to target.
// ═══════════════════════════════════════════════════════════════════════════════

// CallSitePatchResult describes what a call-site rewrite changed.
type CallSitePatchResult struct {
	PatchedBody []string // rewritten caller body
	Sites       int      // number of call sites neutralised
}

// CallSiteOverride controls how a matched call site is neutralised.
type CallSiteOverride struct {
	// Match is a substring of the invoke line identifying the target callee,
	// e.g. "RootBeer;->isRooted". Matching is case-sensitive and literal.
	Match string
	// BoolValue is the constant written into the call's move-result register
	// when the call returns a boolean/int (0 or 1). Ignored for void calls.
	BoolValue int
}

// PatchCallSite rewrites every invocation of the targeted callee in the caller
// body. For a call that produces a value (`invoke ...; move-result vX`) it drops
// the invoke and replaces the move-result with a constant in the same register,
// preserving the register file. For a void call it simply drops the invoke.
//
// The rewrite is verifier-safe: it never leaves a dangling move-result, and it
// keeps every non-matching instruction exactly as-is.
func PatchCallSite(body []string, override CallSiteOverride) (CallSitePatchResult, error) {
	if strings.TrimSpace(override.Match) == "" {
		return CallSitePatchResult{}, fmt.Errorf("call-site match pattern is empty")
	}
	out := make([]string, 0, len(body))
	sites := 0

	for i := 0; i < len(body); i++ {
		line := body[i]
		trimmed := strings.TrimSpace(line)

		isInvoke := strings.HasPrefix(trimmed, "invoke-")
		if !isInvoke || !strings.Contains(trimmed, override.Match) {
			out = append(out, line)
			continue
		}

		// Matched the target call. Look ahead (skipping blanks/comments) for a
		// paired move-result that consumes its result.
		next, nextIdx := nextMeaningfulLine(body, i+1)
		if next != "" && strings.HasPrefix(strings.TrimSpace(next), "move-result") {
			reg, ok := moveResultRegister(strings.TrimSpace(next))
			if ok {
				out = append(out, indentLike(line)+constForRegister(reg, override.BoolValue))
				sites++
				i = nextIdx // consume both invoke and move-result
				continue
			}
		}

		// Void call (or unrecognised result form): just drop the invoke.
		sites++
	}

	if sites == 0 {
		return CallSitePatchResult{}, fmt.Errorf("no call site matched %q", override.Match)
	}
	return CallSitePatchResult{PatchedBody: out, Sites: sites}, nil
}

// nextMeaningfulLine returns the next non-blank, non-comment line at or after
// start, together with its index. Returns ("", -1) when none remains.
func nextMeaningfulLine(body []string, start int) (string, int) {
	for j := start; j < len(body); j++ {
		t := strings.TrimSpace(body[j])
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		return body[j], j
	}
	return "", -1
}

// moveResultRegister extracts vX from a move-result / move-result-object /
// move-result-wide instruction.
func moveResultRegister(trimmed string) (string, bool) {
	fields := strings.Fields(trimmed)
	if len(fields) != 2 || !strings.HasPrefix(fields[0], "move-result") {
		return "", false
	}
	if strings.HasPrefix(fields[1], "v") || strings.HasPrefix(fields[1], "p") {
		return fields[1], true
	}
	return "", false
}

// indentLike returns the leading whitespace of a line so injected instructions
// line up with the surrounding code.
func indentLike(line string) string {
	return line[:len(line)-len(strings.TrimLeft(line, " \t"))]
}
