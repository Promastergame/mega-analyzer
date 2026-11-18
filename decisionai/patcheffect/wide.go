package patcheffect

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"decisionai/engine"
)

var wideRE = regexp.MustCompile(`^(\s*)(const-wide(?:/16|/32)?)\s+([vp]\d+)\s*,\s*(-?(?:0x[0-9a-fA-F]+|\d+))([lL]?)(\s*#.*)?$`)

func sha(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func parseInt64(s string) (int64, error) {
	neg := strings.HasPrefix(s, "-")
	t := strings.TrimPrefix(s, "-")
	base := 10
	if strings.HasPrefix(t, "0x") || strings.HasPrefix(t, "0X") {
		base, t = 16, t[2:]
	}
	u, err := strconv.ParseUint(t, base, 64)
	if err != nil {
		return 0, err
	}
	if neg {
		return -int64(u), nil
	}
	return int64(u), nil
}

func hexLit(v int64) string {
	if v < 0 {
		return "-0x" + strconv.FormatUint(uint64(-v), 16)
	}
	return "0x" + strconv.FormatInt(v, 16)
}

// isWideLine reports whether the selected line is a const-wide (long) literal.
func isWideLine(code string, line int) bool {
	ls := strings.Split(code, "\n")
	return line >= 1 && line <= len(ls) && wideRE.MatchString(strings.TrimRight(ls[line-1], "\r"))
}

// planWide rewrites one const-wide literal, choosing the narrowest encoding (/16, /32, or full 64-bit).
// const-wide/high16 is not handled (it encodes doubles/high bits and needs a different rewrite).
func planWide(code string, line int, expected, replacement int64) (*engine.PatchPlan, error) {
	ls := strings.Split(code, "\n")
	if line < 1 || line > len(ls) {
		return nil, fmt.Errorf("patch line outside method")
	}
	raw := ls[line-1]
	cr := ""
	if strings.HasSuffix(raw, "\r") {
		raw, cr = strings.TrimSuffix(raw, "\r"), "\r"
	}
	m := wideRE.FindStringSubmatch(raw)
	if m == nil {
		return nil, fmt.Errorf("not a const-wide, const-wide/16 or const-wide/32 line")
	}
	before, err := parseInt64(m[4])
	if err != nil || before != expected {
		return nil, fmt.Errorf("expected literal mismatch (stale candidate)")
	}
	if before == replacement {
		return nil, fmt.Errorf("no-op patch")
	}
	op := "const-wide"
	switch {
	case replacement >= -32768 && replacement <= 32767:
		op = "const-wide/16"
	case replacement >= -2147483648 && replacement <= 2147483647:
		op = "const-wide/32"
	}
	newLine := m[1] + op + " " + m[3] + ", " + hexLit(replacement) + m[5] + m[6]
	ls[line-1] = newLine + cr
	patched := strings.Join(ls, "\n")
	plan := &engine.PatchPlan{
		Original: code, Patched: patched, OriginalHash: sha(code), PatchedHash: sha(patched),
		Diff:   fmt.Sprintf("@@ line %d @@\n-%s\n+%s", line, raw, newLine),
		Before: before, After: replacement, Delta: replacement - before,
		Validation: engine.ValidateSmali(patched), Build: "not_run", Runtime: "not_run", CanApply: false,
	}
	if before != 0 {
		pct := 100 * float64(plan.Delta) / float64(before)
		plan.Percent = &pct
	}
	plan.Explanation = fmt.Sprintf("Long-литерал %d → %d (%s → %s); разница %+d. Регистровая пара %s/%s сохранена.", before, replacement, m[2], op, plan.Delta, m[3], m[3][:1]+strconv.Itoa(atoi(m[3][1:])+1))
	return plan, nil
}

func atoi(s string) int { n, _ := strconv.Atoi(s); return n }
