package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

var registerRE = regexp.MustCompile(`^[vp][0-9]+$`)
var constantRE = regexp.MustCompile(`^(const/4|const/16|const)\s+([vp]\d+)\s*,\s*([^\s]+)$`)

// Strip comments and mask strings without confusing '#' inside quoted strings.
func clean(s string) string {
	var b strings.Builder
	quote, esc := false, false
	for _, c := range s {
		if quote {
			if esc {
				esc = false
			} else if c == '\\' {
				esc = true
			} else if c == '"' {
				quote = false
			}
			b.WriteRune(' ')
			continue
		}
		if c == '#' {
			break
		}
		if c == '"' {
			quote = true
			b.WriteRune(' ')
		} else {
			b.WriteRune(c)
		}
	}
	return strings.TrimSpace(b.String())
}
func params(header string) (int, error) {
	i, j := strings.Index(header, "("), strings.Index(header, ")")
	if i < 0 || j < i || j+1 >= len(header) {
		return 0, fmt.Errorf("malformed method descriptor")
	}
	s := header[i+1 : j]
	n := 0
	if !strings.Contains(" "+header+" ", " static ") {
		n++
	}
	for k := 0; k < len(s); {
		array := false
		for k < len(s) && s[k] == '[' {
			array = true
			k++
		}
		if k >= len(s) {
			return 0, fmt.Errorf("malformed array descriptor")
		}
		switch s[k] {
		case 'L':
			end := strings.IndexByte(s[k:], ';')
			if end < 2 {
				return 0, fmt.Errorf("malformed object descriptor")
			}
			k += end + 1
			n++
		case 'J', 'D':
			k++
			if array {
				n++
			} else {
				n += 2
			}
		case 'Z', 'B', 'S', 'C', 'I', 'F':
			k++
			n++
		default:
			return 0, fmt.Errorf("malformed parameter descriptor")
		}
	}
	return n, nil
}
func methodBudget(lines []string) (int, int, error) {
	header := ""
	methods := 0
	ends := 0
	budget := -1
	locals := false
	directives := 0
	for _, raw := range lines {
		l := clean(raw)
		if strings.HasPrefix(l, ".method ") {
			header = l
			methods++
		}
		if l == ".end method" {
			ends++
		}
		f := strings.Fields(l)
		if len(f) > 0 && (f[0] == ".registers" || f[0] == ".locals") {
			directives++
			if len(f) != 2 {
				return 0, 0, fmt.Errorf("malformed register directive")
			}
			v, e := strconv.Atoi(f[1])
			if e != nil || v < 0 || v > 65535 {
				return 0, 0, fmt.Errorf("invalid register budget")
			}
			budget = v
			locals = f[0] == ".locals"
		}
	}
	if methods != 1 || ends != 1 {
		return 0, 0, fmt.Errorf("expected exactly one complete .method/.end method")
	}
	p, e := params(header)
	if e != nil {
		return 0, 0, e
	}
	if directives != 1 {
		return 0, 0, fmt.Errorf("expected one .registers or .locals directive")
	}
	if locals {
		budget += p
	}
	if budget < p || budget > 65535 {
		return 0, 0, fmt.Errorf("register budget incompatible with parameters")
	}
	return budget, p, nil
}
func physical(r string, budget, p int) (int, error) {
	n, e := strconv.Atoi(r[1:])
	if e != nil {
		return 0, e
	}
	if r[0] == 'p' {
		if n >= p {
			return 0, fmt.Errorf("parameter %s outside descriptor", r)
		}
		n = budget - p + n
	}
	if n < 0 || n >= budget {
		return 0, fmt.Errorf("register %s outside budget %d", r, budget)
	}
	return n, nil
}

// ValidateSmali is a partial preflight, NOT a Dalvik verifier or assembler.
func ValidateSmali(code string) Check {
	out := Check{Status: "preflight_pass", Issues: []string{}}
	ls := strings.Split(strings.ReplaceAll(code, "\r\n", "\n"), "\n")
	b, p, e := methodBudget(ls)
	if e != nil {
		out.Status = "fail"
		out.Issues = append(out.Issues, e.Error())
		return out
	}
	for i, raw := range ls {
		l := clean(raw)
		if l == "" || strings.HasPrefix(l, ".") || strings.HasPrefix(l, ":") {
			continue
		}
		for _, operand := range strings.FieldsFunc(l, func(c rune) bool { return c == ' ' || c == '\t' || c == ',' || c == '{' || c == '}' }) {
			if !registerRE.MatchString(operand) {
				continue
			}
			if _, e := physical(operand, b, p); e != nil {
				out.Issues = append(out.Issues, fmt.Sprintf("line %d: %v", i+1, e))
			}
		}
		if strings.HasPrefix(l, "const/4 ") || strings.HasPrefix(l, "const/16 ") || strings.HasPrefix(l, "const ") {
			m := constantRE.FindStringSubmatch(l)
			if m == nil {
				out.Issues = append(out.Issues, fmt.Sprintf("line %d: malformed const", i+1))
				continue
			}
			n, e := integer(m[3])
			r, re := physical(m[2], b, p)
			if e != nil || n < -2147483648 || n > 2147483647 {
				out.Issues = append(out.Issues, fmt.Sprintf("line %d: invalid signed int32 literal", i+1))
			} else if re == nil {
				bad := m[1] == "const/4" && (n < -8 || n > 7 || r > 15) || m[1] == "const/16" && (n < -32768 || n > 32767 || r > 255) || m[1] == "const" && r > 255
				if bad {
					out.Issues = append(out.Issues, fmt.Sprintf("line %d: constant/register does not fit %s", i+1, m[1]))
				}
			}
		}
	}
	if len(out.Issues) > 0 {
		out.Status = "fail"
	}
	return out
}
func Features(r Request) map[string]float64 {
	f := map[string]float64{}
	for _, n := range FeatureNames {
		f[n] = 0
	}
	ls := strings.Split(r.Code, "\n")
	b, _, _ := methodBudget(ls)
	f["register_budget"] = float64(b) / 256
	for _, raw := range ls {
		l := clean(raw)
		if l == "" || strings.HasPrefix(l, ".") || strings.HasPrefix(l, ":") {
			continue
		}
		op := strings.Fields(l)[0]
		f["instructions"] += 1.0 / 128
		if strings.HasPrefix(op, "invoke-") {
			f["invokes"] += 1.0 / 32
		}
		if strings.HasPrefix(op, "if-") || strings.HasPrefix(op, "goto") || strings.Contains(op, "switch") {
			f["branches"] += 1.0 / 32
		}
		if strings.HasPrefix(op, "const") {
			f["constants"] += 1.0 / 32
		}
		if strings.HasPrefix(op, "return") {
			f["returns"] += 1.0 / 8
		}
	}
	f["evidence_count"] = float64(len(r.Meta.Evidence)) / 8
	if r.Meta.AppOwned {
		f["app_owned"] = 1
	}
	if r.Meta.Library {
		f["library"] = 1
	}
	if r.Meta.ServerDependency {
		f["server_dependency"] = 1
	}
	if r.Patch != nil {
		f["patch_requested"] = 1
		f["patch_delta_ratio"] = math.Abs(float64(r.Patch.Replacement)-float64(r.Patch.Expected)) / math.Max(1, math.Abs(float64(r.Patch.Expected))) / 10
		f["patch_replacement_scale"] = math.Abs(float64(r.Patch.Replacement)) / 2147483648
		if plan, err := PlanPatch(r.Code, *r.Patch); err == nil && plan.Validation.Status != "fail" {
			f["patch_preflight_ok"] = 1
			oldLines, newLines := strings.Split(r.Code, "\n"), strings.Split(plan.Patched, "\n")
			oldOp, newOp := strings.Fields(oldLines[r.Patch.Line-1])[0], strings.Fields(newLines[r.Patch.Line-1])[0]
			if oldOp != newOp {
				f["patch_widened_opcode"] = 1
			}
		}
	}
	for k, v := range f {
		if v < 0 {
			v = 0
		}
		if v > 1 {
			v = 1
		}
		f[k] = v
	}
	return f
}
func hash(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func PlanPatch(code string, pr PatchRequest) (*PatchPlan, error) {
	if ValidateSmali(code).Status == "fail" {
		return nil, fmt.Errorf("original failed preflight; repair explicitly before planning")
	}
	ls := strings.Split(code, "\n")
	if pr.Line < 1 || pr.Line > len(ls) {
		return nil, fmt.Errorf("patch line outside method")
	}
	raw := strings.TrimSuffix(ls[pr.Line-1], "\r")
	ending := ""
	if strings.HasSuffix(ls[pr.Line-1], "\r") {
		ending = "\r"
	}
	m := constantRE.FindStringSubmatch(clean(raw))
	if m == nil {
		return nil, fmt.Errorf("only an explicitly selected const/4, const/16 or const is supported")
	}
	before, e := integer(m[3])
	if e != nil || before != pr.Expected {
		return nil, fmt.Errorf("expected literal mismatch (stale candidate)")
	}
	if before == pr.Replacement {
		return nil, fmt.Errorf("no-op patch")
	}
	if pr.Replacement < -2147483648 || pr.Replacement > 2147483647 {
		return nil, fmt.Errorf("replacement must fit signed int32")
	}
	b, p, _ := methodBudget(ls)
	reg, e := physical(m[2], b, p)
	if e != nil || reg > 255 {
		return nil, fmt.Errorf("target register cannot be encoded without a wider rewrite")
	}
	op := "const"
	if pr.Replacement >= -8 && pr.Replacement <= 7 && reg <= 15 {
		op = "const/4"
	} else if pr.Replacement >= -32768 && pr.Replacement <= 32767 {
		op = "const/16"
	}
	indent := raw[:len(raw)-len(strings.TrimLeft(raw, " \t"))]
	replacement := indent + op + " " + m[2] + ", " + strconv.FormatInt(pr.Replacement, 10)
	comment := commentSuffix(raw)
	if comment != "" {
		replacement += " " + comment
	}
	ls[pr.Line-1] = replacement + ending
	patched := strings.Join(ls, "\n")
	plan := &PatchPlan{Original: code, Patched: patched, OriginalHash: hash(code), PatchedHash: hash(patched), Diff: fmt.Sprintf("@@ line %d @@\n-%s\n+%s", pr.Line, raw, replacement), Before: before, After: pr.Replacement, Delta: pr.Replacement - before, Validation: ValidateSmali(patched), Build: "not_run", Runtime: "not_run", CanApply: false}
	if before != 0 {
		pct := 100 * float64(plan.Delta) / float64(before)
		plan.Percent = &pct
	}
	plan.Explanation = fmt.Sprintf("Литерал %d → %d; разница %+d. Назначение и эффект поведения не установлены.", before, pr.Replacement, plan.Delta)
	if pr.Target != "" {
		plan.Explanation += " Заявленная пользователем цель: " + pr.Target + " (не подтверждена анализом потока данных)."
	}
	if before < 0 {
		plan.Explanation += " Процент — арифметическое отношение к отрицательному исходному значению, не рост поведения."
	}
	return plan, nil
}
func commentSuffix(s string) string {
	quote, esc := false, false
	for i, c := range s {
		if quote {
			if esc {
				esc = false
			} else if c == '\\' {
				esc = true
			} else if c == '"' {
				quote = false
			}
			continue
		}
		if c == '"' {
			quote = true
		} else if c == '#' {
			return s[i:]
		}
	}
	return ""
}
