package ml

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// OFFSET-SAFE RETURN OVERRIDE ENGINE
//
// The analyzer's own disassembler emits smali with RAW NUMERIC branch offsets
// (code-unit relative), e.g. `if-eqz v0, +4`, `goto +2`, `goto/16 -216` — NOT
// baksmali labels. That format is reassembled directly at the DEX level, so the
// numeric offset written in the text IS the branch target: it must stay correct
// for the patched instruction layout.
//
// The previous injection strategies inserted a `const vX, N` before every
// `return vX`. That is fine for a branchless method, but any method that
// contains numeric branches has its control flow SILENTLY CORRUPTED: inserting
// a code unit shifts every instruction after it, yet the branch deltas were left
// untouched, so `if-eqz v0, +4` now lands one slot short. It also produced dead
// `const v0, 1` / `const v0, 0x1` pairs when the return was already fed by a
// const.
//
// This engine forces every `return vX` to a fixed value using the least
// destructive edit that keeps offsets valid, in three tiers:
//
//	(a) IN-PLACE literal swap — if the return value is produced by an
//	    immediately-preceding const that can hold the target value at its
//	    current opcode width, we just change the literal. Size-neutral: offsets
//	    are untouched. Handles the classic dual-return boolean idiom. If that
//	    const cannot hold the value (e.g. a `const/4 v1, 4` forced to MAX_INT),
//	    we WIDEN it in place to a `const vX, value` instead of leaving a dead
//	    second const beside it, and recompute offsets for the size change.
//
//	(b) SINGLE-DEF literal swap — if the returned register is written by exactly
//	    one const in the whole method and is otherwise read only by `return`,
//	    we flip that single def (or widen it, as in (a)). It collapses several
//	    return sites into one clean edit (e.g. an early `const v1,0` feeding two
//	    `return v1`).
//
//	(c) INSERT + RECOMPUTE — otherwise (value from move-result/iget/…), we insert
//	    a `const vX, value` before the return and RECOMPUTE every numeric branch
//	    offset in the method so control flow stays valid. A branch that targeted
//	    the return is redirected onto the inserted const, so the forced value
//	    still applies. If the method mixes in an instruction we cannot size, an
//	    unaligned branch target, or an offset that would overflow its branch
//	    format, we abort the relayout (never corrupt) and report it.
//
// The result preserves every original instruction and side effect — this is a
// surgical override, never a whole-method stub.
// ═══════════════════════════════════════════════════════════════════════════════

// trailingOffsetRe captures the signed decimal branch offset at the end of a
// branch line (e.g. "+4", "-216"), preserving everything before it.
var trailingOffsetRe = regexp.MustCompile(`^(.*?)([+-]\d+)\s*$`)

// smaliUnits returns the size in 16-bit code units of a smali instruction given
// its mnemonic, and whether the size is known. Sizes are fixed by the Dalvik
// instruction format; unknown mnemonics return (0,false) so callers can refuse
// to recompute offsets rather than guess.
func smaliUnits(mnem string) (int, bool) {
	if u, ok := smaliUnitTable[mnem]; ok {
		return u, true
	}
	return 0, false
}

// smaliUnitTable maps every standard smali mnemonic to its code-unit size.
// Grouped by Dalvik format. Payload-bearing ops (packed-switch/sparse-switch/
// fill-array-data) are intentionally ABSENT: their true size depends on a data
// block, so a method containing them cannot be safely re-laid-out here and the
// engine falls back to size-neutral edits only.
var smaliUnitTable = func() map[string]int {
	m := map[string]int{}
	one := []string{
		"nop", "move", "move-wide", "move-object",
		"move-result", "move-result-wide", "move-result-object", "move-exception",
		"return-void", "return", "return-wide", "return-object",
		"const/4", "monitor-enter", "monitor-exit", "array-length", "throw", "goto",
		"neg-int", "not-int", "neg-long", "not-long", "neg-float", "neg-double",
		"int-to-long", "int-to-float", "int-to-double",
		"long-to-int", "long-to-float", "long-to-double",
		"float-to-int", "float-to-long", "float-to-double",
		"double-to-int", "double-to-long", "double-to-float",
		"int-to-byte", "int-to-char", "int-to-short",
	}
	for _, op := range one {
		m[op] = 1
	}
	// all /2addr binary ops are format 12x (1 unit)
	for _, base := range []string{"add", "sub", "mul", "div", "rem", "and", "or", "xor", "shl", "shr", "ushr"} {
		for _, ty := range []string{"int", "long", "float", "double"} {
			m[base+"-"+ty+"/2addr"] = 1
		}
	}
	two := []string{
		"move/from16", "move-wide/from16", "move-object/from16",
		"const/16", "const/high16", "const-wide/16", "const-wide/high16", "goto/16",
		"cmpl-float", "cmpg-float", "cmpl-double", "cmpg-double", "cmp-long",
		"if-eq", "if-ne", "if-lt", "if-ge", "if-gt", "if-le",
		"if-eqz", "if-nez", "if-ltz", "if-gez", "if-gtz", "if-lez",
		"check-cast", "instance-of", "new-instance", "new-array",
		"const-string", "const-class", "const-method-handle", "const-method-type",
	}
	for _, op := range two {
		m[op] = 2
	}
	// static/instance field accessors (21c/22c) = 2 units
	for _, kind := range []string{"sget", "sput", "iget", "iput"} {
		for _, suf := range []string{"", "-wide", "-object", "-boolean", "-byte", "-char", "-short"} {
			m[kind+suf] = 2
		}
	}
	// array accessors (23x) = 2 units
	for _, kind := range []string{"aget", "aput"} {
		for _, suf := range []string{"", "-wide", "-object", "-boolean", "-byte", "-char", "-short"} {
			m[kind+suf] = 2
		}
	}
	// three-address binary ops (23x) = 2 units
	for _, base := range []string{"add", "sub", "mul", "div", "rem", "and", "or", "xor", "shl", "shr", "ushr"} {
		for _, ty := range []string{"int", "long", "float", "double"} {
			m[base+"-"+ty] = 2
		}
	}
	// literal binary ops (22s/22b) = 2 units
	for _, base := range []string{"add", "rsub", "mul", "div", "rem", "and", "or", "xor", "shl", "shr", "ushr"} {
		m[base+"-int/lit16"] = 2
		m[base+"-int/lit8"] = 2
	}
	m["rsub-int"] = 2 // rsub-int (/lit16 form is written "rsub-int")
	three := []string{
		"const", "const-wide/32", "const-string/jumbo", "goto/32",
		"move/16", "move-wide/16", "move-object/16",
		"invoke-virtual", "invoke-super", "invoke-direct", "invoke-static", "invoke-interface",
		"invoke-virtual/range", "invoke-super/range", "invoke-direct/range",
		"invoke-static/range", "invoke-interface/range",
		"invoke-custom", "invoke-custom/range",
		"filled-new-array", "filled-new-array/range",
	}
	for _, op := range three {
		m[op] = 3
	}
	m["const-wide"] = 5 // 51l
	return m
}()

// branchRange returns the inclusive [min,max] delta (in code units) encodable by
// a branch mnemonic, and whether the mnemonic is a recognised branch. Used to
// guard against an insertion pushing an offset past its format's range.
func branchRange(mnem string) (int, int, bool) {
	switch mnem {
	case "goto": // 10t, signed 8-bit
		return -128, 127, true
	case "goto/16", // 20t, signed 16-bit
		"if-eq", "if-ne", "if-lt", "if-ge", "if-gt", "if-le", // 22t
		"if-eqz", "if-nez", "if-ltz", "if-gez", "if-gtz", "if-lez": // 21t
		return -32768, 32767, true
	case "goto/32": // 30t, signed 32-bit
		return -2147483648, 2147483647, true
	}
	return 0, 0, false
}

// insnLine reports whether a trimmed smali line is a real instruction (not a
// directive, label, comment or blank) and returns its mnemonic.
func insnLine(trimmed string) (string, bool) {
	if trimmed == "" || strings.HasPrefix(trimmed, ".") ||
		strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ":") {
		return "", false
	}
	fields := strings.Fields(trimmed)
	if len(fields) == 0 {
		return "", false
	}
	return fields[0], true
}

// constDestRegister returns the destination register of a const-family
// instruction, e.g. "const/4 v0, 0x1" → ("v0", true). Non-const instructions
// return ("", false).
func constDestRegister(trimmed string) (string, bool) {
	fields := strings.Fields(trimmed)
	if len(fields) < 2 || !strings.HasPrefix(fields[0], "const") {
		return "", false
	}
	reg := strings.TrimSuffix(fields[1], ",")
	if strings.HasPrefix(reg, "v") || strings.HasPrefix(reg, "p") {
		return reg, true
	}
	return "", false
}

// constEncodes reports whether a const opcode can hold value without changing
// its byte size (so an in-place literal swap stays offset-neutral).
func constEncodes(opcode string, value int32) bool {
	switch opcode {
	case "const/4":
		return value >= -8 && value <= 7
	case "const/16", "const-wide/16":
		return value >= -32768 && value <= 32767
	case "const/high16":
		return value&0xFFFF == 0
	case "const", "const-wide/32":
		return true
	default:
		return false
	}
}

// constLiteralValue parses the trailing literal of a const-family instruction
// ("const/4 v0, 0x1c" → 28). Accepts signed decimal and hex. ok=false for
// anything unusual — the caller then just rewrites the line.
func constLiteralValue(trimmed string) (int32, bool) {
	fields := strings.Fields(trimmed)
	if len(fields) < 3 {
		return 0, false
	}
	n, err := strconv.ParseInt(fields[len(fields)-1], 0, 32)
	if err != nil {
		return 0, false
	}
	return int32(n), true
}

// fmtLiteral renders a 32-bit literal the way smali expects: positive as "0x…",
// negative as "-0x…" ("const/4 v0, -0x1", never "0xffffffff").
func fmtLiteral(v int32) string {
	if v < 0 {
		return "-0x" + strconv.FormatUint(uint64(-int64(v)), 16)
	}
	return "0x" + strconv.FormatUint(uint64(v), 16)
}

// chooseConstLine picks the narrowest const opcode that can load value into reg
// and returns the full instruction text plus its code-unit size.
// Returns ("", 0) when no const encoding can address reg (v256+ needs
// /16 move variants which const-family lacks) — callers must refuse the
// edit rather than emit invalid smali.
func chooseConstLine(reg string, value int32) (string, int) {
	if !regFitsConst(reg, value) {
		return "", 0
	}
	if value >= -8 && value <= 7 && regIndexLE15(reg) {
		return fmt.Sprintf("const/4 %s, %s", reg, fmtLiteral(value)), 1
	}
	if value >= -32768 && value <= 32767 {
		return fmt.Sprintf("const/16 %s, %s", reg, fmtLiteral(value)), 2
	}
	return fmt.Sprintf("const %s, %s", reg, fmtLiteral(value)), 3
}

// regIndex parses vN/pN → N, ok=false for malformed names.
func regIndex(reg string) (int, bool) {
	if len(reg) < 2 || (reg[0] != 'v' && reg[0] != 'p') {
		return 0, false
	}
	n := 0
	for _, c := range reg[1:] {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
		if n > 65535 {
			return 0, false
		}
	}
	return n, true
}

// regFitsConst reports whether a const-family instruction can encode reg.
// const/4: 4-bit (v0-v15). const/16 and const: 8-bit (v0-v255).
// p-registers alias v-slots, so the same limits apply to their numeric index.
func regFitsConst(reg string, value int32) bool {
	n, ok := regIndex(reg)
	if !ok {
		return false
	}
	if value >= -8 && value <= 7 {
		// narrowest would be const/4 — needs 4-bit
		if n <= 15 {
			return true
		}
		// else fall through to wider encodings (8-bit)
	}
	return n <= 255
}

// regTokenPresent reports whether register reg appears as a standalone token in
// a line (bounded by non-identifier chars), so "v1" does not match "v10".
func regTokenPresent(line, reg string) bool {
	idx := 0
	for {
		pos := strings.Index(line[idx:], reg)
		if pos < 0 {
			return false
		}
		pos += idx
		before := pos == 0 || !isRegIdentByte(line[pos-1])
		afterPos := pos + len(reg)
		after := afterPos >= len(line) || !isRegIdentByte(line[afterPos])
		if before && after {
			return true
		}
		idx = pos + 1
	}
}

func isRegIdentByte(b byte) bool {
	return b == '_' || (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

// retSite records a `return vX` line and how we decided to force it.
type retSite struct {
	lineIdx int    // index in body
	reg     string // returned register
	// resolution (exactly one is chosen per site):
	swapLineIdx   int  // >=0: swap the literal of the const at this body line (size-neutral)
	resizeLineIdx int  // >=0: replace the const at this body line with a wider/narrower one that can hold value
	noEdit        bool // true: the feeding const already holds value — leave the line untouched
	doInsert      bool // true: insert a const before the return
}

// overrideReturnsSafe forces every plain `return vX` in a method body to `value`
// while keeping the numeric branch offsets valid. It returns the rewritten
// smali, the number of return sites now guaranteed to yield value, and a note
// describing anything that had to be skipped (empty when fully clean).
//
// body is the full method text (`.method …` through `.end method`), matching
// MethodInfo.RawBody. value is the target 32-bit result (0/1 for booleans,
// 0x7fffffff for MAX_INT, …).
func overrideReturnsSafe(body []string, value int32) (string, int, string) {
	// ── Pass 1: locate return sites and their preceding meaningful instruction.
	sites := make([]*retSite, 0, 2)
	prevInsnIdx := straightLinePredecessors(body)
	for i, line := range body {
		trimmed := smaliCodeLine(line)
		if reg, ok := plainReturnRegister(trimmed); ok {
			sites = append(sites, &retSite{lineIdx: i, reg: reg, swapLineIdx: -1, resizeLineIdx: -1})
		}
	}
	if len(sites) == 0 {
		return strings.Join(body, "\n") + "\n", 0, ""
	}

	// ── Pass 2: tier (a) — immediate-predecessor const. If it can hold value at
	// its current width we swap the literal (size-neutral); if not, we widen it
	// in place (resize) — still surgical, never a dead second const.
	for _, s := range sites {
		p := prevInsnIdx[s.lineIdx]
		if p < 0 {
			continue
		}
		ptrim := strings.TrimSpace(body[p])
		if dreg, ok := constDestRegister(ptrim); ok && dreg == s.reg {
			if cur, lok := constLiteralValue(ptrim); lok && cur == value {
				s.noEdit = true // const already holds value — rewriting it would only churn the diff
			} else if constEncodes(strings.Fields(ptrim)[0], value) {
				s.swapLineIdx = p
			} else {
				s.resizeLineIdx = p
			}
		}
	}

	// ── Pass 2: tier (b) — single-def const for still-unresolved sites.
	// A register written by exactly one const and read only by `return` can be
	// forced at its definition — flipped in place if it fits, otherwise widened —
	// covering all its returns without any insert.
	for _, s := range sites {
		if s.noEdit || s.swapLineIdx >= 0 || s.resizeLineIdx >= 0 {
			continue
		}
		defIdx, opcode, ok := singleConstDefOnlyReturned(body, s.reg)
		if !ok || !entryDefinitionDominates(body, defIdx, s.lineIdx) {
			continue
		}
		if cur, lok := constLiteralValue(strings.TrimSpace(body[defIdx])); lok && cur == value {
			s.noEdit = true
		} else if constEncodes(opcode, value) {
			s.swapLineIdx = defIdx
		} else {
			s.resizeLineIdx = defIdx
		}
	}

	// Sites still unresolved need an insert. A resize can change an instruction's
	// size, so anything but pure size-neutral swaps requires a relayout pass.
	needRelayout := false
	for _, s := range sites {
		if !s.noEdit && s.swapLineIdx < 0 && s.resizeLineIdx < 0 {
			s.doInsert = true
		}
		if s.doInsert || s.resizeLineIdx >= 0 {
			needRelayout = true
		}
	}

	// ── Fast path: only size-neutral swaps → offsets are untouched, emit directly.
	if !needRelayout {
		out := applySwaps(body, sites, value)
		return out, len(sites), ""
	}

	// ── Relayout path. Refuse layouts we cannot re-offset by hand: payload ops
	// (packed-switch/sparse-switch/fill-array-data), try/catch ranges, or any
	// instruction we cannot size. For those we apply only the size-neutral
	// swaps and honestly report the sites we left alone rather than risk
	// corrupting control flow.
	if hasRelayoutHazard(body) {
		return swapOnlyFallback(body, sites, value)
	}

	// Registers a const cannot encode (v256+ for const/16 and const, v16+ for
	// const/4-only values) must refuse the relayout the same honest way:
	// swap-only + note, never an unassemblable `const/16 v300`.
	for _, s := range sites {
		if s.doInsert || s.resizeLineIdx >= 0 {
			if !regFitsConst(s.reg, value) {
				return swapOnlyFallback(body, sites, value)
			}
		}
	}

	// No numeric branches → size changes shift nothing that matters, emit directly.
	if !hasNumericBranch(body) {
		out, forced := applyEdits(body, sites, value, nil)
		return out, forced, ""
	}

	// Numeric branches present → recompute every offset for the new layout.
	rewrites, ok := recomputeBranchOffsets(body, sites, value)
	if !ok {
		return swapOnlyFallback(body, sites, value)
	}

	out, forced := applyEdits(body, sites, value, rewrites)
	return out, forced, ""
}

// hasRelayoutHazard reports whether a method contains anything that references
// code by an offset or label we do not model — a payload/switch/array-data
// block, a try/catch range, or an instruction of unknown size. Inserting into
// such a method could shift a reference we cannot fix, so the engine falls back
// to size-neutral swaps only.
func hasRelayoutHazard(body []string) bool {
	for _, line := range body {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		if strings.HasPrefix(t, ".packed-switch") || strings.HasPrefix(t, ".sparse-switch") ||
			strings.HasPrefix(t, ".array-data") || strings.HasPrefix(t, ".catch") {
			return true
		}
		mnem, ok := insnLine(t)
		if !ok {
			continue
		}
		switch mnem {
		case "packed-switch", "sparse-switch", "fill-array-data":
			return true
		}
		if _, known := smaliUnits(mnem); !known {
			return true
		}
	}
	return false
}

// swapOnlyFallback emits the body with just the size-neutral literal swaps that
// were already resolved, leaving insert-only sites untouched, and returns a note
// naming how many return sites could not be forced. Never corrupts offsets.
func swapOnlyFallback(body []string, sites []*retSite, value int32) (string, int, string) {
	swapOnly := make([]*retSite, 0, len(sites))
	forced := 0
	for _, s := range sites {
		switch {
		case s.swapLineIdx >= 0:
			swapOnly = append(swapOnly, s)
			forced++
		case s.noEdit:
			forced++ // already returns value, nothing to edit
		}
	}
	out := applySwaps(body, swapOnly, value)
	skipped := len(sites) - forced
	note := fmt.Sprintf(
		"%d return site(s) left unforced: method layout (switch/try-catch or unrecognised opcode) cannot be safely re-offset",
		skipped)
	return out, forced, note
}

// singleConstDefOnlyReturned reports whether reg is defined by exactly one
// const-family instruction (returning its body line index and opcode) and is
// used nowhere except that def and `return reg` lines. This is a conservative,
// purely textual check: any ambiguity disables the optimisation (callers then
// insert instead), so it can never mis-force a register used by a branch or
// comparison.
func singleConstDefOnlyReturned(body []string, reg string) (int, string, bool) {
	defIdx := -1
	defOpcode := ""
	for i, line := range body {
		trimmed := strings.TrimSpace(line)
		if _, ok := insnLine(trimmed); !ok {
			continue
		}
		// `return reg` is an allowed use.
		if r, ok := plainReturnRegister(trimmed); ok && r == reg {
			continue
		}
		if !regTokenPresent(trimmed, reg) {
			continue
		}
		// reg appears here. It is only acceptable as the destination of a const.
		if dreg, ok := constDestRegister(trimmed); ok && dreg == reg {
			// Must be the sole const def and reg must not also be a source
			// operand of this same const (const has no reg source, so fine).
			if defIdx >= 0 {
				return 0, "", false // more than one def
			}
			defIdx = i
			defOpcode = strings.Fields(trimmed)[0]
			continue
		}
		// Any other appearance (branch, comparison, arithmetic, move) disqualifies.
		return 0, "", false
	}
	if defIdx < 0 {
		return 0, "", false
	}
	return defIdx, defOpcode, true
}

// hasNumericBranch reports whether any instruction line carries a trailing
// numeric branch offset.
func hasNumericBranch(body []string) bool {
	for _, line := range body {
		trimmed := smaliCodeLine(line)
		mnem, ok := insnLine(trimmed)
		if !ok {
			continue
		}
		if _, _, isBranch := branchRange(mnem); isBranch && trailingOffsetRe.MatchString(trimmed) {
			return true
		}
	}
	return false
}

// applySwaps rewrites const-def lines flagged for swapping to load value,
// keeping their opcode (and therefore size). Returns the full method text.
func applySwaps(body []string, sites []*retSite, value int32) string {
	swap := map[int]bool{}
	for _, s := range sites {
		if s.swapLineIdx >= 0 {
			swap[s.swapLineIdx] = true
		}
	}
	var b strings.Builder
	for i, line := range body {
		if swap[i] {
			b.WriteString(swapConstLiteral(line, value))
		} else {
			b.WriteString(line)
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// swapConstLiteral replaces the literal of a `const* reg, LIT` line with value,
// preserving indentation, opcode and register.
func swapConstLiteral(line string, value int32) string {
	indent := indentLike(line)
	fields := strings.Fields(strings.TrimSpace(line))
	// fields: [opcode, reg(,)] LIT...
	reg := strings.TrimSuffix(fields[1], ",")
	return fmt.Sprintf("%s%s %s, %s", indent, fields[0], reg, fmtLiteral(value))
}

// applyEdits emits the body applying every resolved edit: a `const reg, value`
// inserted before each insert-flagged return, a size-neutral literal swap for
// swap-flagged const defs, an in-place widen/narrow (resize) for resize-flagged
// const defs, and — when provided — branch lines rewritten from the recompute
// map (body line index → new signed offset text).
func applyEdits(body []string, sites []*retSite, value int32, rewrites map[int]string) (string, int) {
	insertBefore := map[int]string{} // return line idx → const reg
	swap := map[int]bool{}           // const def line idx → flip literal in place
	resize := map[int]string{}       // const def line idx → dest reg (rewrite to a fitting const)
	forced := 0
	for _, s := range sites {
		switch {
		case s.doInsert:
			insertBefore[s.lineIdx] = s.reg
			forced++
		case s.resizeLineIdx >= 0:
			resize[s.resizeLineIdx] = s.reg
			forced++
		case s.swapLineIdx >= 0:
			swap[s.swapLineIdx] = true
			forced++
		case s.noEdit:
			forced++
		}
	}
	var b strings.Builder
	for i, line := range body {
		if reg, ok := insertBefore[i]; ok {
			indent := indentLike(line)
			cline, _ := chooseConstLine(reg, value)
			b.WriteString(indent)
			b.WriteString(cline)
			b.WriteByte('\n')
		}
		switch {
		case swap[i]:
			b.WriteString(swapConstLiteral(line, value))
		case resize[i] != "":
			indent := indentLike(line)
			cline, _ := chooseConstLine(resize[i], value)
			b.WriteString(indent)
			b.WriteString(cline)
		case rewrites != nil && rewrites[i] != "":
			b.WriteString(rewrites[i])
		default:
			b.WriteString(line)
		}
		b.WriteByte('\n')
	}
	return b.String(), forced
}

// insnRec is a decoded instruction with its pre-edit code-unit offset.
type insnRec struct {
	lineIdx  int
	mnem     string
	units    int
	offset   int  // pre-edit absolute code-unit offset
	isReturn bool // plain `return vX`
	isBranch bool
	delta    int // branch delta (pre-edit)
}

// recomputeBranchOffsets computes new branch offsets for a method after
// inserting a const before every insert-flagged return. It returns a map of
// body line index → rewritten branch line text, or ok=false if the method
// cannot be safely re-laid-out (unknown instruction size, payload op, unaligned
// branch target, or an offset that would overflow its branch format).
func recomputeBranchOffsets(body []string, sites []*retSite, value int32) (map[int]string, bool) {
	// Build the instruction stream with pre-edit offsets.
	recs := make([]insnRec, 0, len(body))
	byOffset := map[int]int{} // pre-edit offset → recs index
	pos := 0
	for i, line := range body {
		trimmed := smaliCodeLine(line)
		mnem, ok := insnLine(trimmed)
		if !ok {
			continue
		}
		units, known := smaliUnits(mnem)
		if !known {
			return nil, false // cannot size this method
		}
		rec := insnRec{lineIdx: i, mnem: mnem, units: units, offset: pos}
		if _, isBranch := branchRangeOK(mnem); isBranch {
			if d, ok := parseTrailingOffset(trimmed); ok {
				rec.isBranch = true
				rec.delta = d
			}
		}
		if _, ok := plainReturnRegister(trimmed); ok {
			rec.isReturn = true
		}
		byOffset[pos] = len(recs)
		recs = append(recs, rec)
		pos += units
	}

	// Which return line indices get a const inserted (and its size), and which
	// const-def line indices are resized in place (to a new, possibly different
	// size). A resize and an insert never land on the same line: inserts precede
	// a `return`, resizes rewrite a `const` def.
	insertUnits := map[int]int{}  // recs index of return → inserted const units
	insertSet := map[int]bool{}   // body line idx flagged for insert
	resizeUnits := map[int]int{}  // recs index of const def → new units
	resizeSet := map[int]string{} // body line idx flagged for resize → dest reg
	for _, s := range sites {
		if s.doInsert {
			insertSet[s.lineIdx] = true
		}
		if s.resizeLineIdx >= 0 {
			resizeSet[s.resizeLineIdx] = s.reg
		}
	}
	for ri, rec := range recs {
		if rec.isReturn && insertSet[rec.lineIdx] {
			// size of the const we will insert for this return's register
			reg := returnRegAt(body, rec.lineIdx)
			_, u := chooseConstLine(reg, value)
			if u == 0 {
				return nil, false // register unencodable (v256+) — refuse relayout
			}
			insertUnits[ri] = u
		}
		if reg, ok := resizeSet[rec.lineIdx]; ok {
			// size of the const this def is rewritten to
			_, u := chooseConstLine(reg, value)
			if u == 0 {
				return nil, false
			}
			resizeUnits[ri] = u
		}
	}

	// Rewrite each branch against the new layout, with fixpoint goto promotion:
	// goto(1u,±127) → goto/16(2u,±32767) → goto/32(3u,±2^31). Each promotion
	// grows the layout by 1 unit, which can push OTHER branches over their
	// range — so we iterate until stable (max len(recs)+2 passes) instead of
	// the old single-goto fast path.
	promoted := map[int]string{} // recs index → promoted mnemonic
	for pass := 0; pass < len(recs)+2; pass++ {
		// Rebuild offsets with current promotions applied.
		newInsnOffset := make([]int, len(recs))
		newSlotOffset := make([]int, len(recs))
		np := 0
		for ri := range recs {
			units := recs[ri].units
			if u, ok := resizeUnits[ri]; ok {
				units = u
			}
			if mnem, ok := promoted[ri]; ok {
				if u, known := smaliUnits(mnem); known {
					units = u
				}
			}
			if u, ok := insertUnits[ri]; ok {
				newSlotOffset[ri] = np
				np += u
				newInsnOffset[ri] = np
				np += units
			} else {
				newSlotOffset[ri] = np
				newInsnOffset[ri] = np
				np += units
			}
		}
		rewrites := map[int]string{}
		needAnotherPass := false
		failed := false
		for bi, rec := range recs {
			if !rec.isBranch {
				continue
			}
			targetAbs := rec.offset + rec.delta
			ti, ok := byOffset[targetAbs]
			if !ok {
				return nil, false // branch target not aligned to an instruction
			}
			mnem := rec.mnem
			if p, ok := promoted[bi]; ok {
				mnem = p
			}
			newDelta := newSlotOffset[ti] - newInsnOffset[bi]
			lo, hi := branchBounds(mnem)
			if newDelta >= lo && newDelta <= hi {
				if mnem != rec.mnem {
					rewrites[rec.lineIdx] = rewriteBranchMnemonic(body[rec.lineIdx], rec.mnem, mnem, newDelta)
				} else {
					rewrites[rec.lineIdx] = rewriteTrailingOffset(body[rec.lineIdx], newDelta)
				}
				continue
			}
			// Overflow — try to promote one step up.
			next, ok := promoteBranchMnemonic(mnem)
			if !ok {
				failed = true
				break
			}
			promoted[bi] = next
			needAnotherPass = true
		}
		if failed {
			return nil, false
		}
		if !needAnotherPass {
			return rewrites, true
		}
	}
	return nil, false
}

// promoteBranchMnemonic steps a branch mnemonic one size up:
// goto → goto/16 → goto/32. if-*/goto/16 already max out at 16-bit
// (Dalvik has no if/32), so they cannot be promoted.
func promoteBranchMnemonic(mnem string) (string, bool) {
	switch mnem {
	case "goto":
		return "goto/16", true
	case "goto/16":
		return "goto/32", true
	}
	return "", false
}

// rewriteBranchMnemonic rewrites both the mnemonic and trailing offset.
func rewriteBranchMnemonic(line, oldMnem, newMnem string, delta int) string {
	indent := indentLike(line)
	trimmed := smaliCodeLine(line)
	m := trailingOffsetRe.FindStringSubmatch(trimmed)
	if m == nil {
		return line
	}
	prefix := strings.Replace(m[1], oldMnem+" ", newMnem+" ", 1)
	if prefix == m[1] {
		prefix = strings.Replace(m[1], oldMnem, newMnem, 1)
	}
	return fmt.Sprintf("%s%s%s", indent, prefix, signedOffset(delta))
}

// returnRegAt returns the register of the plain `return vX` at body[idx].
func returnRegAt(body []string, idx int) string {
	if idx < 0 || idx >= len(body) {
		return "v0"
	}
	if reg, ok := plainReturnRegister(smaliCodeLine(body[idx])); ok {
		return reg
	}
	return "v0"
}

// branchRangeOK reports whether mnem is a numeric branch (thin wrapper used
// during stream decode).
func branchRangeOK(mnem string) (struct{}, bool) {
	_, _, ok := branchRange(mnem)
	return struct{}{}, ok
}

// branchBounds returns the encodable delta range for a branch mnemonic.
func branchBounds(mnem string) (int, int) {
	lo, hi, _ := branchRange(mnem)
	return lo, hi
}

// parseTrailingOffset extracts the signed decimal branch delta from a line.
func parseTrailingOffset(trimmed string) (int, bool) {
	m := trailingOffsetRe.FindStringSubmatch(trimmed)
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[2])
	if err != nil {
		return 0, false
	}
	return n, true
}

// rewriteTrailingOffset replaces the trailing signed offset of a branch line
// with delta, preserving indentation and everything before the offset.
func rewriteTrailingOffset(line string, delta int) string {
	indent := indentLike(line)
	trimmed := smaliCodeLine(line)
	m := trailingOffsetRe.FindStringSubmatch(trimmed)
	if m == nil {
		return line
	}
	return fmt.Sprintf("%s%s%s", indent, m[1], signedOffset(delta))
}

// signedOffset formats a delta as the disassembler does: "+N" / "-N".
func signedOffset(delta int) string {
	if delta >= 0 {
		return "+" + strconv.Itoa(delta)
	}
	return strconv.Itoa(delta)
}

// promoteGotoAndRelayout handles the case where a 1-unit `goto` overflows
// its ±128 range after inserts/resizes shift the layout. It rebuilds the
// offset map with the promoted `goto/16` (2 units) and recomputes all
// branch deltas from scratch. Returns the final rewrites or ok=false if the
// layout still cannot be resolved (extremely rare — would need goto/32).
func promoteGotoAndRelayout(
	body []string,
	sites []*retSite,
	value int32,
	recs []insnRec,
	promoteIdx int,
	insertUnits map[int]int,
	resizeUnits map[int]int,
	resizeSet map[int]string,
	insertSet map[int]bool,
) (map[int]string, bool) {
	// Rebuild offsets with the goto at promoteIdx taking 2 units instead of 1.
	byOffset := map[int]int{}
	newInsnOffset := make([]int, len(recs))
	newSlotOffset := make([]int, len(recs))
	np := 0
	for ri := range recs {
		units := recs[ri].units
		if ri == promoteIdx {
			units = 2 // goto/16
		}
		if u, ok := resizeUnits[ri]; ok {
			units = u
		}
		if u, ok := insertUnits[ri]; ok {
			newSlotOffset[ri] = np
			np += u
			newInsnOffset[ri] = np
			np += units
		} else {
			newSlotOffset[ri] = np
			newInsnOffset[ri] = np
			np += units
		}
		byOffset[recs[ri].offset] = ri
	}

	rewrites := map[int]string{}
	for bi, rec := range recs {
		if !rec.isBranch {
			continue
		}
		targetAbs := rec.offset + rec.delta
		ti, ok := byOffset[targetAbs]
		if !ok {
			return nil, false
		}
		newSrc := newInsnOffset[bi]
		newTgt := newSlotOffset[ti]
		newDelta := newTgt - newSrc

		mnem := rec.mnem
		if bi == promoteIdx {
			mnem = "goto/16"
		}
		lo, hi := branchBounds(mnem)
		if newDelta < lo || newDelta > hi {
			return nil, false
		}
		if bi == promoteIdx {
			// Rewrite goto → goto/16 with new delta.
			indent := indentLike(body[rec.lineIdx])
			trimmed := strings.TrimSpace(body[rec.lineIdx])
			// Replace the mnemonic and the offset.
			m := trailingOffsetRe.FindStringSubmatch(trimmed)
			if m == nil {
				return nil, false
			}
			// m[1] contains everything before the offset, starting with "goto "
			prefix := strings.Replace(m[1], "goto ", "goto/16 ", 1)
			rewrites[rec.lineIdx] = fmt.Sprintf("%s%s%s", indent, prefix, signedOffset(newDelta))
		} else {
			rewrites[rec.lineIdx] = rewriteTrailingOffset(body[rec.lineIdx], newDelta)
		}
	}
	return rewrites, true
}
