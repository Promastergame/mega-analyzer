package ml

import (
	"strings"
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// UNIT TESTS FOR THE OFFSET-SAFE RETURN OVERRIDE ENGINE (smali_offset.go)
//
// These lock in the two properties the old inject-before-every-return code got
// wrong on the real com.playgendary.tom patches:
//   1. numeric branch offsets stay valid after an edit, and
//   2. no dead adjacent double-const is produced.
// ═══════════════════════════════════════════════════════════════════════════════

// countOccurrences counts non-overlapping substring hits.
func countOccurrences(s, sub string) int {
	return strings.Count(s, sub)
}

// countNopLines counts lines that are exactly a `nop` instruction. Substring
// counting ("\n    nop\n") is wrong for this because adjacent nop lines share
// the newline between them, so a run of N nops yields only ceil(N/2) matches.
func countNopLines(out string) int {
	n := 0
	for _, ln := range strings.Split(out, "\n") {
		if strings.TrimSpace(ln) == "nop" {
			n++
		}
	}
	return n
}

// hasAdjacentDoubleConst reports whether two const instructions targeting the
// same register appear back-to-back (the dead-store smell the user complained
// about).
func hasAdjacentDoubleConst(out string) bool {
	lines := strings.Split(out, "\n")
	prevReg, prevWasConst := "", false
	for _, ln := range lines {
		t := strings.TrimSpace(ln)
		if reg, ok := constDestRegister(t); ok {
			if prevWasConst && prevReg == reg {
				return true
			}
			prevReg, prevWasConst = reg, true
			continue
		}
		if _, ok := insnLine(t); ok {
			// any other real instruction breaks adjacency
			prevWasConst = false
		}
	}
	return false
}

// assertOffsetsValid re-walks the patched body, recomputes code-unit offsets and
// checks every numeric branch lands exactly on an instruction boundary. This is
// the ground-truth control-flow validity check.
func assertOffsetsValid(t *testing.T, out string) {
	t.Helper()
	lines := strings.Split(out, "\n")
	type rec struct {
		offset   int
		isBranch bool
		delta    int
		mnem     string
	}
	recs := []rec{}
	offsets := map[int]bool{}
	pos := 0
	for _, ln := range lines {
		trimmed := strings.TrimSpace(ln)
		mnem, ok := insnLine(trimmed)
		if !ok {
			continue
		}
		units, known := smaliUnits(mnem)
		if !known {
			t.Fatalf("unknown-size instruction in patched output: %q", trimmed)
		}
		r := rec{offset: pos, mnem: mnem}
		if _, _, isBranch := branchRange(mnem); isBranch {
			if d, ok := parseTrailingOffset(trimmed); ok {
				r.isBranch = true
				r.delta = d
			}
		}
		offsets[pos] = true
		recs = append(recs, r)
		pos += units
	}
	for _, r := range recs {
		if !r.isBranch {
			continue
		}
		target := r.offset + r.delta
		if !offsets[target] {
			t.Errorf("branch %s at offset %d delta %d targets offset %d which is not an instruction boundary",
				r.mnem, r.offset, r.delta, target)
		}
	}
}

// TestOverrideReturns_DualReturnBoolean covers the classic two-return boolean
// idiom (deviceNeedsAutoFrcWorkaround shape): one path returns 1, one returns 0,
// a numeric branch selects between them. Forcing true must flip the false path's
// const IN PLACE — no insertion, offsets untouched, no double-const.
func TestOverrideReturns_DualReturnBoolean(t *testing.T) {
	body := []string{
		".method public static deviceNeedsAutoFrcWorkaround()Z",
		"    .registers 2",
		"    sget v0, Lp;->x:I",
		"    const/16 v1, 0x1c",
		"    if-ne v0, v1, +4",
		"    const/4 v0, 0x1",
		"    return v0",
		"    const/4 v0, 0x0",
		"    return v0",
		".end method",
	}

	out, count, note := overrideReturnsSafe(body, 1)
	if count != 2 {
		t.Fatalf("expected 2 forced return sites, got %d", count)
	}
	if note != "" {
		t.Errorf("expected no note for in-place swap, got %q", note)
	}
	if got := countOccurrences(out, "const/4 v0, 0x0"); got != 0 {
		t.Errorf("false-path const should have been flipped to 0x1, still %d occurrence(s):\n%s", got, out)
	}
	if got := countOccurrences(out, "const/4 v0, 0x1"); got != 2 {
		t.Errorf("expected 2 const/4 v0, 0x1, got %d:\n%s", got, out)
	}
	if !strings.Contains(out, "if-ne v0, v1, +4") {
		t.Errorf("branch offset must be untouched (size-neutral swap):\n%s", out)
	}
	if hasAdjacentDoubleConst(out) {
		t.Errorf("must not produce a dead double-const:\n%s", out)
	}
	assertOffsetsValid(t, out)
}

// TestOverrideReturns_SingleDefFlip covers a register defined by exactly one
// const and read only by two `return` sites (isSnapshotValid shape). Forcing
// true must flip that single def and cover both returns with no insertion.
func TestOverrideReturns_SingleDefFlip(t *testing.T) {
	body := []string{
		".method public isSnapshotValid()Z",
		"    .registers 3",
		"    const/4 v1, 0x0",
		"    sget-boolean v0, Lp;->ready:Z",
		"    if-nez v0, +3",
		"    return v1",
		"    return v1",
		".end method",
	}

	out, count, note := overrideReturnsSafe(body, 1)
	if count != 2 {
		t.Fatalf("expected 2 forced return sites, got %d", count)
	}
	if note != "" {
		t.Errorf("expected no note, got %q", note)
	}
	if got := countOccurrences(out, "const/4 v1, 0x1"); got != 1 {
		t.Errorf("expected exactly one flipped def const/4 v1, 0x1, got %d:\n%s", got, out)
	}
	if strings.Contains(out, "const/4 v1, 0x0") {
		t.Errorf("original def const/4 v1, 0x0 should be gone:\n%s", out)
	}
	if !strings.Contains(out, "if-nez v0, +3") {
		t.Errorf("branch offset must be untouched:\n%s", out)
	}
	assertOffsetsValid(t, out)
}

// TestOverrideReturns_BranchlessInsert covers an economy getter whose value
// comes from an iget (no const to swap). MAX_INT must be inserted before the
// return; with no branches the offsets need no recompute.
func TestOverrideReturns_BranchlessInsert(t *testing.T) {
	body := []string{
		".method public getCoins()I",
		"    .registers 2",
		"    iget v0, p0, Lp;->coins:I",
		"    return v0",
		".end method",
	}

	out, count, note := overrideReturnsSafe(body, 0x7fffffff)
	if count != 1 {
		t.Fatalf("expected 1 forced return site, got %d", count)
	}
	if note != "" {
		t.Errorf("expected no note, got %q", note)
	}
	if !strings.Contains(out, "iget v0, p0, Lp;->coins:I") {
		t.Errorf("original iget side effect must be preserved:\n%s", out)
	}
	if !strings.Contains(out, "const v0, 0x7fffffff") {
		t.Errorf("expected inserted const v0, 0x7fffffff:\n%s", out)
	}
	if hasAdjacentDoubleConst(out) {
		t.Errorf("must not produce a dead double-const:\n%s", out)
	}
	assertOffsetsValid(t, out)
}

// TestOverrideReturns_InsertWithBranchRecompute is the core regression: a method
// where the return value comes from move-result (needs insert) AND a numeric
// branch must be recomputed for the shifted layout. The old code left the branch
// delta stale; here it must be updated so the target still lands correctly.
func TestOverrideReturns_InsertWithBranchRecompute(t *testing.T) {
	// offsets (pre-edit): invoke@0(3) move-result@3(1) if-lez@4(2) invoke@6(3)
	// move-result@9(1) return@10(1) const/4@11(1) return@12(1)
	// if-lez targets @11 → delta +7.
	body := []string{
		".method public getScore()I",
		"    .registers 2",
		"    invoke-static {}, Lp;->base()I",
		"    move-result v0",
		"    if-lez v0, +7",
		"    invoke-virtual {p0}, Lp;->bonus()I",
		"    move-result v0",
		"    return v0",
		"    const/4 v0, 0x0",
		"    return v0",
		".end method",
	}

	out, count, note := overrideReturnsSafe(body, 0x7fffffff)
	if count != 2 {
		t.Fatalf("expected 2 forced return sites, got %d", count)
	}
	if note != "" {
		t.Errorf("expected clean recompute with no note, got %q", note)
	}
	if !strings.Contains(out, "if-lez v0, +10") {
		t.Errorf("branch delta must be recomputed to +10 for the shifted layout:\n%s", out)
	}
	if strings.Contains(out, "if-lez v0, +7") {
		t.Errorf("stale +7 branch delta must not survive:\n%s", out)
	}
	if got := countOccurrences(out, "const v0, 0x7fffffff"); got != 2 {
		t.Errorf("expected MAX_INT forced at both returns, got %d:\n%s", got, out)
	}
	// both invoke side effects preserved
	if !strings.Contains(out, "Lp;->base()I") || !strings.Contains(out, "Lp;->bonus()I") {
		t.Errorf("original invoke side effects must be preserved:\n%s", out)
	}
	assertOffsetsValid(t, out)
}

// TestOverrideReturns_HazardFallback verifies that a method containing a payload
// op (packed-switch) which also needs an insert falls back to swap-only and
// reports the skipped site instead of corrupting the switch layout.
func TestOverrideReturns_HazardFallback(t *testing.T) {
	body := []string{
		".method public route(I)I",
		"    .registers 2",
		"    packed-switch p1, +8",
		"    invoke-static {}, Lp;->def()I",
		"    move-result v0",
		"    return v0",
		".end method",
	}

	out, count, note := overrideReturnsSafe(body, 0x7fffffff)
	if count != 0 {
		t.Fatalf("expected 0 forced sites (insert refused near packed-switch), got %d", count)
	}
	if note == "" {
		t.Errorf("expected a note explaining the skipped site")
	}
	// nothing inserted → body unchanged except trailing newline normalisation
	if strings.Contains(out, "const v0, 0x7fffffff") {
		t.Errorf("must NOT insert near a packed-switch payload:\n%s", out)
	}
	if !strings.Contains(out, "packed-switch p1, +8") {
		t.Errorf("packed-switch must be preserved verbatim:\n%s", out)
	}
}

// TestOverrideReturns_HighRegisterInsert verifies register-width correctness:
// forcing a boolean into a register above v15 must use const/16 (const/4 cannot
// encode the register), and remain offset-valid.
func TestOverrideReturns_HighRegisterInsert(t *testing.T) {
	body := []string{
		".method public check()Z",
		"    .registers 20",
		"    invoke-virtual {p0}, Lp;->probe()Z",
		"    move-result v16",
		"    return v16",
		".end method",
	}

	out, count, _ := overrideReturnsSafe(body, 1)
	if count != 1 {
		t.Fatalf("expected 1 forced site, got %d", count)
	}
	if !strings.Contains(out, "const/16 v16, 0x1") {
		t.Errorf("register above v15 must use const/16, got:\n%s", out)
	}
	assertOffsetsValid(t, out)
}

// TestOverrideReturns_NegativeGotoRecompute checks that a backward goto (negative
// delta) is recomputed correctly when an insert lands between the goto and its
// target.
func TestOverrideReturns_NegativeGotoRecompute(t *testing.T) {
	// invoke@0(3) move-result@3(1) return@4(1) goto@5(1 has delta -5 → target @0)
	// The return before the goto needs an insert; the goto's target (@0) is before
	// the insert, so its delta must grow by the inserted size.
	body := []string{
		".method public loopy()I",
		"    .registers 1",
		"    invoke-static {}, Lp;->step()I",
		"    move-result v0",
		"    return v0",
		"    goto -5",
		".end method",
	}

	out, count, note := overrideReturnsSafe(body, 0x7fffffff)
	if count != 1 {
		t.Fatalf("expected 1 forced site, got %d", count)
	}
	if note != "" {
		t.Errorf("expected clean recompute, got note %q", note)
	}
	// inserted const is 3 units before the return; goto now sits 3 units later,
	// target unchanged at 0 → delta -5-3 = -8.
	if !strings.Contains(out, "goto -8") {
		t.Errorf("backward goto delta must be recomputed to -8:\n%s", out)
	}
	assertOffsetsValid(t, out)
}

// TestOverrideReturns_ResizeConstWiden is the getFormatLanguageScore regression:
// several `const/4 vX, K; return vX` sites forced to MAX_INT. const/4 cannot hold
// 0x7fffffff, so the engine must WIDEN each defining const in place to a full
// `const vX, 0x7fffffff` (never insert a dead second const beside it) and
// recompute the branch that selects between them for the enlarged layout.
func TestOverrideReturns_ResizeConstWiden(t *testing.T) {
	// pre-edit: if-eqz@0(2) const/4@2(1) return@3(1) const/4@4(1) return@5(1)
	// const/4@6(1) return@7(1). if-eqz targets @6 → delta +6.
	body := []string{
		".method public getFormatLanguageScore(I)I",
		"    .registers 3",
		"    if-eqz v2, +6",
		"    const/4 v1, 0x4",
		"    return v1",
		"    const/4 v1, 0x2",
		"    return v1",
		"    const/4 v1, 0x1",
		"    return v1",
		".end method",
	}

	out, count, note := overrideReturnsSafe(body, 0x7fffffff)
	if count != 3 {
		t.Fatalf("expected 3 forced return sites, got %d", count)
	}
	if note != "" {
		t.Errorf("expected clean recompute with no note, got %q", note)
	}
	if got := countOccurrences(out, "const v1, 0x7fffffff"); got != 3 {
		t.Errorf("expected 3 widened const v1, 0x7fffffff, got %d:\n%s", got, out)
	}
	if strings.Contains(out, "const/4 v1,") {
		t.Errorf("narrow const/4 defs must be widened away, still present:\n%s", out)
	}
	if hasAdjacentDoubleConst(out) {
		t.Errorf("widen-in-place must NOT leave a dead double-const:\n%s", out)
	}
	// after widening three 1-unit consts to 3 units each, the if-eqz target
	// (the third const, originally @6) moves to @10 → delta +10.
	if !strings.Contains(out, "if-eqz v2, +10") {
		t.Errorf("branch delta must be recomputed to +10 for the widened layout:\n%s", out)
	}
	if strings.Contains(out, "if-eqz v2, +6") {
		t.Errorf("stale +6 branch delta must not survive:\n%s", out)
	}
	assertOffsetsValid(t, out)
}

// TestOverrideReturns_ResizeSingleDefWiden covers tier (b) widening: a register
// defined by exactly one narrow const and read only by returns, forced to a value
// the narrow const cannot hold. The single def must be widened in place (covering
// every return), not duplicated.
func TestOverrideReturns_ResizeSingleDefWiden(t *testing.T) {
	body := []string{
		".method public getGems()I",
		"    .registers 3",
		"    const/4 v1, 0x0",
		"    sget-boolean v0, Lp;->ready:Z",
		"    if-nez v0, +3",
		"    return v1",
		"    return v1",
		".end method",
	}

	out, count, note := overrideReturnsSafe(body, 0x7fffffff)
	if count != 2 {
		t.Fatalf("expected 2 forced return sites, got %d", count)
	}
	if note != "" {
		t.Errorf("expected clean recompute, got note %q", note)
	}
	if got := countOccurrences(out, "const v1, 0x7fffffff"); got != 1 {
		t.Errorf("expected exactly one widened def const v1, 0x7fffffff, got %d:\n%s", got, out)
	}
	if strings.Contains(out, "const/4 v1, 0x0") {
		t.Errorf("original narrow def must be widened away:\n%s", out)
	}
	if hasAdjacentDoubleConst(out) {
		t.Errorf("must not produce a dead double-const:\n%s", out)
	}
	// const/4(1u)→const(3u) shifts everything after by 2 units; if-nez sits
	// BEFORE the resized def, so the +3 that jumped over the first return is
	// unchanged (target and source both move together only past the def). The
	// def is before the branch, so branch source shifts by +2 and its target
	// (first return) also shifts by +2 → delta stays +3.
	if !strings.Contains(out, "if-nez v0, +3") {
		t.Errorf("branch delta should remain +3 (def precedes the branch):\n%s", out)
	}
	assertOffsetsValid(t, out)
}

// TestOverrideReturns_AlreadyCorrect_NoPhantomEdit locks in the phantom-diff
// fix: when every return already yields the target value via consts holding it,
// not a single line may be rewritten. Previously the literal was normalised
// decimal→hex, producing semantically empty hunks like
// "const/4 v1, 1" → "const/4 v1, 0x1" in the generated patches.
//
// NOTE: the branch here targets the second const (+4), so both returns are
// genuinely already-correct on every path. A branch landing directly on a
// return (see TestOverrideReturns_BranchEntryBypass_Forces) is NOT
// already-correct: the taken path reaches it with an unknown register value.
func TestOverrideReturns_AlreadyCorrect_NoPhantomEdit(t *testing.T) {
	body := []string{
		".method public check()Z",
		"    .registers 2",
		"    sget-boolean v0, Lp;->ok:Z",
		"    if-eqz v0, +4",
		"    const/4 v0, 1", // decimal form must stay decimal
		"    return v0",
		"    const/4 v0, 0x1",
		"    return v0",
		".end method",
	}

	want := strings.Join(body, "\n") + "\n"
	out, count, note := overrideReturnsSafe(body, 1)
	if count != 2 {
		t.Fatalf("expected 2 forced (already-correct) sites, got %d", count)
	}
	if note != "" {
		t.Errorf("expected no note, got %q", note)
	}
	if out != want {
		t.Errorf("already-correct method must be emitted verbatim, got diff:\n--- want\n+++ got\n%s", out)
	}
	assertOffsetsValid(t, out)
}

// TestOverrideReturns_BranchEntryBypass_Forces: a lexically preceding const is
// NOT proof when a numeric branch lands directly on the return — the taken
// path (here: if-eqz jumps with v0==0) bypasses the const. The forcer must
// not claim noEdit; it inserts the const at the entry instead. Previously the
// naive previous-instruction tracking marked this site already-correct and
// emitted the method verbatim, silently missing the bypass path.
func TestOverrideReturns_BranchEntryBypass_Forces(t *testing.T) {
	body := []string{
		".method public check()Z",
		"    .registers 2",
		"    sget-boolean v0, Lp;->ok:Z",
		"    if-eqz v0, +3",
		"    const/4 v0, 1",
		"    return v0",
		"    const/4 v0, 0x1",
		"    return v0",
		".end method",
	}
	want := strings.Join([]string{
		".method public check()Z",
		"    .registers 2",
		"    sget-boolean v0, Lp;->ok:Z",
		"    if-eqz v0, +3",
		"    const/4 v0, 1",
		"    const/4 v0, 0x1",
		"    return v0",
		"    const/4 v0, 0x1",
		"    return v0",
		".end method",
	}, "\n") + "\n"
	out, count, note := overrideReturnsSafe(body, 1)
	if count != 2 {
		t.Fatalf("expected 2 forced sites, got %d", count)
	}
	if note != "" {
		t.Errorf("expected no note, got %q", note)
	}
	if out != want {
		t.Errorf("branch-entry return must be forced at the entry, got diff:\n--- want\n+++ got\n%s", out)
	}
	assertOffsetsValid(t, out)
}

// TestOverrideReturns_NoReturns is a safety check: a void method yields no
// forcing and no change.
func TestOverrideReturns_NoReturns(t *testing.T) {
	body := []string{
		".method public log()V",
		"    .registers 1",
		"    invoke-static {}, Lp;->tick()V",
		"    return-void",
		".end method",
	}
	out, count, note := overrideReturnsSafe(body, 1)
	if count != 0 {
		t.Errorf("void method must yield 0 forced sites, got %d", count)
	}
	if note != "" {
		t.Errorf("unexpected note: %q", note)
	}
	if !strings.Contains(out, "return-void") {
		t.Errorf("return-void must be preserved:\n%s", out)
	}
}
