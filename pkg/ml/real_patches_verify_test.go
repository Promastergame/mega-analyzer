package ml

import (
	"bytes"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// MINI-SANDBOX REGRESSION: re-process the in-tree patch fixture through the
// offset-safe engine and prove the two defects are gone.
//
// The fixture is a small, deterministic patch export checked into testdata.
// It asserts that for every
// value-returning patch (return_true / return_false / return_max_int) the newly
// generated smali has (1) zero numeric branch offsets that miss an instruction
// boundary and (2) zero dead adjacent double-const — the two things the old
// inject-before-every-return code got wrong.
// ═══════════════════════════════════════════════════════════════════════════════

const realPatchesFixture = `testdata/mini_patches.json`

type fixturePatch struct {
	MethodName  string `json:"method_name"`
	FilePath    string `json:"file_path"`
	Original_   string `json:"original_code"`
	PatchedCode string `json:"patched_code"`
	PatchType   string `json:"patch_type"`
}

type fixtureFile struct {
	Patches []fixturePatch `json:"patches"`
}

// smaliBranchAudit re-walks a smali method, recomputes code-unit offsets and
// returns the number of numeric branches whose target misses an instruction
// boundary. sized=false means the method contains an opcode we cannot size, so
// the offset verdict is indeterminate (caller skips the offset assertion).
func smaliBranchAudit(code string) (bad int, sized bool) {
	lines := strings.Split(code, "\n")
	type br struct {
		off, delta int
	}
	branches := []br{}
	offsets := map[int]bool{}
	pos := 0
	for _, ln := range lines {
		t := strings.TrimSpace(ln)
		mnem, ok := insnLine(t)
		if !ok {
			continue
		}
		units, known := smaliUnits(mnem)
		if !known {
			return 0, false
		}
		offsets[pos] = true
		if _, _, isBranch := branchRange(mnem); isBranch {
			if d, ok := parseTrailingOffset(t); ok {
				branches = append(branches, br{pos, d})
			}
		}
		pos += units
	}
	for _, b := range branches {
		if !offsets[b.off+b.delta] {
			bad++
		}
	}
	return bad, true
}

func TestMiniPatches_NoOffsetCorruptionOrDoubleConst(t *testing.T) {
	raw, err := os.ReadFile(realPatchesFixture)
	if err != nil {
		t.Skipf("fixture not present (%v); skipping mini-patch regression", err)
	}
	var ff fixtureFile
	if err := json.Unmarshal(raw, &ff); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	if len(ff.Patches) == 0 {
		t.Fatal("fixture has no patches")
	}

	valueFor := func(pt string) (int32, bool) {
		switch pt {
		case "return_true":
			return 1, true
		case "return_false":
			return 0, true
		case "return_max_int":
			return 0x7fffffff, true
		default:
			return 0, false // return_void etc. use a different (non-injection) path
		}
	}

	var (
		processed        int
		baselineBadOff   int // stale offsets in the OLD exported patched_code
		baselineDblConst int // dead double-const in the OLD exported patched_code
		newBadOff        int // stale offsets after the new engine
		newDblConst      int // dead double-const after the new engine
		newUnsized       int // methods we could not size (offset check skipped)
		withNote         int // methods where some sites were safely left unforced
		forcedZeroButHad int // sanity: sites existed but nothing forced
	)

	for i := range ff.Patches {
		p := &ff.Patches[i]
		value, ok := valueFor(p.PatchType)
		if !ok {
			continue
		}
		processed++

		// Baseline: audit the OLD exported patched_code (demonstrates the bug).
		if bad, sized := smaliBranchAudit(p.PatchedCode); sized {
			baselineBadOff += bad
		}
		if hasAdjacentDoubleConst(p.PatchedCode) {
			baselineDblConst++
		}

		// New engine: regenerate from the ORIGINAL method body.
		body := strings.Split(p.Original_, "\n")
		regs, hadReturn := findReturnRegisters(body)
		out, forced, note := overrideReturnsSafe(body, value)
		if note != "" {
			withNote++
		}
		if hadReturn && forced == 0 {
			forcedZeroButHad++
			t.Errorf("[%s] %s: %d return register(s) but engine forced none\n%s",
				p.PatchType, p.MethodName, len(regs), p.Original_)
		}

		if bad, sized := smaliBranchAudit(out); sized {
			newBadOff += bad
			if bad > 0 {
				t.Errorf("[%s] %s: %d branch offset(s) miss their target after patch:\n%s",
					p.PatchType, p.MethodName, bad, out)
			}
		} else {
			newUnsized++
		}
		if hasAdjacentDoubleConst(out) {
			newDblConst++
			t.Errorf("[%s] %s: dead adjacent double-const produced:\n%s",
				p.PatchType, p.MethodName, out)
		}
	}

	t.Logf("processed=%d value-returning patches", processed)
	t.Logf("BEFORE (old export): badOffsets=%d, doubleConst=%d", baselineBadOff, baselineDblConst)
	t.Logf("AFTER  (new engine): badOffsets=%d, doubleConst=%d, unsized=%d, withNote=%d",
		newBadOff, newDblConst, newUnsized, withNote)

	if newBadOff != 0 {
		t.Errorf("new engine still produces %d stale branch offset(s)", newBadOff)
	}
	if newDblConst != 0 {
		t.Errorf("new engine still produces %d dead double-const(s)", newDblConst)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// REGENERATION: rewrite the user's actual omnisec-patches.json into a corrected
// copy (omnisec-patches.fixed.json) using the fixed engine. It is opt-in — it only
// runs when REGEN_PATCHES is set — so the normal test run never touches the file.
//
// It edits each value-returning patch's `patched_code` (and `patched_lines`) IN
// PLACE inside the raw JSON, so every other field, its order, and the file layout
// are preserved byte-for-byte apart from the two corrected fields.
// ═══════════════════════════════════════════════════════════════════════════════

func TestRegenerateMiniPatches(t *testing.T) {
	if os.Getenv("REGEN_PATCHES") == "" {
		t.Skip("set REGEN_PATCHES=1 to regenerate the corrected patches file")
	}
	raw, err := os.ReadFile(realPatchesFixture)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatalf("parse top-level: %v", err)
	}
	var patches []json.RawMessage
	if err := json.Unmarshal(top["patches"], &patches); err != nil {
		t.Fatalf("parse patches array: %v", err)
	}

	valueFor := func(pt string) (int32, bool) {
		switch pt {
		case "return_true":
			return 1, true
		case "return_false":
			return 0, true
		case "return_max_int":
			return 0x7fffffff, true
		default:
			return 0, false
		}
	}

	fixed := 0
	for i := range patches {
		var meta struct {
			PatchType    string `json:"patch_type"`
			OriginalCode string `json:"original_code"`
		}
		if err := json.Unmarshal(patches[i], &meta); err != nil {
			t.Fatalf("parse patch %d: %v", i, err)
		}
		value, ok := valueFor(meta.PatchType)
		if !ok {
			continue // return_void / whole-body stubs pass through untouched
		}
		out, count, _ := overrideReturnsSafe(strings.Split(meta.OriginalCode, "\n"), value)
		if count == 0 {
			continue
		}
		nb, ok := replaceJSONStringField(patches[i], "patched_code", out)
		if !ok {
			t.Errorf("patch %d: could not locate patched_code to rewrite", i)
			continue
		}
		patches[i] = nb
		if lb, ok := replaceJSONNumberField(patches[i], "patched_lines", countLines(out)); ok {
			patches[i] = lb
		}
		fixed++
	}

	// Reassemble: put the edited patch array back, keeping top-level field order.
	newPatches, err := json.Marshal(patches)
	if err != nil {
		t.Fatalf("marshal patches: %v", err)
	}
	top["patches"] = newPatches
	var buf bytes.Buffer
	buf.WriteString("{\n")
	// Emit in the canonical order the generator uses so the file reads naturally.
	order := []string{"schema_version", "capabilities", "version", "timestamp", "generator", "patches"}
	emitted := map[string]bool{}
	writeField := func(key string, first bool) {
		v, ok := top[key]
		if !ok {
			return
		}
		if !first {
			buf.WriteString(",\n")
		}
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, v, "  ", "  "); err != nil {
			pretty.Reset()
			pretty.Write(v)
		}
		buf.WriteString("  ")
		kb, _ := json.Marshal(key)
		buf.Write(kb)
		buf.WriteString(": ")
		buf.Write(pretty.Bytes())
		emitted[key] = true
	}
	first := true
	for _, k := range order {
		if _, ok := top[k]; ok {
			writeField(k, first)
			first = false
		}
	}
	for k := range top { // any keys not in the canonical order
		if !emitted[k] {
			writeField(k, first)
			first = false
		}
	}
	buf.WriteString("\n}\n")

	outPath := strings.TrimSuffix(realPatchesFixture, ".json") + ".fixed.json"
	if err := os.WriteFile(outPath, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("write corrected file: %v", err)
	}
	// Validate the result parses back cleanly.
	if err := json.Unmarshal(buf.Bytes(), &map[string]json.RawMessage{}); err != nil {
		t.Fatalf("corrected file is not valid JSON: %v", err)
	}
	t.Logf("wrote %s with %d corrected patch(es)", outPath, fixed)
}

// replaceJSONStringField locates "field": "…" inside a JSON object's raw bytes and
// replaces the string value with a correctly-escaped encoding of newVal, leaving
// every other byte (and the field order) intact. Returns false if the field or a
// well-formed string value is not found.
func replaceJSONStringField(objRaw []byte, field, newVal string) ([]byte, bool) {
	start, end, ok := jsonStringValueSpan(objRaw, field)
	if !ok {
		return objRaw, false
	}
	lit, err := json.Marshal(newVal)
	if err != nil {
		return objRaw, false
	}
	out := make([]byte, 0, len(objRaw)-(end-start)+len(lit))
	out = append(out, objRaw[:start]...)
	out = append(out, lit...)
	out = append(out, objRaw[end:]...)
	return out, true
}

// replaceJSONNumberField replaces a bare integer value of "field" with n.
func replaceJSONNumberField(objRaw []byte, field string, n int) ([]byte, bool) {
	key := []byte("\"" + field + "\"")
	ki := bytes.Index(objRaw, key)
	if ki < 0 {
		return objRaw, false
	}
	i := ki + len(key)
	i = skipWSColonWS(objRaw, i)
	if i < 0 {
		return objRaw, false
	}
	j := i
	for j < len(objRaw) && (objRaw[j] == '-' || (objRaw[j] >= '0' && objRaw[j] <= '9')) {
		j++
	}
	if j == i {
		return objRaw, false
	}
	out := make([]byte, 0, len(objRaw))
	out = append(out, objRaw[:i]...)
	out = append(out, []byte(strconv.Itoa(n))...)
	out = append(out, objRaw[j:]...)
	return out, true
}

// jsonStringValueSpan returns the [start,end) byte span of the quoted value
// (including both quotes) for "field" in a JSON object's raw bytes.
func jsonStringValueSpan(objRaw []byte, field string) (int, int, bool) {
	key := []byte("\"" + field + "\"")
	ki := bytes.Index(objRaw, key)
	if ki < 0 {
		return 0, 0, false
	}
	i := skipWSColonWS(objRaw, ki+len(key))
	if i < 0 || i >= len(objRaw) || objRaw[i] != '"' {
		return 0, 0, false
	}
	start := i
	i++
	for i < len(objRaw) {
		switch objRaw[i] {
		case '\\':
			i += 2
			continue
		case '"':
			return start, i + 1, true
		}
		i++
	}
	return 0, 0, false
}

// skipWSColonWS advances past whitespace, a single ':', and following whitespace,
// returning the index of the value, or -1 if the layout is not "ws : ws".
func skipWSColonWS(b []byte, i int) int {
	for i < len(b) && isJSONWS(b[i]) {
		i++
	}
	if i >= len(b) || b[i] != ':' {
		return -1
	}
	i++
	for i < len(b) && isJSONWS(b[i]) {
		i++
	}
	return i
}

func isJSONWS(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

// TestAuditFixedFile audits a delivered patches file directly: it walks every
// patch's patched_code — including return_void and whole-body stubs, not just the
// surgically forced ones — and asserts none has a stale branch offset or a dead
// adjacent double-const. Defaults to omnisec-patches.fixed.json; set
// AUDIT_PATCHES to audit any other export (e.g. a fresh analyzer.exe run).
// Skips if the file is absent.
func TestAuditFixedFile(t *testing.T) {
	fixedPath := strings.TrimSuffix(realPatchesFixture, ".json") + ".fixed.json"
	if p := os.Getenv("AUDIT_PATCHES"); p != "" {
		fixedPath = p
	}
	raw, err := os.ReadFile(fixedPath)
	if err != nil {
		t.Skipf("fixed file not present (%v); run TestRegenerateMiniPatches first", err)
	}
	var ff fixtureFile
	if err := json.Unmarshal(raw, &ff); err != nil {
		t.Fatalf("parse fixed file: %v", err)
	}
	if len(ff.Patches) == 0 {
		t.Fatal("fixed file has no patches")
	}

	badOff, dblConst, unsized := 0, 0, 0
	perType := map[string][2]int{} // patch_type → [badOffsetPatches, doubleConstPatches]
	for i := range ff.Patches {
		p := &ff.Patches[i]
		agg := perType[p.PatchType]
		if bad, sized := smaliBranchAudit(p.PatchedCode); sized {
			if bad > 0 {
				badOff += bad
				agg[0]++
				t.Logf("[%s] %s: %d stale branch offset(s)", p.PatchType, p.MethodName, bad)
			}
		} else {
			unsized++
		}
		if hasAdjacentDoubleConst(p.PatchedCode) {
			dblConst++
			agg[1]++
			t.Logf("[%s] %s: dead adjacent double-const", p.PatchType, p.MethodName)
		}
		perType[p.PatchType] = agg
	}
	t.Logf("audited %s: %d patch(es), badOffsets=%d, doubleConstPatches=%d, unsized=%d",
		fixedPath, len(ff.Patches), badOff, dblConst, unsized)
	for ty, agg := range perType {
		t.Logf("  %-16s badOffsetPatches=%d doubleConstPatches=%d", ty, agg[0], agg[1])
	}
	if badOff != 0 || dblConst != 0 {
		t.Errorf("audit failed: badOffsets=%d, doubleConstPatches=%d", badOff, dblConst)
	}
}
