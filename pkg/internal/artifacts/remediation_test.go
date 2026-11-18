package artifacts

import (
	"archive/zip"
	"bytes"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mega-analyzer/pkg/internal/imageforensics"
	"mega-analyzer/pkg/internal/report"
)

// R2 (Item B): attacker-controlled directory names must NOT be skipped.
func TestWalk_AttackerNamedDirsAreScanned(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"insights", "mobsf", "jspatcher", "analysis_output"} {
		dir := filepath.Join(root, "assets", name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "payload.js"), []byte("evil()"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	out, err := Walk(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 4 {
		t.Fatalf("attacker-named dirs must be scanned: want 4 candidates, got %d: %+v", len(out), out)
	}
}

// R2: the current run's real output dir is still excluded (by absolute path)
// and the exclusion is visible as a scan note.
func TestWalk_ExcludeAbsOutputDirSkipped(t *testing.T) {
	root := t.TempDir()
	outDir := filepath.Join(root, "analysis_output")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(outDir, "report.js"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(root, "a.js"), []byte("x"), 0o644)
	cands, notes, err := WalkDetailed(root, outDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cands {
		if strings.Contains(c.Path, "report.js") {
			t.Fatalf("output dir content was scanned: %+v", c)
		}
	}
	found := false
	for _, n := range notes {
		if strings.Contains(n, "output dir") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected scan note for excluded output dir, got %v", notes)
	}
}

// R3 (Item A): contract test pinning the smali exclusion boundary.
func TestWalk_SmaliContract(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"smali", "smali_classes2", "smali_assets"} {
		os.MkdirAll(filepath.Join(root, d), 0o755)
		os.WriteFile(filepath.Join(root, d, "a.js"), []byte("x"), 0o644)
	}
	// Negative case: a name that merely *starts with* "smali" (no underscore)
	// must still be scanned.
	os.MkdirAll(filepath.Join(root, "smalltalk"), 0o755)
	os.WriteFile(filepath.Join(root, "smalltalk", "b.js"), []byte("x"), 0o644)

	cands, notes, err := WalkDetailed(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(cands) != 1 || !strings.Contains(cands[0].Path, "smalltalk") {
		t.Fatalf("smali contract violated, candidates: %+v", cands)
	}
	smaliNotes := 0
	for _, n := range notes {
		if strings.Contains(n, "smali tree") {
			smaliNotes++
		}
	}
	if smaliNotes != 3 {
		t.Errorf("want 3 smali skip notes, got %d: %v", smaliNotes, notes)
	}
}

// R5: extensionless files must be classified via magic bytes during Walk.
func TestWalk_MagicSniffClassifiesExtensionless(t *testing.T) {
	root := t.TempDir()
	png := []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n', 0, 0, 0, 0}
	os.WriteFile(filepath.Join(root, "noext"), png, 0o644)
	cands, err := Walk(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(cands) != 1 || cands[0].Type != TypeImage {
		t.Fatalf("want one TypeImage candidate, got %+v", cands)
	}
}

// R12: walk errors surface as scan notes instead of vanishing.
func TestWalk_ErrorsRecordedAsNotes(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; permission errors are not enforceable")
	}
	root := t.TempDir()
	locked := filepath.Join(root, "locked")
	os.MkdirAll(locked, 0o755)
	os.WriteFile(filepath.Join(locked, "x.js"), []byte("x"), 0o644)
	if err := os.Chmod(locked, 0); err != nil {
		t.Skipf("cannot chmod: %v", err)
	}
	defer os.Chmod(locked, 0o755)
	if _, err := os.ReadDir(locked); err == nil {
		// e.g. containers with CAP_DAC_OVERRIDE: chmod 0 is not enforced.
		t.Skip("environment ignores permission bits; walk errors not reproducible")
	}
	_, notes, err := WalkDetailed(root, "")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, n := range notes {
		if strings.Contains(n, "walk error") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected walk error note, got %v", notes)
	}
}

// R4: non-zip archive formats must not produce a bogus zip-parse warning.
func TestFillArchive_NonZipFormatsNoBogusWarning(t *testing.T) {
	item := &report.ArtifactItem{}
	gzHeader := []byte{0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00}
	fillArchive(item, gzHeader, Candidate{Path: "a.tar.gz"})
	if len(item.Warnings) != 0 {
		t.Errorf("unexpected warnings for tar.gz: %v", item.Warnings)
	}
	if item.Forensic.Verdict != imageforensics.VerdictOK {
		t.Errorf("want OK verdict, got %q", item.Forensic.Verdict)
	}
	if item.Archive == nil {
		t.Error("expected archive card even without entry listing")
	}
}

// R4: corrupt data with a zip-family name still warns (regression guard).
func TestFillArchive_ZipFamilyStillParsed(t *testing.T) {
	item := &report.ArtifactItem{}
	fillArchive(item, []byte("not a zip"), Candidate{Path: "bad.zip"})
	if len(item.Warnings) == 0 {
		t.Error("corrupt .zip must still produce a parse warning")
	}
}

// R9: entry listing is capped with an explicit truncation warning.
func TestFillArchive_EntryCapTruncates(t *testing.T) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	total := maxArchiveEntries + 10
	for i := 0; i < total; i++ {
		f, err := w.Create(fmt.Sprintf("f%05d.txt", i))
		if err != nil {
			t.Fatal(err)
		}
		f.Write([]byte("x"))
	}
	w.Close()

	item := &report.ArtifactItem{}
	fillArchive(item, buf.Bytes(), Candidate{Path: "big.zip"})
	if len(item.Archive.Files) != maxArchiveEntries {
		t.Fatalf("want %d listed entries, got %d", maxArchiveEntries, len(item.Archive.Files))
	}
	found := false
	for _, wrn := range item.Warnings {
		if strings.Contains(wrn, "truncated") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected truncation warning, got %v", item.Warnings)
	}
}

// R6: an item with several flag signals still counts exactly once.
func TestItemFlaggedCountsOnce(t *testing.T) {
	both := &report.ArtifactItem{
		Forensic: report.ForensicReport{Verdict: imageforensics.VerdictSuspicious},
		Image:    &report.ImageArtifact{SensitiveLabel: "sensitive"},
	}
	if !itemFlagged(both) {
		t.Error("doubly-signalled item must be flagged")
	}
	clean := &report.ArtifactItem{Forensic: report.ForensicReport{Verdict: imageforensics.VerdictOK}}
	if itemFlagged(clean) {
		t.Error("clean item must not be flagged")
	}
	imgOnly := &report.ArtifactItem{Image: &report.ImageArtifact{SensitiveLabel: "x"}}
	if !itemFlagged(imgOnly) {
		t.Error("sensitive-image item must be flagged")
	}
}

// R7: oversized files are rejected before being loaded into memory.
func TestReadCappedAndOversizedCard(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "big.bin")
	t.Cleanup(func() {
		for attempt := 0; attempt < 20; attempt++ {
			if err := os.Remove(p); err == nil || os.IsNotExist(err) {
				return
			}
			time.Sleep(time.Millisecond)
		}
	})
	os.WriteFile(p, make([]byte, 4096), 0o644)

	if _, err := readCapped(p, 1024); err != errTooLarge {
		t.Fatalf("want errTooLarge, got %v", err)
	}
	if data, err := readCapped(p, 8192); err != nil || len(data) != 4096 {
		t.Fatalf("in-cap read failed: %d bytes, err %v", len(data), err)
	}

	old := maxAnalyzeBytes
	maxAnalyzeBytes = 1024
	defer func() { maxAnalyzeBytes = old }()
	item := buildItem(0, Candidate{Path: "big.bin", AbsPath: p, Size: 4096, Type: TypeOther}, NewBudget(10, 200), "", Options{})
	if item == nil {
		t.Fatal("expected stub card for oversized file")
	}
	if item.SHA256 != "" {
		t.Error("oversized file must not be read/hashed")
	}
	found := false
	for _, w := range item.Warnings {
		if strings.Contains(w, "analysis skipped") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected analysis-skipped warning, got %v", item.Warnings)
	}
}

// R8: a panicking enrichment must not crash the run.
func TestEnrichSafelyRecoversPanic(t *testing.T) {
	item := &report.ArtifactItem{}
	enrichSafely(item, func() { panic("boom") })
	if len(item.Warnings) == 0 || !strings.Contains(item.Warnings[0], "internal error") {
		t.Fatalf("expected internal-error warning, got %v", item.Warnings)
	}
	if item.Forensic.Verdict != imageforensics.VerdictSuspicious {
		t.Errorf("want suspicious verdict after panic, got %q", item.Forensic.Verdict)
	}
}

// R10: uint64 sizes are clamped, never wrapped negative.
func TestClampToInt64(t *testing.T) {
	if got := clampToInt64(math.MaxUint64); got != math.MaxInt64 {
		t.Errorf("want MaxInt64, got %d", got)
	}
	if got := clampToInt64(42); got != 42 {
		t.Errorf("want 42, got %d", got)
	}
}

// R11: MB-to-bytes conversion clamps instead of overflowing to negative.
func TestNewBudgetOverflowClamped(t *testing.T) {
	b := NewBudget(math.MaxInt, math.MaxInt)
	if b.maxFileBytes != math.MaxInt64 || b.totalBytes != math.MaxInt64 {
		t.Fatalf("overflow not clamped: maxFile=%d total=%d", b.maxFileBytes, b.totalBytes)
	}
	if !b.CanEmbed(123) {
		t.Error("clamped budget must still allow embedding")
	}
	if got := mbToBytes(10); got != 10<<20 {
		t.Errorf("normal conversion broken: %d", got)
	}
}

// R13: the budget is charged with the real embedded payload size
// (base64 expansion included), not the raw stat size.
func TestBudgetChargedWithEmbeddedBytes(t *testing.T) {
	dir := t.TempDir()
	data := bytes.Repeat([]byte{'a'}, 999)
	p := filepath.Join(dir, "a.bin")
	os.WriteFile(p, data, 0o644)

	b := NewBudget(10, 200)
	item := buildItem(0, Candidate{Path: "a.bin", AbsPath: p, Size: 999, Type: TypeOther}, b, "", Options{})
	if item.EmbeddedDataURI == "" {
		t.Fatal("expected inline embed")
	}
	if b.Used() != int64(len(item.EmbeddedDataURI)) {
		t.Errorf("budget charged %d, want embedded size %d", b.Used(), len(item.EmbeddedDataURI))
	}
	if b.Used() <= 999 {
		t.Error("base64 expansion must be accounted for")
	}
}

// R14: sanitized names are length-capped; nothing is dropped silently.
func TestSanitizeNameLengthCapped(t *testing.T) {
	long := strings.Repeat("a", 300) + ".png"
	if got := sanitizeName(long); len(got) > 100 {
		t.Errorf("sanitized name too long: %d", len(got))
	}
	if got := sanitizeName("ok.png"); got != "ok.png" {
		t.Errorf("short names must be unchanged, got %q", got)
	}
}

func TestNoOutputDirWarning(t *testing.T) {
	dir := t.TempDir()
	data := make([]byte, 2<<20) // 2 MB > 1 MB per-file cap
	p := filepath.Join(dir, "big.bin")
	os.WriteFile(p, data, 0o644)

	item := buildItem(0, Candidate{Path: "big.bin", AbsPath: p, Size: int64(len(data)), Type: TypeOther}, NewBudget(1, 200), "", Options{})
	if item.EmbeddedDataURI != "" || item.ExternalPath != "" {
		t.Fatal("test setup wrong: content should be neither embedded nor external")
	}
	found := false
	for _, w := range item.Warnings {
		if strings.Contains(w, "content omitted") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected content-omitted warning, got %v", item.Warnings)
	}
}

// R16: control characters are stripped from report-bound paths.
func TestSanitizeDisplayStripsControlChars(t *testing.T) {
	in := "evil\x1b[31m\npath\x7f.js"
	got := sanitizeDisplay(in)
	for _, r := range got {
		if r < 0x20 || r == 0x7f {
			t.Fatalf("control char survived: %q", got)
		}
	}
	if sanitizeDisplay("clean/path.js") != "clean/path.js" {
		t.Error("clean paths must be unchanged")
	}

	dir := t.TempDir()
	p := filepath.Join(dir, "x.txt")
	os.WriteFile(p, []byte("x"), 0o644)
	item := buildItem(0, Candidate{Path: "bad\x1b.txt", AbsPath: p, Size: 1, Type: TypeOther}, NewBudget(10, 200), "", Options{})
	if strings.ContainsRune(item.Path, 0x1b) {
		t.Errorf("item.Path contains control char: %q", item.Path)
	}
}

// R16: active content in SVGs is flagged at the source.
func TestSVGActiveContentDetection(t *testing.T) {
	active := []string{
		`<svg onload="alert(1)"></svg>`,
		`<svg onclick="x()"><rect/></svg>`,
		`<svg><script>evil()</script></svg>`,
		`<svg><set attributeName="href" onbegin="x()"/></svg>`,
		`<svg><foreignObject><body/></foreignObject></svg>`,
		`<svg><animate attributeName="href" values="#ok;javascript:x()"/></svg>`,
	}
	for _, s := range active {
		if !svgActiveContent("a.svg", []byte(s)) {
			t.Errorf("active content missed: %s", s)
		}
	}
	if svgActiveContent("a.svg", []byte(`<svg><rect width="1"/></svg>`)) {
		t.Error("plain svg falsely flagged")
	}
	if svgActiveContent("a.png", []byte("onclick=")) {
		t.Error("non-svg falsely flagged")
	}

	item := &report.ArtifactItem{}
	fillImage(item, []byte(`<svg onclick="x()"><rect/></svg>`), Candidate{Path: "a.svg"})
	found := false
	for _, r := range item.Forensic.Reasons {
		if strings.Contains(r, "active content") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected active-content reason, got %v", item.Forensic.Reasons)
	}
	if item.Forensic.Verdict == imageforensics.VerdictOK {
		t.Error("active svg must not be verdict OK")
	}
}
