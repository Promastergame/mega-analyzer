package assetscan

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── fixtures ─────────────────────────────────────────────────────────────

func testPNG(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.SetRGBA(x, y, color.RGBA{R: uint8(x * 8), G: uint8(y * 8), B: 0x60, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("png.Encode: %v", err)
	}
	return buf.Bytes()
}

// makeGLB writes a minimal but structurally valid binary glTF container.
func makeGLB(t *testing.T, doc string, bin []byte) []byte {
	t.Helper()
	var body []byte
	add := func(tag string, data []byte, fill byte) {
		for len(data)%4 != 0 {
			data = append(data, fill)
		}
		var hdr [8]byte
		binary.LittleEndian.PutUint32(hdr[0:4], uint32(len(data)))
		copy(hdr[4:8], tag)
		body = append(body, hdr[:]...)
		body = append(body, data...)
	}
	add("JSON", []byte(doc), ' ')
	if bin != nil {
		add("BIN\x00", bin, 0)
	}
	out := make([]byte, 12, 12+len(body))
	copy(out[0:4], "glTF")
	binary.LittleEndian.PutUint32(out[4:8], 2)
	binary.LittleEndian.PutUint32(out[8:12], uint32(12+len(body)))
	return append(out, body...)
}

func writeFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return p
}

func makeZip(t *testing.T, dir, name string, entries map[string][]byte) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for entryName, data := range entries {
		w, err := zw.Create(entryName)
		if err != nil {
			t.Fatalf("zip.Create(%s): %v", entryName, err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatalf("zip write: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip.Close: %v", err)
	}
	return writeFile(t, dir, name, buf.Bytes())
}

func findItem(rep *Report, suffix string) *Item {
	for i := range rep.Items {
		if strings.HasSuffix(rep.Items[i].Path, suffix) {
			return &rep.Items[i]
		}
	}
	return nil
}

// ── options ──────────────────────────────────────────────────────────────

func TestOptionsNormalizeFillsDefaultsWithoutMutating(t *testing.T) {
	orig := Options{}
	n := orig.Normalize()
	if n.MaxFileMB != 64 || n.MaxEntries != 5000 || n.MaxDepth != 2 || n.MaxPreviews != 256 || n.MaxDim != 512 {
		t.Fatalf("defaults = %+v", n)
	}
	if orig.MaxFileMB != 0 {
		t.Fatalf("Normalize mutated its receiver")
	}
	if got := n.maxBytes(); got != 64<<20 {
		t.Fatalf("maxBytes = %d, want %d", got, int64(64)<<20)
	}
}

// ── scanning ────────────────────────────────────────────────────────────

func TestScanRejectsAMissingTarget(t *testing.T) {
	if _, err := Scan(filepath.Join(t.TempDir(), "nope"), Options{}); err == nil {
		t.Fatalf("scanning a missing path succeeded")
	}
}

func TestScanFindsAGLBInADirectory(t *testing.T) {
	dir := t.TempDir()
	glb := makeGLB(t, `{"asset":{"version":"2.0"},"meshes":[]}`, nil)
	writeFile(t, dir, filepath.Join("models", "hero.glb"), glb)
	writeFile(t, dir, "readme.txt", []byte("nothing to see here"))

	rep, err := Scan(dir, Options{})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if rep.Scanned < 2 {
		t.Fatalf("Scanned = %d, want at least 2", rep.Scanned)
	}

	it := findItem(rep, "hero.glb")
	if it == nil {
		t.Fatalf("the .glb was not reported; items = %+v", rep.Items)
	}
	if it.Class != ClassThreeD {
		t.Fatalf("Class = %q, want %q", it.Class, ClassThreeD)
	}
	if it.ThreeD == nil {
		t.Fatalf("a 3D item carried no ThreeD block")
	}
	if it.ThreeD.Kind != "glb" {
		t.Fatalf("ThreeD.Kind = %q", it.ThreeD.Kind)
	}
	if rep.Root != dir {
		t.Fatalf("Root = %q, want %q", rep.Root, dir)
	}
	// A plain text file is not an asset and must not pad the results.
	if findItem(rep, "readme.txt") != nil {
		t.Fatalf("a text file was reported as an asset")
	}
}

func TestScanReadsAssetsInsideAnAPKWithoutUnpacking(t *testing.T) {
	dir := t.TempDir()
	apk := makeZip(t, dir, "game.apk", map[string][]byte{
		"assets/models/hero.glb": makeGLB(t, `{"asset":{"version":"2.0"}}`, nil),
		"res/drawable/logo.png":  testPNG(t, 8, 8),
		"classes.dex":            []byte("dex\n035\x00 not really"),
	})

	out := filepath.Join(dir, "previews")
	rep, err := Scan(apk, Options{PreviewDir: out})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	glb := findItem(rep, "hero.glb")
	if glb == nil {
		t.Fatalf("the .glb inside the APK was not found")
	}
	if glb.Container != "game.apk" {
		t.Fatalf("Container = %q, want game.apk", glb.Container)
	}
	if want := "game.apk!assets/models/hero.glb"; glb.Display() != want {
		t.Fatalf("Display() = %q, want %q", glb.Display(), want)
	}

	logo := findItem(rep, "logo.png")
	if logo == nil {
		t.Fatalf("the PNG inside the APK was not found")
	}
	if logo.Class != ClassImage || logo.Format != "png" {
		t.Fatalf("png item = class %q format %q", logo.Class, logo.Format)
	}
	if len(logo.Previews) == 0 {
		t.Fatalf("no preview was rendered for a plain PNG")
	}
	if logo.Previews[0].Lossy {
		t.Fatalf("a real PNG decode was flagged lossy")
	}
	if _, err := os.Stat(logo.Previews[0].Path); err != nil {
		t.Fatalf("preview file is missing: %v", err)
	}
	if rep.PreviewDir != out {
		t.Fatalf("PreviewDir = %q, want %q", rep.PreviewDir, out)
	}
}

func TestScanRecoversAnObfuscatedImage(t *testing.T) {
	dir := t.TempDir()
	raw := testPNG(t, 16, 16)
	enc := make([]byte, len(raw))
	for i, b := range raw {
		enc[i] = b ^ 0x5A
	}
	writeFile(t, dir, "splash.dat", enc)

	out := filepath.Join(dir, "previews")
	rep, err := Scan(dir, Options{PreviewDir: out})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	it := findItem(rep, "splash.dat")
	if it == nil {
		t.Fatalf("the XORed image was not reported")
	}
	if it.Class != ClassEncrypted {
		t.Fatalf("Class = %q, want %q (verdict %q)", it.Class, ClassEncrypted, it.Verdict)
	}
	if it.Image == nil || it.Image.Direct {
		t.Fatalf("Image = %+v, want a non-direct recovery", it.Image)
	}
	if it.Image.Transform == "" {
		t.Fatalf("no transform was recorded for a recovered image")
	}
	if !strings.Contains(it.Verdict, "recovered with") {
		t.Fatalf("Verdict = %q", it.Verdict)
	}

	// The whole point of the feature: the recovered bytes render to a PNG the
	// user can actually look at.
	if len(it.Previews) == 0 {
		t.Fatalf("no preview was produced for the recovered image")
	}
	p := it.Previews[0]
	if p.Source != "recovered" {
		t.Fatalf("preview source = %q, want recovered", p.Source)
	}
	if p.Lossy || p.Decoder != "png" {
		t.Fatalf("recovered preview = decoder %q lossy %v, want a real png", p.Decoder, p.Lossy)
	}
	blob, err := os.ReadFile(p.Path)
	if err != nil {
		t.Fatalf("reading the preview: %v", err)
	}
	if _, err := png.Decode(bytes.NewReader(blob)); err != nil {
		t.Fatalf("the written preview is not a valid PNG: %v", err)
	}
}

func TestScanSkipsOversizedEntriesInsteadOfTruncating(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "big.png", testPNG(t, 200, 200))

	// MaxFileMB is the smallest non-zero value, so a 200x200 PNG is fine but
	// the cap arithmetic is still exercised; then force a skip with a file
	// larger than a deliberately tiny cap.
	rep, err := Scan(dir, Options{MaxFileMB: 1})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if findItem(rep, "big.png") == nil {
		t.Fatalf("a 200x200 PNG was skipped under a 1 MB cap")
	}

	huge := make([]byte, 3<<20)
	copy(huge, testPNG(t, 8, 8))
	writeFile(t, dir, "huge.png", huge)

	rep, err = Scan(dir, Options{MaxFileMB: 1})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if rep.Skipped == 0 {
		t.Fatalf("an oversized file was not counted as skipped")
	}
	if findItem(rep, "huge.png") != nil {
		t.Fatalf("an oversized file was analysed anyway")
	}
}

func TestScanStopsAtMaxEntries(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 6; i++ {
		writeFile(t, dir, string(rune('a'+i))+".png", testPNG(t, 4, 4))
	}
	rep, err := Scan(dir, Options{MaxEntries: 2})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if rep.Matched > 2 {
		t.Fatalf("Matched = %d, want at most 2", rep.Matched)
	}
}

func TestScanCapsPreviewCount(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 5; i++ {
		writeFile(t, dir, string(rune('a'+i))+".png", testPNG(t, 4, 4))
	}
	out := filepath.Join(dir, "out")
	rep, err := Scan(dir, Options{PreviewDir: out, MaxPreviews: 2})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	total := 0
	for _, it := range rep.Items {
		total += len(it.Previews)
	}
	if total > 2 {
		t.Fatalf("rendered %d previews, want at most 2", total)
	}
}

func TestScanOfASingleFileUsesItsParentAsRoot(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "lone.png", testPNG(t, 4, 4))
	rep, err := Scan(p, Options{})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if rep.Root != dir {
		t.Fatalf("Root = %q, want %q", rep.Root, dir)
	}
	if findItem(rep, "lone.png") == nil {
		t.Fatalf("a single-file scan found nothing")
	}
}

func TestScanTreatsAZipWithoutAKnownExtensionAsAnArchive(t *testing.T) {
	dir := t.TempDir()
	// No .zip/.apk suffix: detection has to fall back to the PK\x03\x04 magic.
	blob := makeZip(t, dir, "bundle.pak", map[string][]byte{
		"tex/logo.png": testPNG(t, 8, 8),
	})
	rep, err := Scan(blob, Options{})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if findItem(rep, "logo.png") == nil {
		t.Fatalf("a zip with an unknown extension was not walked")
	}
}

func TestScanAllReportsEvenBoringFiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "notes.txt", []byte(strings.Repeat("plain text, no assets here. ", 8)))

	quiet, err := Scan(dir, Options{})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(quiet.Items) != 0 {
		t.Fatalf("a text file was reported without -assets-all: %+v", quiet.Items)
	}

	all, err := Scan(dir, Options{All: true})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(all.Items) == 0 {
		t.Fatalf("-assets-all reported nothing")
	}
}

func TestScanIsOrderedByClass(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "zzz.png", testPNG(t, 4, 4))
	writeFile(t, dir, "aaa.glb", makeGLB(t, `{"asset":{"version":"2.0"}}`, nil))

	rep, err := Scan(dir, Options{})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(rep.Items) < 2 {
		t.Fatalf("expected both assets, got %d", len(rep.Items))
	}
	// 3D outranks image regardless of the alphabetical order of the names.
	if rep.Items[0].Class != ClassThreeD {
		t.Fatalf("first item class = %q, want %q", rep.Items[0].Class, ClassThreeD)
	}
	for i := 1; i < len(rep.Items); i++ {
		if classRank(rep.Items[i-1].Class) > classRank(rep.Items[i].Class) {
			t.Fatalf("items are not ordered by class: %q then %q",
				rep.Items[i-1].Class, rep.Items[i].Class)
		}
	}
}

// ── naming and reporting ────────────────────────────────────────────────────

func TestSlugifyProducesPortableNames(t *testing.T) {
	cases := map[string]string{
		"assets/models/hero":  "assets-models-hero",
		"текстура":            "",
		"a  b":                "a-b",
		"--edge--":            "edge",
		"keep_underscores_09": "keep_underscores_09",
		"":                    "",
	}
	for in, want := range cases {
		if got := slugify(in); got != want {
			t.Fatalf("slugify(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPreviewNamesNeverCollide(t *testing.T) {
	s := &scanner{opts: Options{}.Normalize(), rep: &Report{}, slugs: map[string]int{}}
	a := Item{Path: "tex/logo.png"}
	b := Item{Path: "tex/logo.png"}
	first := s.previewName(&a, "")
	second := s.previewName(&b, "")
	if first == second {
		t.Fatalf("two identical stems produced the same file name %q", first)
	}
	if !strings.HasSuffix(first, ".png") || !strings.HasSuffix(second, ".png") {
		t.Fatalf("preview names are not PNGs: %q, %q", first, second)
	}

	// A name made entirely of non-ASCII must still produce something usable.
	c := Item{Path: "текстуры/герой.png"}
	if got := s.previewName(&c, ""); !strings.HasSuffix(got, ".png") || len(got) < 5 {
		t.Fatalf("non-ASCII path produced %q", got)
	}

	// Long paths are clipped, and the clip keeps the identifying tail.
	d := Item{Path: strings.Repeat("deep/", 40) + "leaf.png"}
	name := s.previewName(&d, "tex0")
	if len(name) > 80 {
		t.Fatalf("preview name is %d chars: %q", len(name), name)
	}
	if !strings.Contains(name, "leaf") {
		t.Fatalf("the clipped name lost the leaf: %q", name)
	}
}

func TestReportJSONNeverMarshalsNull(t *testing.T) {
	rep := &Report{Target: "x"}
	blob, err := rep.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}

	// The Zig reader iterates items unconditionally; a null would be a crash
	// there and a special case in every other consumer.
	var probe struct {
		Items   *[]Item         `json:"items"`
		ByClass *map[string]int `json:"byClass"`
	}
	if err := json.Unmarshal(blob, &probe); err != nil {
		t.Fatalf("the report is not valid JSON: %v", err)
	}
	if probe.Items == nil || probe.ByClass == nil {
		t.Fatalf("items or byClass marshalled as null: %s", blob)
	}
	if len(*probe.Items) != 0 {
		t.Fatalf("an empty report produced %d items", len(*probe.Items))
	}
}

func TestReportJSONCarriesTheFieldsTheEditorReads(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "logo.png", testPNG(t, 8, 8))
	out := filepath.Join(dir, "out")
	rep, err := Scan(dir, Options{PreviewDir: out})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	blob, err := rep.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}

	// These key names are the contract with src/logic/assetscan.zig. Renaming
	// one silently breaks the editor, so they are asserted literally.
	for _, key := range []string{
		`"target"`, `"scanned"`, `"matched"`, `"skipped"`, `"previewDir"`,
		`"byClass"`, `"items"`, `"path"`, `"class"`, `"format"`, `"verdict"`,
		`"previews"`, `"decoder"`, `"lossy"`, `"source"`,
	} {
		if !bytes.Contains(blob, []byte(key)) {
			t.Fatalf("the report is missing %s\n%s", key, blob)
		}
	}
}

func TestReportTextIsRenderableAndMentionsThePreviewDir(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "logo.png", testPNG(t, 8, 8))
	out := filepath.Join(dir, "out")
	rep, err := Scan(dir, Options{PreviewDir: out})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	text := rep.Text()
	if text == "" {
		t.Fatalf("Text() produced nothing")
	}
	if !strings.Contains(text, "previews ->") || !strings.Contains(text, out) {
		t.Fatalf("Text() does not point at the preview directory:\n%s", text)
	}
	if !strings.Contains(text, "logo.png") {
		t.Fatalf("Text() does not list the asset:\n%s", text)
	}
	if rep.Counts() == "" {
		t.Fatalf("Counts() produced nothing")
	}

	// An empty scan must still render rather than panic on nil slices.
	empty := &Report{Target: "nothing"}
	if empty.Text() == "" {
		t.Fatalf("an empty report rendered as an empty string")
	}
}

func TestClassRankPutsUnknownClassesLast(t *testing.T) {
	if classRank(ClassThreeD) != 0 {
		t.Fatalf("3d is not first")
	}
	for i := 1; i < len(ClassOrder); i++ {
		if classRank(ClassOrder[i-1]) >= classRank(ClassOrder[i]) {
			t.Fatalf("ClassOrder is not strictly ranked at %d", i)
		}
	}
	if classRank("hologram") != len(ClassOrder) {
		t.Fatalf("an unknown class did not sort last")
	}
}

func TestItemDisplayJoinsTheContainer(t *testing.T) {
	if got := (Item{Path: "a/b.glb"}).Display(); got != "a/b.glb" {
		t.Fatalf("loose file Display() = %q", got)
	}
	if got := (Item{Path: "a/b.glb", Container: "game.apk"}).Display(); got != "game.apk!a/b.glb" {
		t.Fatalf("archived file Display() = %q", got)
	}
}

func TestScanReportsUnreadableEntriesWithoutStopping(t *testing.T) {
	dir := t.TempDir()
	// A file whose zip magic is a lie: opening it as an archive must fail,
	// be recorded, and leave the rest of the walk intact.
	writeFile(t, dir, "broken.apk", []byte("PK\x03\x04 and then nothing valid"))
	writeFile(t, dir, "logo.png", testPNG(t, 8, 8))

	rep, err := Scan(dir, Options{})
	if err != nil {
		t.Fatalf("Scan aborted on a corrupt archive: %v", err)
	}
	if len(rep.Errors) == 0 {
		t.Fatalf("a corrupt archive produced no error entry")
	}
	if findItem(rep, "logo.png") == nil {
		t.Fatalf("the walk stopped after the corrupt archive")
	}
}
