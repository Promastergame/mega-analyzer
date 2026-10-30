package artifacts

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"

	"mega-analyzer/pkg/internal/codescan"
	"mega-analyzer/pkg/internal/imageforensics"
	"mega-analyzer/pkg/internal/imagesensitive"
	"mega-analyzer/pkg/internal/nativeartifacts"
	"mega-analyzer/pkg/internal/report"
	"mega-analyzer/pkg/internal/threedee"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PIPELINE
//
// Orchestrates collector → classifier → per-type enrichment → JSON-ready
// ArtifactsView. Plan §10: this file lives in pkg/internal/artifacts and
// is the only entry point exposed to the report builder.
// ═══════════════════════════════════════════════════════════════════════════════

// Options controls pipeline behaviour. Mirrors report.ArtifactsOptions
// but kept here to avoid an import cycle.
type Options struct {
	ExtractedDir string
	OutputDir    string
	MaxFileMB    int
	BudgetMB     int
	AllowExport  bool
	NoImageBlur  bool

	// NativeScanLookup returns native scan input keyed by relative path.
	NativeScanLookup func(rel string) *nativeartifacts.ScanInput
	// SmaliClasses lists Smali class names available for JNI resolution.
	SmaliClasses []string
	// CrackPointsByPath maps absolute file paths to crack-point summaries.
	CrackPointsByPath map[string][]string
}

// MaxFileMBDefault is exposed so callers can apply the same default the
// CLI does without re-declaring the magic number.
const MaxFileMBDefault = 10

// BudgetMBDefault matches the CLI default.
const BudgetMBDefault = 200

// Build runs the full artifact pipeline and returns a ready-to-render
// ArtifactsView. Returns nil when ExtractedDir is empty or no artifacts
// remain after classification.
func Build(opts Options) (*report.ArtifactsView, error) {
	if opts.ExtractedDir == "" {
		return nil, nil
	}

	candidates, scanNotes, err := WalkDetailed(opts.ExtractedDir, opts.OutputDir)
	if err != nil {
		// Walk errors are non-fatal — we still want whatever we found.
		_ = err
	}
	if len(candidates) == 0 {
		return nil, nil
	}

	maxFile := opts.MaxFileMB
	if maxFile <= 0 {
		maxFile = MaxFileMBDefault
	}
	totalBudget := opts.BudgetMB
	if totalBudget <= 0 {
		totalBudget = BudgetMBDefault
	}
	budget := NewBudget(maxFile, totalBudget)

	view := &report.ArtifactsView{
		AllowExport: opts.AllowExport,
		NoImageBlur: opts.NoImageBlur,
		Summary: report.ArtifactsSummary{
			ByType:    map[string]int{},
			ScanNotes: scanNotes,
		},
	}

	externalRoot := ""
	if opts.OutputDir != "" {
		externalRoot = filepath.Join(opts.OutputDir, "artifacts")
	}

	for i, c := range candidates {
		item := buildItem(i, c, budget, externalRoot, opts)
		if item == nil {
			continue
		}
		view.Items = append(view.Items, *item)
		view.Summary.Total++
		view.Summary.ByType[string(c.Type)]++
		// Count each artifact at most once even when several signals fire. R6.
		if itemFlagged(item) {
			view.Summary.Flagged++
		}
	}

	if view.Summary.Total == 0 {
		return nil, nil
	}
	return view, nil
}

func buildItem(index int, c Candidate, budget *Budget, externalRoot string, opts Options) *report.ArtifactItem {
	item := &report.ArtifactItem{
		ID: fmt.Sprintf("art_%04d", index+1),
		// Strip control characters so adversarial names cannot smuggle
		// terminal escapes / log injection into the report. R16.
		Path: sanitizeDisplay(c.Path),
		Type: string(c.Type),
		Size: c.Size,
	}

	data, err := readCapped(c.AbsPath, maxAnalyzeBytes)
	if errors.Is(err, errTooLarge) {
		// R7: refuse to load huge files into memory; emit a stub card so
		// the file stays visible in the report.
		item.Warnings = append(item.Warnings, fmt.Sprintf(
			"analysis skipped: file larger than %d MB analysis cap", maxAnalyzeBytes>>20))
		item.Forensic = report.ForensicReport{Verdict: imageforensics.VerdictOK}
		return item
	}
	if err != nil {
		// Cannot read: still emit a card so the user sees something.
		item.Warnings = append(item.Warnings, "read failed: "+err.Error())
		item.Forensic = report.ForensicReport{Verdict: imageforensics.VerdictSuspicious}
		return item
	}

	sum := sha256.Sum256(data)
	item.SHA256 = hex.EncodeToString(sum[:])
	item.Mime = imageforensics.SniffMime(data)

	// Per-type enrichment, isolated so one malformed file cannot panic
	// the whole run. R8.
	enrichSafely(item, func() {
		switch c.Type {
		case TypeImage:
			fillImage(item, data, c)
		case TypeModel3D:
			fillThreeDee(item, data, c)
		case TypeNative:
			fillNative(item, data, c, opts)
		case TypeCode:
			fillCode(item, data, c)
		case TypeArchive:
			fillArchive(item, data, c)
		default:
			item.Forensic = report.ForensicReport{Verdict: imageforensics.VerdictOK}
		}
	})

	// Embed vs external. Gate on the actual byte count (the stat size from
	// the walk can change before the read) and charge the budget with the
	// real embedded payload size, base64 expansion included, so the total
	// budget reflects what actually lands in the report. R13.
	if budget.CanEmbed(int64(len(data))) {
		mime := item.Mime
		if mime == "" {
			mime = "application/octet-stream"
		}
		item.EmbeddedDataURI = "data:" + mime + ";base64," + base64.StdEncoding.EncodeToString(data)
		budget.Charge(int64(len(item.EmbeddedDataURI)))
	} else if externalRoot != "" {
		// Copy to artifacts/ subdir so the HTML can reference it.
		relTarget := filepath.Join(externalRoot, fmt.Sprintf("%s_%s", item.ID, sanitizeName(filepath.Base(c.Path))))
		if err := writeExternal(relTarget, data); err == nil {
			rel := filepath.ToSlash(relTargetRelative(externalRoot, relTarget))
			item.ExternalPath = "artifacts/" + rel
		} else {
			item.Warnings = append(item.Warnings, "copy failed: "+err.Error())
		}
	} else {
		// R14: never drop content silently; say why nothing was embedded.
		item.Warnings = append(item.Warnings,
			"content omitted: exceeds embed budget and no output directory is configured")
	}

	return item
}

func relTargetRelative(root, target string) string {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return filepath.Base(target)
	}
	return rel
}

func writeExternal(target string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		return err
	}
	// Exclusive create: refuse to write through a pre-existing file or symlink at target. R1.
	f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, byteReader(data))
	return err
}

// byteReader is a tiny helper to avoid importing bytes here.
func byteReader(data []byte) io.Reader { return &sliceReader{data: data} }

type sliceReader struct {
	data []byte
	pos  int
}

func (s *sliceReader) Read(p []byte) (int, error) {
	if s.pos >= len(s.data) {
		return 0, io.EOF
	}
	n := copy(p, s.data[s.pos:])
	s.pos += n
	return n, nil
}

func sanitizeName(name string) string {
	out := make([]byte, 0, len(name))
	for i := 0; i < len(name); i++ {
		ch := name[i]
		switch {
		case ch >= 'a' && ch <= 'z',
			ch >= 'A' && ch <= 'Z',
			ch >= '0' && ch <= '9',
			ch == '.', ch == '-', ch == '_':
			out = append(out, ch)
		default:
			out = append(out, '_')
		}
	}
	if len(out) == 0 {
		return "artifact"
	}
	// Cap the length so "art_%04d_<name>" always stays well under
	// filesystem name limits even for adversarial names. Byte slicing is
	// safe here: out is pure ASCII by construction. R14.
	const maxNameLen = 100
	if len(out) > maxNameLen {
		out = out[:maxNameLen]
	}
	return string(out)
}

// ─── enrichment helpers ────────────────────────────────────────────────────

func fillImage(item *report.ArtifactItem, data []byte, c Candidate) {
	rep := imageforensics.Analyze(data, filepath.Ext(c.Path))
	item.Entropy = rep.Entropy
	item.Forensic = report.ForensicReport{
		MimeMismatch:     rep.MimeMismatch,
		Truncated:        rep.Truncated,
		TrailingData:     rep.TrailingData,
		PolyglotSignals:  rep.PolyglotSignals,
		SuspiciousChunks: rep.SuspiciousChunks,
		BadCRC:           rep.BadCRC,
		Reasons:          rep.Reasons,
		Verdict:          imageforensics.SanitizeVerdict(rep.Verdict),
	}

	score, label := imagesensitive.ScoreBytes(data, c.Path)
	img := &report.ImageArtifact{
		Width:          rep.Width,
		Height:         rep.Height,
		EXIF:           rep.EXIF,
		SensitiveScore: score,
	}
	if label != "" {
		img.SensitiveLabel = label
	}
	item.Image = img

	// Flag active content in SVGs at the source. The HTML report only ever
	// renders SVGs inside <img> (scripts are inert there), but exported
	// files can be opened in browsers directly; use a broader pattern list
	// than the renderer badge. R16.
	if svgActiveContent(c.Path, data) {
		item.Forensic.Reasons = append(item.Forensic.Reasons,
			"svg contains active content (script / event handler / animation)")
		if item.Forensic.Verdict == "" || item.Forensic.Verdict == imageforensics.VerdictOK {
			item.Forensic.Verdict = imageforensics.VerdictSuspicious
		}
	}
}

func fillThreeDee(item *report.ArtifactItem, data []byte, c Candidate) {
	meta := threedee.Analyze(data, filepath.Ext(c.Path))
	item.ThreeDee = &report.ThreeDeeArtifact{
		Format:    meta.Format,
		Vertices:  meta.Vertices,
		Faces:     meta.Faces,
		BBoxMin:   meta.BBoxMin,
		BBoxMax:   meta.BBoxMax,
		Triangles: meta.Triangles,
	}
	item.Forensic = report.ForensicReport{Verdict: imageforensics.VerdictOK}
}

func fillNative(item *report.ArtifactItem, data []byte, c Candidate, opts Options) {
	verdict := imageforensics.VerdictOK
	in := nativeartifacts.ScanInput{}
	if opts.NativeScanLookup != nil {
		if lookup := opts.NativeScanLookup(c.Path); lookup != nil {
			in = *lookup
			if lookup.Verdict != "" {
				verdict = lookup.Verdict
			}
		}
	}
	cps := opts.CrackPointsByPath[c.AbsPath]
	v := nativeartifacts.Build(in, opts.SmaliClasses, cps)

	bindings := make([]report.JNIBinding, 0, len(v.JNIBindings))
	for _, b := range v.JNIBindings {
		bindings = append(bindings, report.JNIBinding{Symbol: b.Symbol, SmaliTarget: b.SmaliTarget})
	}

	item.Native = &report.NativeArtifact{
		Arch:              v.Arch,
		Stripped:          v.Stripped,
		JNIBindings:       bindings,
		CrackPoints:       v.CrackPoints,
		SuspiciousStrings: v.SuspiciousStrings,
		AntiSignals:       v.AntiSignals,
		RecoveredStrings:  v.RecoveredStrings,
		ScanReportRef:     v.ScanReportRef,
		Score:             v.Score,
		Verdict:           v.Verdict,
	}
	item.Forensic = report.ForensicReport{Verdict: imageforensics.SanitizeVerdict(verdict)}

	// Hash strings list for sanity (not used in JSON, just future-proofing).
	_ = strings.Join(v.SuspiciousStrings, "|")
	_ = data
}

// fillCode runs the language-aware static-analysis pass for JS / HTML /
// proto / JSON / WASM / shell / lua / python / SQL files. The verdict
// from codescan is reflected in the artifact's ForensicReport so the
// summary bar accounts for flagged files just like images & natives.
func fillCode(item *report.ArtifactItem, data []byte, c Candidate) {
	lang := DetectLanguage(c.Path, data)
	res := codescan.Scan(c.Path, string(lang), data)

	findings := make([]report.CodeFinding, 0, len(res.Findings))
	for _, f := range res.Findings {
		findings = append(findings, report.CodeFinding{
			ID:       f.ID,
			Title:    f.Title,
			Severity: f.Severity,
			Category: f.Category,
			Line:     f.Line,
			Column:   f.Column,
			Snippet:  f.Snippet,
			Rule:     f.Rule,
			Detail:   f.Detail,
		})
	}

	code := &report.CodeArtifact{
		Language:     res.Language,
		Lines:        res.Lines,
		Bytes:        res.Bytes,
		Truncated:    res.Truncated,
		IsMinified:   res.IsMinified,
		IsObfuscated: res.IsObfuscated,
		Score:        res.Score,
		Verdict:      res.Verdict,
		Findings:     findings,
	}
	if res.Schema != nil {
		schema := &report.CodeSchema{
			Package:  res.Schema.Package,
			Imports:  res.Schema.Imports,
			Messages: res.Schema.Messages,
			Enums:    res.Schema.Enums,
			Options:  res.Schema.Options,
		}
		for _, sv := range res.Schema.Services {
			schema.Services = append(schema.Services, report.SchemaServ{
				Name: sv.Name,
				RPCs: sv.RPCs,
			})
		}
		code.Schema = schema
	}
	item.Code = code

	verdict := imageforensics.VerdictOK
	switch res.Verdict {
	case "suspicious":
		verdict = imageforensics.VerdictSuspicious
	case "potentially unsafe":
		verdict = imageforensics.VerdictPotentiallyUnsafe
	case "possible embedded payload":
		verdict = imageforensics.VerdictPossibleEmbedded
	}
	item.Forensic = report.ForensicReport{Verdict: imageforensics.SanitizeVerdict(verdict)}
}

func fillArchive(item *report.ArtifactItem, data []byte, c Candidate) {
	// Only the zip family is parseable here; other archive formats
	// (tar/gz/bz2/7z/rar) get a card without an entry listing instead of a
	// bogus "zip parse failed" warning. R4.
	if !zipFamily(c.Path, data) {
		item.Archive = &report.ArchiveArtifact{}
		item.Forensic = report.ForensicReport{Verdict: imageforensics.VerdictOK}
		return
	}
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		item.Warnings = append(item.Warnings, "zip parse failed: "+err.Error())
		item.Forensic = report.ForensicReport{Verdict: imageforensics.VerdictSuspicious}
		return
	}
	archive := &report.ArchiveArtifact{}
	for i, f := range reader.File {
		// Cap the listing so a crafted archive cannot bloat the report. R9.
		if i == maxArchiveEntries {
			item.Warnings = append(item.Warnings, fmt.Sprintf(
				"archive listing truncated: %d of %d entries shown", maxArchiveEntries, len(reader.File)))
			break
		}
		modifiedStr := f.Modified.Format("2006-01-02 15:04:05")
		archive.Files = append(archive.Files, report.ArchiveFile{
			Path:           f.Name,
			Size:           clampToInt64(f.UncompressedSize64),
			CompressedSize: clampToInt64(f.CompressedSize64),
			Modified:       modifiedStr,
		})
	}
	item.Archive = archive
	item.Forensic = report.ForensicReport{Verdict: imageforensics.VerdictOK}
}

// ─── remediation helpers ───────────────────────────────────────────────────

// maxAnalyzeBytes caps how many bytes buildItem loads into memory for one
// artifact. Declared as a variable so tests can lower it. R7.
var maxAnalyzeBytes int64 = 256 << 20 // 256 MB

// errTooLarge is returned by readCapped when a file exceeds the cap. R7.
var errTooLarge = errors.New("file exceeds analysis cap")

// readCapped reads the file, refusing to load more than limit bytes. The
// limit is enforced on the actual stream, so a file growing between stat
// and read cannot bypass it. R7.
func readCapped(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errTooLarge
	}
	return data, nil
}

// enrichSafely runs fn and converts a panic into a warning on the item so
// one malformed file cannot crash the whole pipeline. R8.
func enrichSafely(item *report.ArtifactItem, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			item.Warnings = append(item.Warnings, fmt.Sprintf("analysis failed (internal error): %v", r))
			item.Forensic = report.ForensicReport{Verdict: imageforensics.VerdictSuspicious}
		}
	}()
	fn()
}

// itemFlagged reports whether the item counts as flagged in the summary.
// Boolean by design: an item with several signals still counts once. R6.
func itemFlagged(item *report.ArtifactItem) bool {
	if item.Forensic.Verdict != "" && item.Forensic.Verdict != imageforensics.VerdictOK {
		return true
	}
	return item.Image != nil && item.Image.SensitiveLabel != ""
}

// sanitizeDisplay replaces control characters in attacker-controlled
// strings destined for the report (paths). R16.
func sanitizeDisplay(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '_'
		}
		return r
	}, s)
}

// The canonical active-content pattern list lives in report.SVGActivePatterns
// so this check and the renderer badge cannot drift apart again (D1).

// svgActiveContent reports whether an SVG contains scripting / event
// handler / animation constructs that could execute outside an <img>
// context. R16.
func svgActiveContent(path string, data []byte) bool {
	if !strings.HasSuffix(strings.ToLower(path), ".svg") {
		head := data
		if len(head) > 1024 {
			head = head[:1024]
		}
		if !strings.Contains(strings.ToLower(string(head)), "<svg") {
			return false
		}
	}
	return report.SVGHasActiveContent(data)
}

// zipFamily reports whether the artifact is a zip-container format that
// archive/zip can actually parse (zip/apk/jar, or PK magic). R4.
func zipFamily(path string, data []byte) bool {
	lower := strings.ToLower(path)
	if strings.HasSuffix(lower, ".zip") || strings.HasSuffix(lower, ".apk") || strings.HasSuffix(lower, ".jar") {
		return true
	}
	return len(data) >= 2 && data[0] == 'P' && data[1] == 'K'
}

// maxArchiveEntries caps the per-archive entry listing in the report. R9.
const maxArchiveEntries = 4096

// clampToInt64 converts a uint64 size to int64 without overflow. R10.
func clampToInt64(v uint64) int64 {
	if v > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(v)
}
