package jspatcher

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ─── Report types ─────────────────────────────────────────────────────────────

// ReportJSON is the machine-readable jspatch.json output.
type ReportJSON struct {
	AnalysisStatus string            `json:"analysis_status"`
	Diagnostics    []string          `json:"diagnostics,omitempty"`
	SourceMaps     SourceMapCoverage `json:"source_maps"`
	Matches        []*JSPatchMatch   `json:"matches"`
	GeneratedAt    string            `json:"generated_at"`
	Target         string            `json:"target"`
	BundleType     string            `json:"bundle_type"`
	IsHermes       bool              `json:"is_hermes"`
	Hermes         []*HermesAnalysis `json:"hermes_analysis,omitempty"`
	Stats          ReportStats       `json:"stats"`
	Groups         []ReportGroupJSON `json:"groups"`
	Patches        []ReportPatchJSON `json:"patches"`
	Applied        []AppliedPatch    `json:"applied,omitempty"`
	Errors         []string          `json:"errors,omitempty"`
}

type ReportStats struct {
	TotalFiles   int `json:"total_files"`
	ScannedFiles int `json:"scanned_files"`
	MatchCount   int `json:"match_count"`
	GroupCount   int `json:"group_count"`
	PatchCount   int `json:"patch_count"`
	AppliedCount int `json:"applied_count"`
	SkippedCount int `json:"skipped_count"`
}

type ReportGroupJSON struct {
	Symbol     string          `json:"symbol"`
	Category   JSPatchCategory `json:"category"`
	RefCount   int             `json:"ref_count"`
	Confidence int             `json:"confidence"`
	Strategy   PatchStrategy   `json:"strategy,omitempty"`
	Severity   string          `json:"severity"`
	Impact     string          `json:"impact"`
	FilePath   string          `json:"file_path"`
	LineNum    int             `json:"line_num"`
}

type ReportPatchJSON struct {
	FilePath    string        `json:"file_path"`
	LineNum     int           `json:"line_num"`
	Strategy    PatchStrategy `json:"strategy"`
	Before      string        `json:"before"`
	After       string        `json:"after"`
	IsValid     bool          `json:"is_valid"`
	Description string        `json:"description,omitempty"`
}

// ─── Markdown generator ───────────────────────────────────────────────────────

// GenerateMarkdownReport writes JSPATCH.md to outputDir and returns the path.
func GenerateMarkdownReport(result *JSPatchResult, outputDir string) (string, error) {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", err
	}
	path := filepath.Join(outputDir, "JSPATCH.md")

	var sb strings.Builder
	writeMD(&sb, result)

	if err := os.WriteFile(path, []byte(sb.String()), 0644); err != nil {
		return "", err
	}
	return path, nil
}

// GenerateJSONReport writes jspatch.json to outputDir and returns the path.
func GenerateJSONReport(result *JSPatchResult, outputDir string) (string, error) {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", err
	}
	path := filepath.Join(outputDir, "jspatch.json")

	j := buildJSON(result)
	data, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return "", err
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return "", err
	}
	return path, nil
}

// ─── Markdown builder ─────────────────────────────────────────────────────────

func writeMD(sb *strings.Builder, r *JSPatchResult) {
	sb.WriteString("# JS Bundle Patch Report\n\n")
	sb.WriteString(fmt.Sprintf("> Generated: %s  \n", time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("> Target: `%s`  \n", r.Target))
	sb.WriteString(fmt.Sprintf("> Bundle type: **%s**\n\n", r.BundleType))

	sb.WriteString(fmt.Sprintf("> Analysis coverage: **%s**\n\n", r.AnalysisStatus))
	if r.SourceMaps.TotalSources > 0 {
		sb.WriteString(fmt.Sprintf("Source maps: **%d / %d** sources scanned, %d skipped, %d truncated; %d / %d bytes.\n\n", r.SourceMaps.ScannedSources, r.SourceMaps.TotalSources, r.SourceMaps.SkippedSources, r.SourceMaps.TruncatedSources, r.SourceMaps.ScannedBytes, r.SourceMaps.TotalBytes))
	}
	for _, diagnostic := range r.Diagnostics {
		sb.WriteString("- Coverage: " + diagnostic + "\n")
	}
	if len(r.Diagnostics) > 0 {
		sb.WriteString("\n")
	}
	if r.IsHermes {
		sb.WriteString("> [!NOTE]\n")
		sb.WriteString("> **Hermes bytecode was analyzed by the built-in HBC parser.** No external tool is required.\n")
		sb.WriteString("> Binary rewriting stays read-only because changing instruction widths can corrupt a compiled bundle.\n\n")
		for _, h := range r.Hermes {
			if !h.Parsed {
				sb.WriteString(fmt.Sprintf("- `%s`: structured parse unavailable (%s)\n", h.Path, h.ParseError))
				continue
			}
			sb.WriteString(fmt.Sprintf("- `%s`: HBC v%d, %d strings, %d functions, %d modules, %d endpoints, %d bridge strings, %d recorded call sites\n",
				h.Path, h.Version, h.StringCount, h.FunctionCount, h.ModuleCount, len(h.Endpoints), len(h.Bridges), len(h.CallEdges)))
			c := h.GraphCoverage
			sb.WriteString(fmt.Sprintf("  Coverage **%s**: %d/%d functions decoded, %d failed, %d skipped; %d/%d bytes; %d direct, %d unresolved, %d builtin calls; %d omitted call sites.\n", h.Status, c.DecodedFunctions, c.TotalFunctions, c.FailedFunctions, c.SkippedFunctions, c.ScannedBytes, c.TotalBytes, c.DirectCalls, c.IndirectCalls, c.BuiltinCalls, c.DroppedCalls))
		}
		sb.WriteString("\n")
	}

	// ── Summary table ──────────────────────────────────────────────────────
	sb.WriteString("## Summary\n\n")
	sb.WriteString("| Metric | Value |\n|---|---|\n")
	sb.WriteString(fmt.Sprintf("| Files scanned | %d / %d |\n", r.ScannedFiles, r.TotalFiles))
	sb.WriteString(fmt.Sprintf("| Unique symbols found | **%d** |\n", r.GroupCount))
	sb.WriteString(fmt.Sprintf("| Total occurrences | %d |\n", r.MatchCount))
	sb.WriteString(fmt.Sprintf("| Patches proposed | %d |\n", r.PatchCount))
	sb.WriteString(fmt.Sprintf("| Patches applied | %d |\n", len(r.Applied)))
	sb.WriteString(fmt.Sprintf("| Below threshold (skipped) | %d |\n", r.SkippedCount))
	sb.WriteString("\n")

	// ── Category overview ──────────────────────────────────────────────────
	sb.WriteString("## Category Overview\n\n")
	sb.WriteString("| Category | Severity | Symbols | Occurrences |\n|---|---|---|---|\n")

	// Aggregate by category.
	type catRow struct {
		cat         JSPatchCategory
		meta        CategoryMeta
		symbolCount int
		matchCount  int
	}
	catRows := make(map[JSPatchCategory]*catRow)
	for _, g := range r.Groups {
		cr, ok := catRows[g.Category]
		if !ok {
			cr = &catRow{cat: g.Category, meta: AllCategoryMeta[g.Category]}
			catRows[g.Category] = cr
		}
		cr.symbolCount++
		cr.matchCount += len(g.AllMatches)
	}
	sortedCats := make([]*catRow, 0, len(catRows))
	for _, cr := range catRows {
		sortedCats = append(sortedCats, cr)
	}
	sort.Slice(sortedCats, func(i, j int) bool {
		return sortedCats[i].meta.SortOrder < sortedCats[j].meta.SortOrder
	})
	for _, cr := range sortedCats {
		sb.WriteString(fmt.Sprintf("| **%s** | %s | %d | %d |\n",
			cr.meta.Name, cr.meta.Severity, cr.symbolCount, cr.matchCount))
	}
	sb.WriteString("\n")

	// ── Per-group details ─────────────────────────────────────────────────
	sb.WriteString("## Findings\n\n")

	currentCat := JSPatchCategory("")
	for _, g := range r.Groups {
		if g.Category != currentCat {
			currentCat = g.Category
			meta := AllCategoryMeta[currentCat]
			sb.WriteString(fmt.Sprintf("### [%s] %s\n\n", strings.ToUpper(string(currentCat)), meta.Name))
			sb.WriteString(fmt.Sprintf("> %s\n\n", meta.Description))
		}

		bm := g.BestMatch
		confBar := confidenceBar(bm.Confidence)

		sb.WriteString(fmt.Sprintf("#### `%s` — line %d, confidence %d%% %s\n\n",
			g.Symbol, bm.LineNum, bm.Confidence, confBar))

		if len(g.AllMatches) > 1 {
			sb.WriteString(fmt.Sprintf("- **References in bundle:** %d occurrences\n", g.TotalRefs))
			sb.WriteString(fmt.Sprintf("- **Unique detection sites:** %d\n", len(g.AllMatches)))
		}

		// Context flags.
		flags := contextFlags(bm.Context)
		if flags != "" {
			sb.WriteString(fmt.Sprintf("- **Context:** %s\n", flags))
		}

		sb.WriteString(fmt.Sprintf("- **Impact:** %s\n", g.Impact))

		if bm.ProposedPatch != nil {
			pp := bm.ProposedPatch
			sb.WriteString(fmt.Sprintf("- **Strategy:** `%s`\n", pp.Strategy))
			if !pp.IsValid {
				sb.WriteString(fmt.Sprintf("- **Validation:** failed — %s\n", pp.ValidationError))
			}
			sb.WriteString("\n**Before:**\n```js\n")
			sb.WriteString(pp.Before)
			sb.WriteString("\n```\n\n**After:**\n```js\n")
			sb.WriteString(pp.After)
			sb.WriteString("\n```\n")
		} else if bm.Context.IsAlreadyPatched {
			sb.WriteString("- **Status:** already patched\n")
		} else if r.IsHermes {
			sb.WriteString("- **Status:** scan only (Hermes bytecode)\n")
		} else {
			sb.WriteString("- **Status:** patch not generated (server IP required or below confidence)\n")
		}

		// Surrounding code.
		if len(bm.SurroundingLines) > 0 {
			sb.WriteString("\n<details><summary>Context</summary>\n\n```js\n")
			sb.WriteString(strings.Join(bm.SurroundingLines, "\n"))
			sb.WriteString("\n```\n</details>\n")
		}

		sb.WriteString("\n")
	}

	// ── Applied patches ────────────────────────────────────────────────────
	if len(r.Applied) > 0 {
		sb.WriteString("## Applied Patches\n\n")
		sb.WriteString(fmt.Sprintf("**%d patches written** to disk.\n\n", len(r.Applied)))
		if len(r.BackedUp) > 0 {
			sb.WriteString("Backups:\n")
			for _, b := range r.BackedUp {
				sb.WriteString(fmt.Sprintf("- `%s`\n", b))
			}
			sb.WriteString("\n")
		}
		for i, ap := range r.Applied {
			sb.WriteString(fmt.Sprintf("**[%d]** `%s` line %d (`%s`)\n",
				i+1, filepath.Base(ap.FilePath), ap.LineNum, ap.Strategy))
		}
		sb.WriteString("\n")
	}

	// ── Errors ────────────────────────────────────────────────────────────
	if len(r.Errors) > 0 {
		sb.WriteString("## Errors\n\n")
		for _, e := range r.Errors {
			sb.WriteString(fmt.Sprintf("- %s\n", e))
		}
		sb.WriteString("\n")
	}
}

// ─── JSON builder ─────────────────────────────────────────────────────────────

func buildJSON(r *JSPatchResult) ReportJSON {
	j := ReportJSON{
		AnalysisStatus: r.AnalysisStatus,
		Diagnostics:    r.Diagnostics,
		SourceMaps:     r.SourceMaps,
		Matches:        r.Matches,
		GeneratedAt:    time.Now().Format(time.RFC3339),
		Target:         r.Target,
		BundleType:     r.BundleType,
		IsHermes:       r.IsHermes,
		Hermes:         r.Hermes,
		Stats: ReportStats{
			TotalFiles:   r.TotalFiles,
			ScannedFiles: r.ScannedFiles,
			MatchCount:   r.MatchCount,
			GroupCount:   r.GroupCount,
			PatchCount:   r.PatchCount,
			AppliedCount: len(r.Applied),
			SkippedCount: r.SkippedCount,
		},
		Applied: r.Applied,
		Errors:  r.Errors,
	}

	for _, g := range r.Groups {
		bm := g.BestMatch
		entry := ReportGroupJSON{
			Symbol:     g.Symbol,
			Category:   g.Category,
			RefCount:   g.TotalRefs,
			Confidence: bm.Confidence,
			Severity:   AllCategoryMeta[g.Category].Severity,
			Impact:     g.Impact,
			FilePath:   bm.FilePath,
			LineNum:    bm.LineNum,
		}
		if bm.ProposedPatch != nil {
			entry.Strategy = bm.ProposedPatch.Strategy
		}
		j.Groups = append(j.Groups, entry)
	}

	for _, p := range r.Patches {
		j.Patches = append(j.Patches, ReportPatchJSON{
			FilePath:    p.FilePath,
			LineNum:     p.LineNum,
			Strategy:    p.Strategy,
			Before:      p.Before,
			After:       p.After,
			IsValid:     p.IsValid,
			Description: p.Description,
		})
	}

	return j
}

// ─── Formatting helpers ────────────────────────────────────────────────────────

func confidenceBar(conf int) string {
	filled := conf / 10
	bar := strings.Repeat("█", filled) + strings.Repeat("░", 10-filled)
	return fmt.Sprintf("[%s]", bar)
}

func contextFlags(ctx MatchContext) string {
	var flags []string
	if ctx.IsFunctionDecl {
		flags = append(flags, "function-declaration")
	}
	if ctx.IsAssignment {
		flags = append(flags, "assignment")
	}
	if ctx.IsCondition {
		flags = append(flags, "condition")
	}
	if ctx.IsCallSite {
		flags = append(flags, "call-site")
	}
	if ctx.IsNegated {
		flags = append(flags, "negated(!)")
	}
	if ctx.IsAlreadyPatched {
		flags = append(flags, "ALREADY-PATCHED")
	}
	return strings.Join(flags, ", ")
}
