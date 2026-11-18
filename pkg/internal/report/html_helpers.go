package report

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"html"
	"math"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	"mega-analyzer/pkg/internal/types"
)

// ═══════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

func renderCodeLinesEnhanced(sb htmlWriter, lines []CodeLine, isMatchLine bool) {
	for _, line := range lines {
		rowClass := "code-row"
		if isMatchLine || line.IsMatch {
			rowClass += " code-row-match"
		}
		sb.WriteString(fmt.Sprintf(`<div class="%s">`, rowClass))
		sb.WriteString(fmt.Sprintf(`<span class="line-no">%d</span>`, line.Number))
		sb.WriteString(`<span class="code-line-content">`)
		sb.WriteString(html.EscapeString(line.Content))
		sb.WriteString(`</span></div>`)
	}
}

func firstLineNum(before []CodeLine, matchLine int) int {
	if len(before) > 0 {
		return before[0].Number
	}
	return matchLine
}

func lastLineNum(after []CodeLine, matchLine int) int {
	if len(after) > 0 {
		return after[len(after)-1].Number
	}
	return matchLine
}

// truncate shortens s to at most maxLen bytes, appending "..." when cut.
// The cut respects UTF-8 rune boundaries so multi-byte characters are never
// split in half (the old byte slice produced mojibake in the HTML output).
func truncate(s string, maxLen int) string {
	if maxLen <= 3 || len(s) <= maxLen {
		return s
	}
	cut := maxLen - 3
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}

// ═══════════════════════════════════════════════════════════════════════════════
// ICON HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

var (
	iconPaths     map[string]string
	iconPathsOnce sync.Once
)

// initIcons is safe for concurrent reporters: the previous bare nil-check
// raced when two goroutines generated reports at the same time.
func initIcons() {
	iconPathsOnce.Do(parseIconSprite)
}

func parseIconSprite() {
	iconPaths = make(map[string]string)

	// Simple robust parsing of iconSprite constant
	data := iconSprite
	for {
		startTag := "<symbol id=\"icon-"
		idx := strings.Index(data, startTag)
		if idx == -1 {
			break
		}
		data = data[idx+len(startTag):]
		endId := strings.Index(data, "\"")
		if endId == -1 {
			break
		}
		id := data[:endId]

		data = data[endId:]
		startContent := strings.Index(data, ">")
		if startContent == -1 {
			break
		}
		data = data[startContent+1:]

		endSymbol := strings.Index(data, "</symbol>")
		if endSymbol == -1 {
			break
		}
		content := data[:endSymbol]
		iconPaths[id] = content
		data = data[endSymbol+len("</symbol>"):]
	}
}

func icon(id string) string {
	return iconWithClass(id, "")
}

func iconWithClass(id, class string) string {
	initIcons()
	cls := "icon icon-" + id
	if class != "" {
		cls += " " + class
	}
	content := iconPaths[id]
	if content == "" {
		// Fallback to use href if icon is not found in sprite
		return fmt.Sprintf(
			`<svg class="%s" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><use href="#icon-%s"></use></svg>`,
			cls, id)
	}
	return fmt.Sprintf(
		`<svg class="%s" viewBox="0 0 24 24" aria-hidden="true" focusable="false">%s</svg>`,
		cls, content)
}

func iconForRisk(r types.RiskLevel) string {
	switch r {
	case types.RiskCritical, types.RiskHigh:
		return icon("alert-triangle")
	case types.RiskMedium:
		return icon("alert-circle")
	case types.RiskLow, types.RiskNone:
		return icon("circle")
	default:
		return icon("circle")
	}
}

func iconForRiskClass(risk string) string {
	switch strings.ToLower(risk) {
	case "critical", "high":
		return icon("alert-triangle")
	case "medium":
		return icon("alert-circle")
	case "low", "none", "clean":
		return icon("circle")
	case "info":
		return icon("info-circle")
	default:
		return icon("circle")
	}
}

func iconForPriority(priority int) string {
	switch types.Priority(priority) {
	case types.PriorityCritical, types.PriorityHigh:
		return icon("alert-triangle")
	case types.PriorityMedium:
		return icon("alert-circle")
	case types.PriorityLow:
		return icon("circle")
	default:
		return icon("info-circle")
	}
}

func iconForGroup(group string) string {
	switch group {
	case types.GroupLicense:
		return icon("key")
	case types.GroupBilling:
		return icon("credit-card")
	case types.GroupPremium:
		return icon("star")
	case types.GroupSubscription:
		return icon("repeat")
	case types.GroupTrial:
		return icon("clock")
	case types.GroupSecurity:
		return icon("shield")
	case types.GroupThreatRules:
		return icon("alert-hex")
	case types.GroupPiracy:
		return icon("skull")
	case types.GroupAds:
		return icon("speakerphone")
	case types.GroupAnalytics:
		return icon("chart-bar")
	case types.GroupConfig:
		return icon("cloud")
	case types.GroupObfuscation:
		return icon("code")
	case types.GroupNetwork:
		return icon("world")
	case types.GroupTechnical:
		return icon("tool")
	case types.GroupResources:
		return icon("folder")
	default:
		return icon("help-circle")
	}
}

var categoryGroupByName = func() map[string]string {
	m := make(map[string]string, 128)
	for _, cat := range types.GetAllCategories() {
		info := types.GetCategoryInfo(cat)
		if info.Name != "" {
			m[info.Name] = info.Group
		}
	}
	return m
}()

func iconForCategoryName(name string) string {
	if group, ok := categoryGroupByName[name]; ok {
		return iconForGroup(group)
	}
	return icon("tag")
}

func iconForContext(ctx string) string {
	switch ctx {
	case "code":
		return icon("code")
	case "resource":
		return icon("folder")
	case "manifest":
		return icon("file-text")
	case "asset":
		return icon("package")
	default:
		return icon("help-circle")
	}
}

func ifStr(cond bool, t, f string) string {
	if cond {
		return t
	}
	return f
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func boolToJS(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func uniqueMatchCategories(matches []HTMLMatchView) []string {
	if len(matches) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(matches))
	for _, m := range matches {
		seen[m.Category] = struct{}{}
	}
	categories := make([]string, 0, len(seen))
	for cat := range seen {
		categories = append(categories, cat)
	}
	sort.Strings(categories)
	return categories
}

func buildSnippetPreview(match HTMLMatchView, maxLines int) string {
	if maxLines <= 1 {
		content := strings.TrimSpace(match.SnippetMatch.Content)
		if content == "" {
			return "(empty line)"
		}
		return truncate(content, 80)
	}

	before := match.SnippetBefore
	after := match.SnippetAfter
	wantBefore := (maxLines - 1) / 2
	wantAfter := maxLines - 1 - wantBefore

	if len(before) > wantBefore {
		before = before[len(before)-wantBefore:]
	}
	if len(after) > wantAfter {
		after = after[:wantAfter]
	}

	lines := make([]string, 0, len(before)+1+len(after))
	for _, line := range before {
		lines = append(lines, strings.TrimSpace(line.Content))
	}
	lines = append(lines, "» "+strings.TrimSpace(match.SnippetMatch.Content))
	for _, line := range after {
		lines = append(lines, strings.TrimSpace(line.Content))
	}

	preview := strings.Join(lines, " | ")
	if preview == "" {
		return "(empty)"
	}
	return truncate(preview, 120)
}

// generateMatchID creates unique ID for each match
func generateMatchID(file string, line int, category string) string {
	data := fmt.Sprintf("%s:%d:%s", file, line, category)
	hash := md5.Sum([]byte(data))
	return hex.EncodeToString(hash[:8])
}

// ═══════════════════════════════════════════════════════════════════════════════
// NEW HELPERS: Context (#1), Explanations (#7), Scoring (#8)
// ═══════════════════════════════════════════════════════════════════════════════

// inferFileContext determines context type from file path (#1)
func inferFileContext(filePath string) string {
	lower := strings.ToLower(filePath)

	switch {
	case strings.Contains(lower, "androidmanifest"):
		return "manifest"
	case strings.HasSuffix(lower, ".xml"):
		return "resource"
	case strings.HasSuffix(lower, ".smali") || strings.HasSuffix(lower, ".java") ||
		strings.HasSuffix(lower, ".kt") || strings.HasSuffix(lower, ".dex"):
		return "code"
	case strings.Contains(lower, "assets/") || strings.HasSuffix(lower, ".js") ||
		strings.HasSuffix(lower, ".json") || strings.HasSuffix(lower, ".html"):
		return "asset"
	default:
		return "unknown"
	}
}

// contextDisplay returns icon, label, and CSS class for a context type (#1)
func contextDisplay(ctx string) (icon, label, class string) {
	switch ctx {
	case "code":
		return iconForContext("code"), "Code", "ctx-code"
	case "resource":
		return iconForContext("resource"), "Resource", "ctx-resource"
	case "manifest":
		return iconForContext("manifest"), "Manifest", "ctx-manifest"
	case "asset":
		return iconForContext("asset"), "Asset", "ctx-asset"
	default:
		return iconForContext("unknown"), "Unknown", "ctx-unknown"
	}
}

// buildContextBadge generates HTML for inline context badge (#1)
func buildContextBadge(item DetectionItem) string {
	ctx := inferFileContext(item.File)
	icon, label, class := contextDisplay(ctx)
	return fmt.Sprintf(`<span class="ctx-badge %s">%s %s</span>`, class, icon, label)
}

// getPatternExplanation returns human-readable explanation for a pattern (#7)
func getPatternExplanation(category, pattern string) string {
	lowerCat := strings.ToLower(category)
	lowerPat := strings.ToLower(pattern)

	// Known pattern explanations
	explanations := map[string]string{
		// Piracy sites
		"androeed":     "Reference to androeed.ru — a known piracy/modded APK distribution site",
		"happymod":     "Reference to HappyMod — a platform for downloading modified/cracked apps",
		"apkpure":      "Reference to APKPure — third-party APK store, sometimes used for piracy",
		"apkmirror":    "Reference to APKMirror — APK hosting site (generally legitimate)",
		"mobilism":     "Reference to Mobilism — a well-known piracy forum for mobile apps",
		"4pda":         "Reference to 4PDA — Russian tech forum known for hosting cracked apps",
		"an1":          "Reference to AN1.com — a site distributing modded APKs",
		"apkmody":      "Reference to APKMody — site for modded/patched APKs",
		"rexdl":        "Reference to RexDL — site distributing cracked Android apps",
		"revdl":        "Reference to RevDL — piracy site for modded mobile games",
		"luckypatcher": "Reference to Lucky Patcher — a tool for patching, cracking, and modifying apps",
		// Behavior indicators
		"premium":   "References to premium/paid features — may indicate license bypass if unlocked unconditionally",
		"crack":     "Reference to cracking — indicates app tampering or license circumvention",
		"patch":     "Reference to patching — could indicate runtime modification of app behavior",
		"keygen":    "Reference to key generation — may indicate license key forgery",
		"license":   "License-related code — check if validation is being bypassed",
		"hack":      "Reference to hacking — indicates potential tampering or exploitation",
		"mod":       "Reference to modifications — may indicate unauthorized app alterations",
		"pirate":    "Direct reference to piracy — strong indicator of unauthorized distribution",
		"watermark": "Watermark-related code — may be removing attribution or DRM marks",
		"signature": "Signature verification code — check if being bypassed for repackaging",
		"debug":     "Debug-related code — check if debug mode is enabled in production",
		"root":      "Root detection code — may be checking for or exploiting rooted devices",
		"emulator":  "Emulator detection — may indicate anti-analysis or testing bypass",
		"hook":      "Hooking/interception code — may indicate runtime manipulation (Xposed/Frida)",
		"obfuscat":  "Obfuscation-related — code may be deliberately hidden or obscured",
		"decrypt":   "Decryption code — check if used for unpacking hidden payloads",
		"inject":    "Code injection reference — may indicate malicious payload insertion",
		"tamper":    "Tamper detection — check if app integrity verification is being bypassed",
		"unlock":    "Unlock-related code — may indicate bypassing of paid features or restrictions",
		"subscri":   "Subscription code — check if subscription validation is circumvented",
		"purchas":   "Purchase/payment code — verify In-App Purchase validation integrity",
		"billing":   "Billing code — check if Google Play Billing is properly validated",
		"validate":  "Validation code — ensure security checks are not being skipped",
		"verif":     "Verification code — check if integrity/license verification is intact",
	}

	// Try to match against known patterns
	for key, explanation := range explanations {
		if strings.Contains(lowerPat, key) || strings.Contains(lowerCat, key) {
			return explanation
		}
	}

	// Category-based fallback
	categoryFallbacks := map[string]string{
		"piracy":  "This pattern matches a known piracy/mod APK distribution indicator",
		"crack":   "This pattern indicates potential app cracking or license bypass",
		"license": "This pattern may indicate circumvention of licensing/payment systems",
		"billing": "This pattern relates to billing/payment verification",
		"secur":   "This pattern relates to security/integrity checks",
	}

	for key, explanation := range categoryFallbacks {
		if strings.Contains(lowerCat, key) {
			return explanation
		}
	}

	return "No additional information available"
}

// classifySuspicionScore returns label, CSS class, and recommendation (#8).
// The bands mirror the rating scale (pkg/internal/rating: overall 0-100 = max
// category score × 10, CRITICAL level at >= 85): a "Do Not Install" headline
// must mean the analyzer found critical evidence, not a pile of high/hygiene
// findings. Measured mismatch (2026-11-04): a clean FOSS editor showed
// "HIGHLY SUSPICIOUS / Do Not Install" at 100 while its malware category was
// LOW and confidence 29%.
func classifySuspicionScore(score int) (label, class, recommendation string) {
	switch {
	case score >= 85:
		return "HIGHLY SUSPICIOUS", "critical",
			"Do Not Install — This application shows strong indicators of piracy, tampering, or malicious modification."
	case score >= 65:
		return "SUSPICIOUS", "high",
			"Exercise Caution — Multiple concerning patterns detected. Verify the source and review the evidence before installing."
	case score >= 40:
		return "MODERATE CONCERN", "medium",
			"Review Carefully — Some suspicious patterns found. May be legitimate but warrants investigation."
	case score >= 20:
		return "LOW RISK", "low",
			"Likely Safe — Few indicators found. Patterns may be false positives or legitimate usage."
	default:
		return "CLEAN", "clean",
			"No Significant Issues — No meaningful suspicious patterns detected."
	}
}

// gaugeNeedleX returns X coordinate for gauge needle (#8)
func gaugeNeedleX(score int) float64 {
	angle := math.Pi - (float64(score)/100.0)*math.Pi
	return 100 + 80*math.Cos(angle)
}

// gaugeNeedleY returns Y coordinate for gauge needle (#8)
func gaugeNeedleY(score int) float64 {
	angle := math.Pi - (float64(score)/100.0)*math.Pi
	return 100 - 80*math.Sin(angle)
}

// ruleSeverityClass maps severity string to CSS class for rule-card
func ruleSeverityClass(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "sev-critical"
	case "high":
		return "sev-high"
	case "medium":
		return "sev-medium"
	case "low":
		return "sev-low"
	case "info":
		return "sev-info"
	default:
		return "sev-info"
	}
}
