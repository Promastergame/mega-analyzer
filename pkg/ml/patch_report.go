package ml

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type PatchReportGenerator struct {
	prediction *PatchPrediction
	generator  *PatchGenerator
	showFix    bool
	apkName    string
}

func NewPatchReportGenerator(prediction *PatchPrediction, apkName string, showFix bool) *PatchReportGenerator {
	return &PatchReportGenerator{
		prediction: prediction,
		generator:  NewPatchGenerator(),
		showFix:    showFix,
		apkName:    apkName,
	}
}

func (prg *PatchReportGenerator) SaveToFile(outputDir string) (string, error) {
	if strings.Contains(outputDir, "::") {
		return "", fmt.Errorf("invalid output directory: %s", outputDir)
	}
	fileName := "PATCHES.md"
	if prg.showFix {
		fileName = "PATCHES_WITH_FIX.md"
	}
	filePath := filepath.Join(outputDir, fileName)

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create output dir: %w", err)
	}
	if err := os.WriteFile(filePath, []byte(prg.GenerateMarkdown()), 0644); err != nil {
		return "", fmt.Errorf("failed to write report: %w", err)
	}
	return filePath, nil
}

func (prg *PatchReportGenerator) GenerateMarkdown() string {
	var b strings.Builder

	prg.writeHeader(&b)

	// 🆕 Partial warning
	if prg.prediction.PartialResults {
		b.WriteString("> 🔴 **WARNING:** analysis timed out — results are partial.\n\n")
	}

	// 🆕 Main findings вверху
	prg.writeMainFindings(&b)
	prg.writeTopIssues(&b)

	prg.writeSummary(&b)
	prg.writeCategoryBreakdown(&b)

	if len(prg.prediction.MalwareIndicators) > 0 {
		prg.writeAuditSection(&b, "🔎 Security Audit — High-confidence Findings",
			prg.prediction.MalwareIndicators)
	}
	if len(prg.prediction.AuditFindings) > 0 {
		prg.writeAuditSection(&b, "🔎 Security Audit — Review",
			prg.prediction.AuditFindings)
	}

	if len(prg.prediction.HighRisk) > 0 {
		prg.writeRiskSection(&b, "🔴 High Risk — App Code", "Most likely targets",
			prg.prediction.HighRisk)
	}
	if len(prg.prediction.MediumRisk) > 0 {
		prg.writeRiskSection(&b, "🟡 Medium Risk — App Code", "Potential targets",
			prg.prediction.MediumRisk)
	}
	if len(prg.prediction.LowRisk) > 0 {
		prg.writeRiskSection(&b, "🟢 Low Risk", "Minor possibilities",
			prg.prediction.LowRisk)
	}

	// 🆕 Library findings — отдельная секция
	if len(prg.prediction.LibraryFindings) > 0 {
		prg.writeLibrarySection(&b, prg.prediction.LibraryFindings)
	}

	prg.writeFooter(&b)
	return b.String()
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTIONS
// ═══════════════════════════════════════════════════════════════════════════════

func (prg *PatchReportGenerator) writeHeader(b *strings.Builder) {
	if prg.showFix {
		b.WriteString("# 🎯 Patch Points + Fix Suggestions\n\n")
	} else {
		b.WriteString("# 🎯 Patch Points Analysis\n\n")
	}
	b.WriteString(fmt.Sprintf("> **APK:** %s  \n", prg.apkName))
	b.WriteString(fmt.Sprintf("> **Generated:** %s  \n", time.Now().Format("2006-01-02 15:04:05")))
	b.WriteString(fmt.Sprintf("> **Patterns:** %d in %d categories  \n",
		CountPatterns(), CountCategories()))
	b.WriteString("> **Generator:** ML Patch Predictor  \n\n")
	b.WriteString("---\n\n")
}

// 🆕 MAIN FINDINGS
func (prg *PatchReportGenerator) writeMainFindings(b *strings.Builder) {
	if len(prg.prediction.MainFindings) == 0 {
		return
	}
	b.WriteString("## ⚠️ Main Findings\n\n")
	for _, f := range prg.prediction.MainFindings {
		b.WriteString(fmt.Sprintf("- %s\n", f))
	}
	b.WriteString("\n")
}

// 🆕 TOP ISSUES
func (prg *PatchReportGenerator) writeTopIssues(b *strings.Builder) {
	if len(prg.prediction.TopIssues) == 0 {
		return
	}
	b.WriteString("## 🥇 Top Issues\n\n")
	for i, issue := range prg.prediction.TopIssues {
		b.WriteString(fmt.Sprintf("%d. %s\n", i+1, issue))
	}
	b.WriteString("\n")
}

func (prg *PatchReportGenerator) writeSummary(b *strings.Builder) {
	s := &prg.prediction.Stats
	b.WriteString("## 📊 Summary\n\n")
	b.WriteString("| Metric | Value |\n|--------|-------|\n")
	b.WriteString(fmt.Sprintf("| Files scanned | %d |\n", s.TotalFilesScanned))
	b.WriteString(fmt.Sprintf("| Methods analyzed | %d |\n", s.MethodsAnalyzed))
	b.WriteString(fmt.Sprintf("| **Patch points (app code)** | **%d** |\n",
		s.HighRiskCount+s.MediumRiskCount+s.LowRiskCount))
	b.WriteString(fmt.Sprintf("| 🔴 High risk | %d |\n", s.HighRiskCount))
	b.WriteString(fmt.Sprintf("| 🟡 Medium risk | %d |\n", s.MediumRiskCount))
	b.WriteString(fmt.Sprintf("| 🟢 Low risk | %d |\n", s.LowRiskCount))
	b.WriteString(fmt.Sprintf("| 🔎 Security audit findings | %d |\n", s.MalwareFindingsCount+s.AuditFindingsCount))
	b.WriteString(fmt.Sprintf("| 📦 Library findings (deprioritized) | %d |\n", s.LibraryFindingsCount))
	if s.MaxScore > 0 {
		b.WriteString(fmt.Sprintf("| Max score | %.1f%% |\n", s.MaxScore))
		b.WriteString(fmt.Sprintf("| Avg score | %.1f%% |\n", s.AvgScore))
	}
	b.WriteString("\n")
}

func (prg *PatchReportGenerator) writeCategoryBreakdown(b *strings.Builder) {
	cats := prg.prediction.Stats.TopCategories
	if len(cats) == 0 {
		return
	}
	b.WriteString("## 📁 Categories\n\n")
	b.WriteString("| Category | Count | Severity |\n|----------|-------|----------|\n")
	for _, cat := range cats {
		severity := "medium"
		if info, ok := GetCategoryInfo(cat.Category); ok {
			severity = info.Severity
		}
		badge := severity
		switch severity {
		case "critical":
			badge = "🔴 critical"
		case "high":
			badge = "🟠 high"
		case "medium":
			badge = "🟡 medium"
		}
		b.WriteString(fmt.Sprintf("| %s | %d | %s |\n", cat.Name, cat.Count, badge))
	}
	b.WriteString("\n")
}

func (prg *PatchReportGenerator) writeRiskSection(b *strings.Builder, title, subtitle string, points []PatchPoint) {
	b.WriteString(fmt.Sprintf("## %s\n\n*%s*\n\n", title, subtitle))
	for i, point := range points {
		prg.writePoint(b, i+1, &point)
	}
}

func (prg *PatchReportGenerator) writeAuditSection(b *strings.Builder, title string, points []PatchPoint) {
	b.WriteString(fmt.Sprintf("## %s\n\n", title))
	b.WriteString("> These are audit findings, not patch artifacts. Use them to harden server-side authorization, endpoint trust, TLS, and secret handling.\n\n")
	for i, point := range points {
		b.WriteString(fmt.Sprintf("### %d. `%s` — `%s()`\n\n", i+1, ShortFilePath(point.FilePath), point.MethodName))
		b.WriteString(fmt.Sprintf("- **Score:** %.1f%%\n", point.RiskScore))
		b.WriteString(fmt.Sprintf("- **Confidence:** %.0f%%\n", point.Confidence*100))
		if point.VulnSignals != nil {
			for _, signal := range point.VulnSignals.Signals {
				b.WriteString(fmt.Sprintf("- **Finding [%s]:** %s\n", signal.Severity, signal.Description))
				if len(signal.Evidence) > 0 {
					ev := signal.Evidence
					if len(ev) > 4 {
						ev = ev[:4]
					}
					b.WriteString("  - Evidence:\n")
					for _, item := range ev {
						b.WriteString(fmt.Sprintf("    - `%s`\n", item))
					}
				}
				b.WriteString(fmt.Sprintf("  - Action: %s\n", auditActionText(signal.Kind)))
			}
		}
		b.WriteString("\n")
	}
}

// 🆕 LIBRARY SECTION
func (prg *PatchReportGenerator) writeLibrarySection(b *strings.Builder, points []PatchPoint) {
	b.WriteString("## 📦 Library Findings (low priority)\n\n")
	b.WriteString("> These matches are inside well-known third-party libraries\n")
	b.WriteString("> (e.g. SpongyCastle, BouncyCastle, jose4j, Braze, Microsoft SDK).\n")
	b.WriteString("> They are usually **not** the actual cracking targets and are listed\n")
	b.WriteString("> here only for completeness.\n\n")
	b.WriteString("| # | Library | Method | Risk | Category |\n")
	b.WriteString("|---|---------|--------|------|----------|\n")
	for i, p := range points {
		lib := p.LibraryName
		if lib == "" {
			lib = "third-party"
		}
		b.WriteString(fmt.Sprintf("| %d | `%s` | `%s()` | %.0f%% | %s |\n",
			i+1, lib, p.MethodName, p.RiskScore, p.CategoryName))
	}
	b.WriteString("\n")
}

func (prg *PatchReportGenerator) writePoint(b *strings.Builder, index int, point *PatchPoint) {
	b.WriteString("---\n\n")
	shortPath := ShortFilePath(point.FilePath)
	b.WriteString(fmt.Sprintf("### %s #%d — %s\n\n", point.RiskLevel.Emoji(), index, shortPath))

	b.WriteString("| Property | Value |\n|----------|-------|\n")
	b.WriteString(fmt.Sprintf("| **File** | `%s` |\n", point.FilePath))
	b.WriteString(fmt.Sprintf("| **Method** | `%s` |\n", point.MethodSignature))
	b.WriteString(fmt.Sprintf("| **Risk Score** | **%.1f%%** |\n", point.RiskScore))
	b.WriteString(fmt.Sprintf("| **Confidence** | %.0f%% |\n", point.Confidence*100))
	b.WriteString(fmt.Sprintf("| **Category** | %s |\n", point.CategoryName))
	if point.PatternID != "" {
		b.WriteString(fmt.Sprintf("| **Pattern** | %s |\n", point.PatternID))
	}
	// 🆕 Безопасные формулировки
	b.WriteString(fmt.Sprintf("| **Weakness** | %s |\n", weaknessTextFor(point)))
	b.WriteString(fmt.Sprintf("| **Impact** | %s |\n", impactTextFor(point)))
	b.WriteString(fmt.Sprintf("| **App Code** | %s |\n", boolYesNo(point.IsAppCode)))
	b.WriteString("\n")

	if len(point.WhyVulnerable) > 0 {
		b.WriteString("**Why:**\n\n")
		for _, r := range point.WhyVulnerable {
			b.WriteString(fmt.Sprintf("- %s\n", r))
		}
		b.WriteString("\n")
	}

	if len(point.MatchedParts) > 0 {
		b.WriteString("**Matched indicators:**\n\n")
		for _, p := range point.MatchedParts {
			b.WriteString(fmt.Sprintf("- `%s`\n", p))
		}
		b.WriteString("\n")
	}

	if len(point.Warnings) > 0 {
		b.WriteString("**⚠️ Warnings:**\n\n")
		for _, w := range point.Warnings {
			b.WriteString(fmt.Sprintf("- %s\n", w))
		}
		b.WriteString("\n")
	}

	if prg.showFix {
		prg.writeFixSection(b, point)
	}
	b.WriteString("\n")
}

func (prg *PatchReportGenerator) writeFixSection(b *strings.Builder, point *PatchPoint) {
	patch := prg.generator.Generate(point)
	if patch == nil {
		return
	}
	b.WriteString("#### 🔧 Suggested Hardening\n\n")
	b.WriteString("<details>\n<summary>📄 Original code</summary>\n\n")
	b.WriteString(patch.OriginalBlock)
	b.WriteString("\n\n</details>\n\n")
	b.WriteString("**✅ Hardened version:**\n\n")
	b.WriteString(patch.PatchedBlock)
	b.WriteString("\n\n")
	b.WriteString("<details>\n<summary>📋 Diff</summary>\n\n```diff\n")
	b.WriteString(patch.DiffView)
	b.WriteString("```\n\n</details>\n\n")
}

func (prg *PatchReportGenerator) writeFooter(b *strings.Builder) {
	b.WriteString("---\n\n## ℹ️ About\n\n")
	b.WriteString("Generated by **ML Patch Predictor**.\n\n")
	b.WriteString("**Risk thresholds:**\n\n")
	b.WriteString(fmt.Sprintf("- 🔴 High Risk ≥ %.0f%%\n", HighRiskThreshold))
	b.WriteString(fmt.Sprintf("- 🟡 Medium Risk ≥ %.0f%%\n", MediumRiskThreshold))
	b.WriteString(fmt.Sprintf("- 🟢 Low Risk ≥ %.0f%%\n\n", LowRiskThreshold))
	b.WriteString("**Disclaimer:** for educational and security audit purposes only.\n")
}

func AppendAuditFindingsMarkdown(filePath string, prediction *PatchPrediction) error {
	content := BuildAuditFindingsMarkdown(prediction)
	if content == "" {
		return nil
	}
	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(content)
	return err
}

func BuildAuditFindingsMarkdown(prediction *PatchPrediction) string {
	if prediction == nil || (len(prediction.MalwareIndicators) == 0 && len(prediction.AuditFindings) == 0) {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n---\n\n# 🔎 Security Audit Findings\n\n")
	b.WriteString("> These are audit findings, not patch artifacts. Use them to harden server-side authorization, endpoint trust, TLS, WebView exposure, and secret handling.\n\n")
	write := func(title string, points []PatchPoint) {
		if len(points) == 0 {
			return
		}
		b.WriteString(fmt.Sprintf("## %s\n\n", title))
		for i, point := range points {
			b.WriteString(fmt.Sprintf("### %d. `%s` — `%s()`\n\n", i+1, ShortFilePath(point.FilePath), point.MethodName))
			b.WriteString(fmt.Sprintf("- **Score:** %.1f%%\n", point.RiskScore))
			b.WriteString(fmt.Sprintf("- **Confidence:** %.0f%%\n", point.Confidence*100))
			if point.VulnSignals != nil {
				for _, signal := range point.VulnSignals.Signals {
					b.WriteString(fmt.Sprintf("- **Finding [%s]:** %s\n", signal.Severity, signal.Description))
					if len(signal.Evidence) > 0 {
						ev := signal.Evidence
						if len(ev) > 4 {
							ev = ev[:4]
						}
						b.WriteString("  - Evidence:\n")
						for _, item := range ev {
							b.WriteString(fmt.Sprintf("    - `%s`\n", item))
						}
					}
					b.WriteString(fmt.Sprintf("  - Action: %s\n", auditActionText(signal.Kind)))
				}
			}
			b.WriteString("\n")
		}
	}
	write("High-confidence Findings", prediction.MalwareIndicators)
	write("Review", prediction.AuditFindings)
	return b.String()
}

// ═══════════════════════════════════════════════════════════════════════════════
// TERMINAL WITH FIX
// ═══════════════════════════════════════════════════════════════════════════════

func RenderToTerminalWithFix(w io.Writer, prediction *PatchPrediction) {
	gen := NewPatchGenerator()

	fmt.Fprintln(w)
	fmt.Fprintln(w, "  ╔══════════════════════════════════════════╗")
	fmt.Fprintln(w, "  ║       POTENTIAL PATCH POINTS             ║")
	fmt.Fprintln(w, "  ║       + HARDENING SUGGESTIONS            ║")
	fmt.Fprintln(w, "  ╚══════════════════════════════════════════╝")
	fmt.Fprintln(w)

	if prediction.PartialResults {
		fmt.Fprintln(w, "  🔴 WARNING: analysis timed out (partial results)")
		fmt.Fprintln(w)
	}

	printTerminologyLegendForReport(w, prediction.Mode)

	if len(prediction.MainFindings) > 0 {
		fmt.Fprintln(w, "  ⚠️  MAIN FINDINGS")
		fmt.Fprintln(w, "  ─────────────────")
		for _, f := range prediction.MainFindings {
			fmt.Fprintf(w, "  • %s\n", f)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "  Patch points: %d (app code: %d, library: %d)\n",
		prediction.Stats.PatchPointsFound,
		prediction.Stats.HighRiskCount+prediction.Stats.MediumRiskCount+prediction.Stats.LowRiskCount,
		prediction.Stats.LibraryFindingsCount)
	fmt.Fprintf(w, "  Audit findings: %d\n",
		prediction.Stats.MalwareFindingsCount+prediction.Stats.AuditFindingsCount)
	fmt.Fprintln(w)

	if prediction.Stats.PatchPointsFound == 0 &&
		prediction.Stats.MalwareFindingsCount+prediction.Stats.AuditFindingsCount == 0 {
		fmt.Fprintln(w, "  No patch points detected. No audit findings detected.")
		return
	}

	renderListWithFix := func(title string, points []PatchPoint) {
		if len(points) == 0 {
			return
		}
		fmt.Fprintln(w)
		fmt.Fprintf(w, "  %s\n", title)
		fmt.Fprintln(w, "  ════════════════════════════════════════")
		shown := 0
		for _, point := range points {
			if isSDKOrFrameworkPatchNoise(&point) || (strings.HasPrefix(strings.ToLower(point.MethodName), "exp") && strings.TrimSpace(point.CategoryName) == "" && strings.TrimSpace(string(point.Category)) == "") {
				continue
			}
			shown++
			fmt.Fprintln(w)
			fmt.Fprintf(w, "  %s #%d %s\n", point.RiskLevel.Emoji(), shown, ShortFilePath(point.FilePath))
			fmt.Fprintf(w, "  Method: %s\n", MethodSignatureShort(&MethodInfo{
				Name: point.MethodName, ReturnType: point.ReturnType,
			}))
			fmt.Fprintf(w, "  Risk: %.0f%% | Category: %s\n", point.RiskScore, point.CategoryName)
			fmt.Fprintf(w, "  Weakness: %s\n", weaknessTextFor(&point))
			fmt.Fprintf(w, "  Impact:   %s\n", impactTextFor(&point))

			patch := gen.Generate(&point)
			if patch != nil {
				fmt.Fprintln(w)
				if shouldSuppressAutoPatch(&point) {
					fmt.Fprintln(w, "  Suggested hardening:")
					fmt.Fprintln(w, "    Diagnostic-only - no resolved monetization/auth gate at this method")
					fmt.Fprintln(w, "      (structural or heuristic match). Auto-neutering it would corrupt")
					fmt.Fprintln(w, "      behaviour without bypassing a real check - review manually.")
				} else {
					fmt.Fprintln(w, "  Suggested hardening:")
					fmt.Fprintln(w, FormatUnifiedDiffForTerminal(patch))
				}
			}
			renderChainExplanation(w, &point)
		}
	}

	renderAuditList := func(title string, points []PatchPoint) {
		if len(points) == 0 {
			return
		}
		fmt.Fprintln(w)
		fmt.Fprintf(w, "  %s\n", title)
		fmt.Fprintln(w, "  ════════════════════════════════════════")
		for i, point := range points {
			fmt.Fprintln(w)
			fmt.Fprintf(w, "  🔎 #%d %s\n", i+1, ShortFilePath(point.FilePath))
			fmt.Fprintf(w, "  Method: %s\n", MethodSignatureShort(&MethodInfo{
				Name: point.MethodName, ReturnType: point.ReturnType,
			}))
			fmt.Fprintf(w, "  Score: %.0f%% | Confidence: %.0f%%\n", point.RiskScore, point.Confidence*100)
			if point.VulnSignals == nil {
				continue
			}
			maxSignals := 3
			if len(point.VulnSignals.Signals) < maxSignals {
				maxSignals = len(point.VulnSignals.Signals)
			}
			for j := 0; j < maxSignals; j++ {
				signal := point.VulnSignals.Signals[j]
				fmt.Fprintf(w, "  Finding: [%s] %s\n", signal.Severity, signal.Description)
				if len(signal.Evidence) > 0 {
					ev := signal.Evidence
					if len(ev) > 3 {
						ev = ev[:3]
					}
					fmt.Fprintf(w, "  Evidence: %s\n", strings.Join(ev, " | "))
				}
				fmt.Fprintf(w, "  Action:   %s\n", auditActionText(signal.Kind))
			}
		}
	}

	renderAuditList("🔎 SECURITY AUDIT — High-confidence Findings", prediction.MalwareIndicators)
	renderAuditList("🔎 SECURITY AUDIT — Review", prediction.AuditFindings)

	renderListWithFix("🔴 HIGH RISK — App Code", prediction.HighRisk)
	renderListWithFix("🟡 MEDIUM RISK — App Code", prediction.MediumRisk)

	if len(prediction.LowRisk) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  🟢 LOW RISK")
		fmt.Fprintln(w, "  ═══════════")
		for i, p := range prediction.LowRisk {
			fmt.Fprintf(w, "  %d. %s → %s (%.0f%%)\n",
				i+1, ShortFilePath(p.FilePath), p.MethodName, p.RiskScore)
		}
	}

	if len(prediction.LibraryFindings) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  📦 LIBRARY FINDINGS (low priority)")
		fmt.Fprintln(w, "  ════════════════════════════════════")
		for i, p := range prediction.LibraryFindings {
			tag := "[LIB]"
			if p.LibraryName != "" {
				tag = fmt.Sprintf("[LIB:%s]", p.LibraryName)
			}
			fmt.Fprintf(w, "  %d. %s %s → %s() %.0f%%\n",
				i+1, tag, ShortFilePath(p.FilePath), p.MethodName, p.RiskScore)
		}
	}

	fmt.Fprintln(w)
}

func printTerminologyLegendForReport(w io.Writer, mode PatchMode) {
	fmt.Fprintln(w, "  Terminology")
	fmt.Fprintln(w, "  ───────────")
	if mode == PatchModeDefensive {
		fmt.Fprintln(w, "  🛡️  Defensive Mode")
		fmt.Fprintln(w, "  • Weakness  - Where check can be bypassed")
		fmt.Fprintln(w, "  • Impact    - What could happen if bypassed")
	} else {
		fmt.Fprintln(w, "  ⚔️  Research Mode")
		fmt.Fprintln(w, "  • Bypass             - Circumvent high-risk checks")
		fmt.Fprintln(w, "  • Exploit suggestion - Circumvent medium/low-risk checks")
	}
	fmt.Fprintln(w)
}

// ═══════════════════════════════════════════════════════════════════════════════
// SHARED HELPERS — безопасные формулировки для report/terminal
// ═══════════════════════════════════════════════════════════════════════════════

// getPatchLabelForReport returns mode-specific label for patches
func getPatchLabelForReport(mode PatchMode, isHighRisk bool) string {
	if mode == PatchModeDefensive {
		if isHighRisk {
			return "Impact"
		}
		return "Weakness"
	}
	// research mode
	if isHighRisk {
		return "Bypass"
	}
	return "Exploit suggestion"
}

func weaknessTextFor(p *PatchPoint) string {
	switch p.Category {
	case PatchCatBilling:
		return "Signature/receipt verification can be bypassed"
	case PatchCatLicense:
		return "License validation can be short-circuited"
	case PatchCatPremium:
		return "Premium entitlement check can be skipped"
	case PatchCatSubscription:
		return "Subscription state check can be bypassed"
	case PatchCatTamper:
		return "Tamper detection can be disabled"
	case PatchCatAds:
		return "Ad-display logic can be neutralized"
	case PatchCatFeatureGate:
		return "Feature flag can be force-enabled"
	case PatchCatInstaller:
		return "Installer-source check can be spoofed"
	case PatchCatServerAuth:
		return "Client-side server-auth decision may be trusted too broadly"
	case PatchCatDRM:
		return "Content protection relies on client-side decision points"
	case PatchCatCurrency:
		return "Currency validation may rely on client-side state"
	default:
		return "Check is structurally bypassable"
	}
}

func impactTextFor(p *PatchPoint) string {
	switch p.Category {
	case PatchCatBilling:
		return "Unauthorized purchases may be accepted"
	case PatchCatLicense:
		return "Unlicensed copies could appear licensed"
	case PatchCatPremium:
		return "Free users could access paid features"
	case PatchCatSubscription:
		return "Expired subscriptions may remain active"
	case PatchCatTamper:
		return "Modified APK may run undetected"
	case PatchCatAds:
		return "Ads may be disabled"
	case PatchCatFeatureGate:
		return "Locked features may be unlocked"
	case PatchCatInstaller:
		return "App may run from unofficial sources"
	case PatchCatServerAuth:
		return "Auth/session decisions may need stronger server-side enforcement"
	case PatchCatDRM:
		return "Protected content may need stronger server-side entitlement checks"
	case PatchCatCurrency:
		return "Economy state should be treated as server-authoritative"
	default:
		return "Security control may be evaded"
	}
}

func boolYesNo(v bool) string {
	if v {
		return "✅ Yes"
	}
	return "❌ No"
}
