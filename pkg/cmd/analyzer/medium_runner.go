package main

import (
	"fmt"
	"net/url"
	"path/filepath"
	"sort"
	"strings"

	"mega-analyzer/pkg/internal/certaudit"
	"mega-analyzer/pkg/internal/cicdaudit"
	"mega-analyzer/pkg/internal/cloudaudit"
	"mega-analyzer/pkg/internal/insights"
	"mega-analyzer/pkg/internal/malwarecheck"
	"mega-analyzer/pkg/internal/niap"
	"mega-analyzer/pkg/internal/permissionmap"
	"mega-analyzer/pkg/internal/playstore"
	"mega-analyzer/pkg/internal/sbom"
	"mega-analyzer/pkg/internal/supplychain"
	"mega-analyzer/pkg/internal/types"
	"os"
)

// runMediumModules runs the MobSF-inspired medium-priority sidecar
// analyzers when their corresponding CLI flags are enabled.
func (a *App) runMediumModules(result *types.AnalysisResult, target, outputDir, originalAPKPath string) {
	if a == nil || a.opts == nil || result == nil {
		return
	}
	if !a.opts.EnableMediumAll &&
		!a.opts.EnablePlayStore &&
		!a.opts.EnableSBOM &&
		!a.opts.EnablePermMap &&
		!a.opts.EnableCertAudit &&
		!a.opts.EnableMalwareDomains &&
		!a.opts.EnableNIAP {
		return
	}

	mediumDir := filepath.Join(outputDir, "medium")
	if err := os.MkdirAll(mediumDir, 0755); err != nil {
		// Without the output dir the sidecar modules can't persist their
		// artifacts; skip them instead of failing every write below.
		return
	}

	// 1. Play Store Metadata
	if a.opts.EnableMediumAll || a.opts.EnablePlayStore {
		pkg := result.AppPackage
		if pkg == "" {
			pkg = extractPackageNameFromTarget(target)
		}
		rep := playstore.Analyze(pkg)
		_ = insights.WriteJSON(filepath.Join(mediumDir, "playstore.json"), rep)
		_ = insights.WriteText(filepath.Join(mediumDir, "PLAYSTORE.md"), rep.RenderMarkdown())
		if rep.Metadata != nil && !rep.Metadata.Found {
			result.ArtifactFindings = append(result.ArtifactFindings, types.ArtifactFinding{
				Path:     "medium/PLAYSTORE.md",
				Severity: types.SeverityInfo,
				Reason:   fmt.Sprintf("Play Store: %s — %s", rep.Verdict, rep.Metadata.Error),
			})
		} else if rep.Metadata != nil {
			result.ArtifactFindings = append(result.ArtifactFindings, types.ArtifactFinding{
				Path:     "medium/PLAYSTORE.md",
				Severity: types.SeverityInfo,
				Reason:   fmt.Sprintf("Play Store: %s (%s, rating %.1f)", rep.Metadata.Name, rep.Metadata.Developer, rep.Metadata.Rating),
			})
		}
		a.output.Success("Play Store metadata: %s", rep.Verdict)
	}

	// 2. SBOM Extraction
	if a.opts.EnableMediumAll || a.opts.EnableSBOM {
		rep, err := sbom.Extract(target)
		if err == nil {
			_ = insights.WriteJSON(filepath.Join(mediumDir, "sbom.json"), rep)
			_ = insights.WriteText(filepath.Join(mediumDir, "SBOM.md"), rep.RenderMarkdown())
			if cdx, cdxErr := sbom.ExportCycloneDX(rep); cdxErr == nil {
				_ = insights.WriteText(filepath.Join(mediumDir, "sbom.cdx.json"), string(cdx))
			}
			for _, dep := range rep.Deps {
				result.ArtifactFindings = append(result.ArtifactFindings, types.ArtifactFinding{
					Path:     "medium/SBOM.md",
					Severity: types.SeverityInfo,
					Reason:   fmt.Sprintf("SBOM dependency: %s", dep.Raw),
				})
			}
			// Known-set PURL verdict (opt-in -known-set): bad = critical typed
			// finding (CI-gated), good = info note. Append-only.
			a.applyKnownSetSBOM(result, rep.Deps)
			a.output.Success("SBOM: %d dependencies extracted", rep.Count)
		}
	}

	// 2b. Modern CI/CD, Cloud/GitOps and React Server Components audits.
	// These are local, read-only analyzers and only run as part of -medium-all.
	if a.opts.EnableMediumAll {
		if rep, err := cicdaudit.Analyze(target); err == nil {
			_ = insights.WriteJSON(filepath.Join(mediumDir, "cicd_audit.json"), rep)
			_ = insights.WriteText(filepath.Join(mediumDir, "CICD_AUDIT.md"), cicdaudit.RenderMarkdown(rep))
			for _, issue := range rep.Issues {
				result.ArtifactFindings = append(result.ArtifactFindings, types.ArtifactFinding{
					Path: "medium/CICD_AUDIT.md", Severity: modernAuditSeverity(string(issue.Severity)),
					Reason: fmt.Sprintf("%s: %s (%s:%d)", issue.ID, issue.Title, issue.File, issue.Line),
				})
			}
			a.output.Success("CI/CD audit: %d high-signal finding(s)", len(rep.Issues))
		}
		if rep, err := cloudaudit.Analyze(target); err == nil {
			_ = insights.WriteJSON(filepath.Join(mediumDir, "cloud_audit.json"), rep)
			_ = insights.WriteText(filepath.Join(mediumDir, "CLOUD_AUDIT.md"), cloudaudit.RenderMarkdown(rep))
			for _, issue := range rep.Issues {
				result.ArtifactFindings = append(result.ArtifactFindings, types.ArtifactFinding{
					Path: "medium/CLOUD_AUDIT.md", Severity: modernAuditSeverity(string(issue.Severity)),
					Reason: fmt.Sprintf("%s: %s (%s:%d)", issue.ID, issue.Title, issue.File, issue.Line),
				})
			}
			a.output.Success("Cloud/GitOps audit: %d high-signal finding(s)", len(rep.Issues))
		}
		if findings, err := supplychain.DetectReactServerComponents(target); err == nil {
			for _, finding := range findings {
				result.ArtifactFindings = append(result.ArtifactFindings, types.ArtifactFinding{
					Path: finding.File, Severity: types.SeverityCritical,
					Reason: fmt.Sprintf("%s: %s %s — %s", finding.ID, finding.Package, finding.Version, finding.Description),
				})
			}
			if len(findings) > 0 {
				a.output.Success("React2Shell audit: %d vulnerable dependency finding(s)", len(findings))
			}
		}
	}

	// 3. Permission-to-Code Mapping
	if a.opts.EnableMediumAll || a.opts.EnablePermMap {
		declared := extractPermissions(result)
		rep, err := permissionmap.Analyze(target, declared)
		if err == nil {
			_ = insights.WriteJSON(filepath.Join(mediumDir, "permission_map.json"), rep)
			_ = insights.WriteText(filepath.Join(mediumDir, "PERMISSION_MAP.md"), rep.RenderMarkdown())
			for _, p := range rep.Permissions {
				if !p.Used {
					result.ArtifactFindings = append(result.ArtifactFindings, types.ArtifactFinding{
						Path:     "medium/PERMISSION_MAP.md",
						Severity: types.SeverityLow,
						Reason:   fmt.Sprintf("Dead permission: %s", p.Permission),
					})
				}
			}
			a.output.Success("Permission map: %d used / %d unused", rep.UsedCount, rep.UnusedCount)
		}
	}

	// 4. Certificate Deep Analysis
	if (a.opts.EnableMediumAll || a.opts.EnableCertAudit) && originalAPKPath != "" && isAPK(originalAPKPath) {
		rep, err := certaudit.AnalyzeAPK(originalAPKPath)
		if err == nil {
			_ = insights.WriteJSON(filepath.Join(mediumDir, "cert_audit.json"), rep)
			_ = insights.WriteText(filepath.Join(mediumDir, "CERT_AUDIT.md"), rep.RenderMarkdown())
			for _, c := range rep.Certs {
				if c.Expired {
					result.ArtifactFindings = append(result.ArtifactFindings, types.ArtifactFinding{
						Path:     "medium/CERT_AUDIT.md",
						Severity: types.SeverityHigh,
						Reason:   fmt.Sprintf("Expired certificate: %s", c.Subject),
					})
				}
				if c.IsDebug {
					result.ArtifactFindings = append(result.ArtifactFindings, types.ArtifactFinding{
						Path:     "medium/CERT_AUDIT.md",
						Severity: types.SeverityHigh,
						Reason:   fmt.Sprintf("Debug certificate: %s", c.Subject),
					})
				}
			}
			a.output.Success("Certificate audit: %d certs, verdict %s", len(rep.Certs), rep.Verdict)
		}
	}

	// 5. Malware Domain Check
	if a.opts.EnableMediumAll || a.opts.EnableMalwareDomains {
		urls := extractURLs(result)
		rep, err := malwarecheck.Analyze(urls, "")
		if err == nil {
			_ = insights.WriteJSON(filepath.Join(mediumDir, "malware_domains.json"), rep)
			_ = insights.WriteText(filepath.Join(mediumDir, "MALWARE_DOMAINS.md"), rep.RenderMarkdown())
			for _, f := range rep.Findings {
				result.ArtifactFindings = append(result.ArtifactFindings, types.ArtifactFinding{
					Path:     "medium/MALWARE_DOMAINS.md",
					Severity: types.SeverityHigh,
					Reason:   fmt.Sprintf("Malware domain: %s (%s)", f.Domain, f.List),
				})
			}
			a.output.Success("Malware domains: %d hits", rep.Hits)
		}
	}

	// 7. NIAP Compliance
	if a.opts.EnableMediumAll || a.opts.EnableNIAP {
		rep, err := niap.Analyze(target)
		if err == nil {
			_ = insights.WriteJSON(filepath.Join(mediumDir, "niap.json"), rep)
			_ = insights.WriteText(filepath.Join(mediumDir, "NIAP.md"), rep.RenderMarkdown())
			for _, m := range rep.Matches {
				sev, reason, ok := niapFinding(m)
				if !ok {
					continue
				}
				result.ArtifactFindings = append(result.ArtifactFindings, types.ArtifactFinding{
					Path:     "medium/NIAP.md",
					Severity: sev,
					Reason:   reason,
				})
			}
			a.output.Success("NIAP: %d passed, %d failed (%s)", rep.Passed, rep.Failed, rep.Verdict)
		}
	}
}

// niapFinding maps a NIAP match to a report finding. Only failed rules are
// findings; manual-review rules are informational. Passed rules — including
// clean negative rules whose anti-pattern was NOT found — produce nothing.
// The old `!m.Matched` condition did the opposite: every clean app collected
// a Medium finding per negative rule ("AES-ECB mode used", "TLS bypass", ...)
// for patterns that never matched, while real hits stayed silent.
func niapFinding(m niap.Match) (types.Severity, string, bool) {
	switch m.Status {
	case niap.StatusFailed:
		return types.SeverityMedium, fmt.Sprintf("NIAP %s: %s", m.RuleID, m.Message), true
	case niap.StatusManual:
		return types.SeverityInfo, fmt.Sprintf("NIAP %s needs manual review: %s", m.RuleID, m.Message), true
	default:
		return 0, "", false
	}
}

func modernAuditSeverity(value string) types.Severity {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return types.SeverityCritical
	case "high":
		return types.SeverityHigh
	case "medium":
		return types.SeverityMedium
	case "low":
		return types.SeverityLow
	default:
		return types.SeverityInfo
	}
}

// isAPK reports whether target looks like an APK file.
func isAPK(target string) bool {
	return filepath.Ext(target) == ".apk"
}

// extractPackageNameFromTarget tries to infer package name from path (last dir component).
func extractPackageNameFromTarget(target string) string {
	base := filepath.Base(target)
	if ext := filepath.Ext(base); ext != "" {
		base = base[:len(base)-len(ext)]
	}
	return base
}

// extractPermissions attempts to infer declared permissions from the analysis result.
func extractPermissions(result *types.AnalysisResult) []string {
	if result == nil {
		return nil
	}
	seen := make(map[string]struct{})
	for _, file := range result.Files {
		if file == nil {
			continue
		}
		if file.XMLData != nil {
			for _, permission := range file.XMLData.Permissions {
				permission = strings.TrimSpace(permission)
				if permission != "" {
					seen[permission] = struct{}{}
				}
			}
		}
		for _, match := range file.Matches {
			if match.Category != types.CategoryManifestPermission {
				continue
			}
			permission := strings.TrimSpace(match.Pattern)
			if permission != "" {
				seen[permission] = struct{}{}
			}
		}
	}
	permissions := make([]string, 0, len(seen))
	for permission := range seen {
		permissions = append(permissions, permission)
	}
	sort.Strings(permissions)
	return permissions
}

// extractURLs pulls candidate URLs from the analysis result.
func extractURLs(result *types.AnalysisResult) []string {
	if result == nil {
		return nil
	}
	seen := make(map[string]struct{})
	for _, file := range result.Files {
		if file == nil {
			continue
		}
		for _, match := range file.Matches {
			if match.Category != types.CategoryNetworkEndpoint && match.Category != types.CategorySuspiciousURL {
				continue
			}
			candidate := strings.TrimSpace(match.Pattern)
			parsed, err := url.Parse(candidate)
			if err != nil || parsed.Scheme == "" || parsed.Hostname() == "" {
				continue
			}
			seen[candidate] = struct{}{}
		}
	}
	urls := make([]string, 0, len(seen))
	for candidate := range seen {
		urls = append(urls, candidate)
	}
	sort.Strings(urls)
	return urls
}
