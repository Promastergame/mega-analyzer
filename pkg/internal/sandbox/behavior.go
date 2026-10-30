package sandbox

import (
	"net"
	"path/filepath"
	"sort"
	"strings"
)

var executableDropExts = map[string]struct{}{
	".apk": {}, ".com": {}, ".cpl": {}, ".dex": {}, ".dll": {}, ".drv": {},
	".exe": {}, ".jar": {}, ".msi": {}, ".ocx": {}, ".scr": {}, ".sys": {},
}

var scriptDropExts = map[string]struct{}{
	".bat": {}, ".cmd": {}, ".hta": {}, ".js": {}, ".jse": {}, ".ps1": {},
	".psm1": {}, ".vbe": {}, ".vbs": {}, ".wsf": {},
}

func buildBehaviorSummary(report *Report) BehaviorSummary {
	summary := BehaviorSummary{
		ChildProcessCount:      maxInt(0, len(report.Processes)-1),
		ConnectionCount:        len(report.Connections),
		CreatedFileCount:       len(report.FileChanges.Created),
		ModifiedFileCount:      len(report.FileChanges.Modified),
		PersistenceCount:       len(report.RegistryChanges.Added) + len(report.RegistryChanges.Modified),
		PermissionWarningCount: permissionWarningCount(report.AndroidProfile),
	}

	for _, conn := range report.Connections {
		if isPublicRemoteAddress(conn.RemoteAddr) {
			summary.PublicConnectionCount++
		}
	}

	for _, artifact := range report.FileChanges.Created {
		ext := strings.ToLower(filepath.Ext(artifact.Path))
		if _, ok := executableDropExts[ext]; ok {
			summary.DroppedExecutableCount++
		} else if _, ok := scriptDropExts[ext]; ok {
			summary.DroppedScriptCount++
		}
		if looksLikePersistencePath(artifact.Path) {
			summary.PersistenceCount++
		}
	}

	summary.Highlights = summarizeHighlights(report, summary)
	return summary
}

func summarizeHighlights(report *Report, summary BehaviorSummary) []string {
	highlights := make([]string, 0, 8)

	if !report.Executed {
		if report.ExecutionSkipReason != "" {
			highlights = append(highlights, "Execution skipped: "+report.ExecutionSkipReason)
		}
		if report.AndroidProfile != nil {
			highlights = append(highlights, "Static Android profile captured for triage")
		}
	}
	if report.NetworkMode == "blocked" {
		highlights = append(highlights, "Network access was blocked by sandbox policy")
	}
	if summary.ChildProcessCount > 0 {
		highlights = append(highlights, pluralize(summary.ChildProcessCount, "Spawned %d child process", "Spawned %d child processes"))
	}
	if summary.CreatedFileCount > 0 {
		highlights = append(highlights, pluralize(summary.CreatedFileCount, "Created %d file inside the session workspace", "Created %d files inside the session workspace"))
	}
	if summary.ModifiedFileCount > 0 {
		highlights = append(highlights, pluralize(summary.ModifiedFileCount, "Modified %d file inside the session workspace", "Modified %d files inside the session workspace"))
	}
	if summary.DroppedExecutableCount > 0 {
		highlights = append(highlights, pluralize(summary.DroppedExecutableCount, "Dropped %d executable or library", "Dropped %d executables or libraries"))
	}
	if summary.DroppedScriptCount > 0 {
		highlights = append(highlights, pluralize(summary.DroppedScriptCount, "Dropped %d script artifact", "Dropped %d script artifacts"))
	}
	if summary.PublicConnectionCount > 0 {
		highlights = append(highlights, pluralize(summary.PublicConnectionCount, "Contacted %d public network endpoint", "Contacted %d public network endpoints"))
	}
	if summary.PersistenceCount > 0 {
		highlights = append(highlights, pluralize(summary.PersistenceCount, "Touched %d persistence indicator", "Touched %d persistence indicators"))
	}
	if report.AndroidProfile != nil {
		if report.AndroidProfile.HighRiskPermissionCount > 0 {
			highlights = append(highlights, pluralize(report.AndroidProfile.HighRiskPermissionCount, "Requests %d high-risk Android permission", "Requests %d high-risk Android permissions"))
		}
		if report.AndroidProfile.DangerousPermissionCount > 0 {
			highlights = append(highlights, pluralize(report.AndroidProfile.DangerousPermissionCount, "Requests %d dangerous Android permission", "Requests %d dangerous Android permissions"))
		}
		exported := countExportedComponents(report.AndroidProfile.ExportedComponents)
		if exported > 0 {
			highlights = append(highlights, pluralize(exported, "Declares %d exported Android component", "Declares %d exported Android components"))
		}
	}

	sort.Strings(highlights)
	return highlights
}

func permissionWarningCount(profile *AndroidProfile) int {
	if profile == nil {
		return 0
	}
	return profile.HighRiskPermissionCount + profile.DangerousPermissionCount
}

func countExportedComponents(components []AndroidComponent) int {
	count := 0
	for _, component := range components {
		if component.Exported {
			count++
		}
	}
	return count
}

func looksLikePersistencePath(path string) bool {
	lower := strings.ToLower(filepath.ToSlash(path))
	return strings.Contains(lower, "/startup/") ||
		strings.Contains(lower, "/autorun/") ||
		strings.Contains(lower, "/runonce/") ||
		strings.Contains(lower, "/start menu/programs/startup/")
}

func isPublicRemoteAddress(raw string) bool {
	if raw == "" || raw == "*:*" {
		return false
	}

	host := raw
	if h, _, err := net.SplitHostPort(raw); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	return true
}

func pluralize(n int, singularFmt, pluralFmt string) string {
	if n == 1 {
		return sprintfInt(singularFmt, n)
	}
	return sprintfInt(pluralFmt, n)
}

func sprintfInt(format string, n int) string {
	return strings.Replace(format, "%d", strconvItoa(n), 1)
}

func strconvItoa(n int) string {
	if n == 0 {
		return "0"
	}
	negative := n < 0
	if negative {
		n = -n
	}
	buf := [20]byte{}
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if negative {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
