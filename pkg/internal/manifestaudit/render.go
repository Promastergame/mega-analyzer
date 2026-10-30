package manifestaudit

import (
	"fmt"
	"strings"
)

// RenderMarkdown produces a human-readable report. The output is
// stable enough to be used as a snapshot fixture in tests.
func RenderMarkdown(r *Report) string {
	var b strings.Builder
	b.WriteString("# Manifest Audit\n\n")
	if r == nil {
		b.WriteString("_(no report)_\n")
		return b.String()
	}
	fmt.Fprintf(&b, "- **Target**: `%s`\n", r.Target)
	if r.Package != "" {
		fmt.Fprintf(&b, "- **Package**: `%s`\n", r.Package)
	}
	if r.VersionName != "" {
		fmt.Fprintf(&b, "- **Version**: %s (code %d)\n", r.VersionName, r.VersionCode)
	}
	fmt.Fprintf(&b, "- **SDK**: minSdk=%d, targetSdk=%d\n", r.MinSDK, r.TargetSDK)
	fmt.Fprintf(&b, "- **Score**: %d / 100 (`%s`)\n\n", r.Score, r.Verdict)

	b.WriteString("## Application flags\n\n")
	fmt.Fprintf(&b, "| flag | value |\n|---|---|\n")
	fmt.Fprintf(&b, "| debuggable | %v |\n", r.Debuggable)
	fmt.Fprintf(&b, "| allowBackup | %v |\n", r.AllowBackup)
	fmt.Fprintf(&b, "| usesCleartextTraffic | %v |\n", r.UsesCleartext)
	fmt.Fprintf(&b, "| networkSecurityConfig | %v |\n", r.HasNetworkSecCfg)
	fmt.Fprintf(&b, "| extractNativeLibs | %v |\n", r.ExtractNativeLibs)
	if r.SharedUserID != "" {
		fmt.Fprintf(&b, "| sharedUserId | `%s` |\n", r.SharedUserID)
	}
	b.WriteString("\n")

	b.WriteString("## Component counts\n\n")
	fmt.Fprintf(&b, "| kind | total | exported |\n|---|---:|---:|\n")
	fmt.Fprintf(&b, "| activities | %d | %d |\n", r.Counts.Activities, r.Counts.ExportedActivities)
	fmt.Fprintf(&b, "| services | %d | %d |\n", r.Counts.Services, r.Counts.ExportedServices)
	fmt.Fprintf(&b, "| receivers | %d | %d |\n", r.Counts.Receivers, r.Counts.ExportedReceivers)
	fmt.Fprintf(&b, "| providers | %d | %d |\n", r.Counts.Providers, r.Counts.ExportedProviders)
	b.WriteString("\n")

	if len(r.Issues) > 0 {
		b.WriteString("## Issues\n\n")
		fmt.Fprintf(&b, "| severity | id | component | title |\n|---|---|---|---|\n")
		for _, is := range r.Issues {
			fmt.Fprintf(&b, "| %s | `%s` | `%s` | %s |\n", is.Severity, is.ID, is.Component, is.Title)
		}
		b.WriteString("\n")
	}

	if len(r.ExportedComponents) > 0 {
		b.WriteString("## Exported components\n\n")
		fmt.Fprintf(&b, "| kind | name | permission | severity | risk |\n|---|---|---|---|---|\n")
		for _, c := range r.ExportedComponents {
			fmt.Fprintf(&b, "| %s | `%s` | `%s` | %s | %s |\n", c.Kind, c.Name, c.Permission, c.Severity, c.Risk)
		}
	}
	return b.String()
}
