package insights

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func WriteJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func WriteText(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0644)
}

func RenderJNIMarkdown(r *JNIReport) string {
	var b strings.Builder
	b.WriteString("# JNI Boundary Analyzer\n\n")
	if r == nil {
		b.WriteString("No JNI data.\n")
		return b.String()
	}
	fmt.Fprintf(&b, "- **Target**: `%s`\n- **Score**: %d / 100\n- **LoadLibrary calls**: %d\n- **Native methods**: %d\n- **Native libraries**: %d\n- **Bindings**: %d\n\n", r.Target, r.Score, len(r.LoadLibraries), len(r.NativeMethods), len(r.NativeLibraries), len(r.Bindings))
	if len(r.Findings) > 0 {
		b.WriteString("## Findings\n\n")
		writeFindings(&b, r.Findings)
	}
	if len(r.Bindings) > 0 {
		b.WriteString("## Java to native bindings\n\n| Java method | Library | Native symbol | Confidence | Reason |\n|---|---|---|---:|---|\n")
		for _, x := range r.Bindings {
			fmt.Fprintf(&b, "| `%s->%s` | `%s` | `%s` | %.2f | %s |\n", x.JavaClass, x.JavaMethod, x.Library, x.NativeSymbol, x.Confidence, x.Reason)
		}
		b.WriteString("\n")
	}
	if len(r.UnresolvedMethods) > 0 {
		b.WriteString("## Unresolved native methods\n\n")
		for _, m := range limitNativeMethods(r.UnresolvedMethods, 50) {
			fmt.Fprintf(&b, "- `%s->%s%s` in `%s:%d`\n", m.Class, m.Method, m.Signature, m.File, m.Line)
		}
		b.WriteString("\n")
	}
	if len(r.NativeLibraries) > 0 {
		b.WriteString("## Native libraries\n\n| Library | Path | JNI exports | RegisterNatives |\n|---|---|---:|---|\n")
		for _, lib := range r.NativeLibraries {
			fmt.Fprintf(&b, "| `%s` | `%s` | %d | %v |\n", lib.Name, lib.Path, len(lib.JNIExports), lib.RegisterNatives)
		}
	}
	return b.String()
}

func RenderPrivacyMarkdown(r *PrivacyReport) string {
	var b strings.Builder
	b.WriteString("# Privacy Analyzer\n\n")
	if r == nil {
		b.WriteString("No privacy data.\n")
		return b.String()
	}
	fmt.Fprintf(&b, "- **Target**: `%s`\n- **Privacy score**: %d / 100\n- **Risk**: %s\n- **Sensitive sources**: %d\n- **Sinks**: %d\n- **Trackers**: %d\n- **Flow candidates**: %d\n\n", r.Target, r.Score, r.Risk, len(r.Sources), len(r.Sinks), len(r.Trackers), len(r.Flows))
	if len(r.Findings) > 0 {
		b.WriteString("## Findings\n\n")
		writeFindings(&b, r.Findings)
	}
	if len(r.Flows) > 0 {
		b.WriteString("## Sensitive flow candidates\n\n| Source | Sink | Endpoint | File |\n|---|---|---|---|\n")
		for _, f := range limitFlows(r.Flows, 50) {
			fmt.Fprintf(&b, "| %s | %s | `%s` | `%s` |\n", f.Source, f.Sink, f.Endpoint, f.Path)
		}
		b.WriteString("\n")
	}
	if len(r.Trackers) > 0 {
		b.WriteString("## Trackers\n\n")
		for _, t := range r.Trackers {
			fmt.Fprintf(&b, "- %s (`%s`)\n", t.Name, t.Path)
		}
		b.WriteString("\n")
	}
	if len(r.Permissions) > 0 {
		b.WriteString("## Permissions\n\n")
		for _, p := range limitSignals(r.Permissions, 80) {
			fmt.Fprintf(&b, "- `%s`\n", p.Name)
		}
	}
	return b.String()
}

func RenderDiffMarkdown(r *DiffReport) string {
	var b strings.Builder
	b.WriteString("# Version Diff Analyzer\n\n")
	if r == nil {
		b.WriteString("No diff data.\n")
		return b.String()
	}
	fmt.Fprintf(&b, "- **Old**: `%s`\n- **New**: `%s`\n- **Risk**: %d -> %d (**delta %+d**)\n- **Files**: %d -> %d\n\n", r.OldPath, r.NewPath, r.RiskOld, r.RiskNew, r.RiskDelta, r.Old.FileCount, r.New.FileCount)
	if len(r.Findings) > 0 {
		b.WriteString("## Findings\n\n")
		writeFindings(&b, r.Findings)
	}
	writeDiffSection(&b, "Added", r.Added)
	writeDiffSection(&b, "Removed", r.Removed)
	writeDiffSection(&b, "Changed", r.Changed)
	return b.String()
}

func RenderFirmwareMarkdown(r *FirmwareReport) string {
	var b strings.Builder
	b.WriteString("# Firmware / IoT Analyzer\n\n")
	if r == nil {
		b.WriteString("No firmware data.\n")
		return b.String()
	}
	fmt.Fprintf(&b, "- **Target**: `%s`\n- **Kind**: %s\n- **Risk**: %s (%d / 100)\n- **Files scanned**: %d\n\n", r.Target, r.Kind, r.Risk, r.Score, r.FileCount)
	if len(r.RootFSHints) > 0 {
		b.WriteString("## RootFS hints\n\n")
		for _, h := range r.RootFSHints {
			fmt.Fprintf(&b, "- %s\n", h)
		}
		b.WriteString("\n")
	}
	if len(r.Findings) > 0 {
		b.WriteString("## Findings\n\n")
		writeFindings(&b, r.Findings)
	}
	writeFirmwareItems(&b, "Services", r.Services)
	writeFirmwareItems(&b, "Web panels", r.WebPanels)
	writeFirmwareItems(&b, "Secret markers", r.Secrets)
	writeFirmwareItems(&b, "Packages", r.Packages)
	return b.String()
}

func writeFindings(b *strings.Builder, findings []Finding) {
	for _, f := range findings {
		loc := f.Path
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.Path, f.Line)
		}
		if loc != "" {
			fmt.Fprintf(b, "- **%s** `%s` — %s: %s\n", f.Severity, loc, f.Title, f.Detail)
		} else {
			fmt.Fprintf(b, "- **%s** — %s: %s\n", f.Severity, f.Title, f.Detail)
		}
	}
	b.WriteString("\n")
}

func writeDiffSection(b *strings.Builder, title string, c DiffChanges) {
	if len(c.Permissions)+len(c.Endpoints)+len(c.NativeLibs)+len(c.Certificates)+len(c.Trackers)+len(c.Secrets)+len(c.Files) == 0 {
		return
	}
	fmt.Fprintf(b, "## %s\n\n", title)
	writeList(b, "Permissions", c.Permissions)
	writeList(b, "Endpoints", limitStrings(c.Endpoints, 30))
	writeList(b, "Native libs", c.NativeLibs)
	writeList(b, "Certificates", c.Certificates)
	writeList(b, "Trackers", c.Trackers)
	writeList(b, "Secret markers", c.Secrets)
}

func writeList(b *strings.Builder, title string, items []string) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(b, "### %s\n\n", title)
	for _, item := range items {
		fmt.Fprintf(b, "- `%s`\n", item)
	}
	b.WriteString("\n")
}

func writeFirmwareItems(b *strings.Builder, title string, items []FirmwareItem) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(b, "## %s\n\n| Severity | Name | Path | Detail |\n|---|---|---|---|\n", title)
	for _, x := range limitFirmwareItems(items, 80) {
		fmt.Fprintf(b, "| %s | %s | `%s` | %s |\n", x.Severity, x.Name, x.Path, x.Detail)
	}
	b.WriteString("\n")
}

func limitNativeMethods(in []NativeMethod, n int) []NativeMethod {
	if len(in) <= n {
		return in
	}
	return in[:n]
}

func limitFlows(in []PrivacyFlow, n int) []PrivacyFlow {
	if len(in) <= n {
		return in
	}
	return in[:n]
}

func limitSignals(in []PrivacySignal, n int) []PrivacySignal {
	if len(in) <= n {
		return in
	}
	return in[:n]
}

func limitFirmwareItems(in []FirmwareItem, n int) []FirmwareItem {
	if len(in) <= n {
		return in
	}
	return in[:n]
}
