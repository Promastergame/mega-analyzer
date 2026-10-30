package binzap

import (
	"fmt"
	"os"
	"strings"

	"mega-analyzer/pkg/internal/apkloader"
	"mega-analyzer/pkg/internal/peinspect"
)

// ScanNativeFile runs the native binary analyzer (ELF/PE/Mach-O, including
// managed .NET assemblies) over a single file on disk and renders a
// human-readable report. It never executes the target.
func ScanNativeFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	rep, ok := apkloader.AnalyzeNativeGo(data)
	if !ok {
		return "", fmt.Errorf("unrecognized binary format: %s", path)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "File: %s (%d bytes)\n", path, len(data))
	fmt.Fprintf(&b, "Format: %s | Arch: %s | Verdict: %s | Score: %d\n",
		rep.TargetFormat, rep.TargetArch, rep.Verdict, rep.Score)
	// ILSpy-style managed header when this is a .NET assembly.
	if dn, err := peinspect.ParseDotNet(data); err == nil && dn != nil {
		b.WriteString("\n" + dn.Summary(path) + "\n")
		if len(dn.AssemblyRefs) > 0 {
			n := len(dn.AssemblyRefs)
			if n > 20 {
				n = 20
			}
			b.WriteString("// References (first 20):\n")
			for _, r := range dn.AssemblyRefs[:n] {
				fmt.Fprintf(&b, "//   %s\n", r)
			}
			if len(dn.AssemblyRefs) > 20 {
				fmt.Fprintf(&b, "//   ... +%d more\n", len(dn.AssemblyRefs)-20)
			}
			b.WriteString("\n")
		}
	}
	if len(rep.Findings) == 0 {
		b.WriteString("Findings: none\n")
		return b.String(), nil
	}
	fmt.Fprintf(&b, "Findings (%d):\n", len(rep.Findings))
	for _, f := range rep.Findings {
		fmt.Fprintf(&b, "  [%s] %s: %s\n      %s\n", f.Severity, f.ID, f.Title, f.Description)
	}
	return b.String(), nil
}
