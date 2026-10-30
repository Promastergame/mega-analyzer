package apkloader

import (
	"fmt"
	"regexp"
	"strings"
)

var aapt2LocRe = regexp.MustCompile(`(?m)^([^:\n]+):(\d+):(\d+):\s*(?:error|warn(?:ing)?)?:?\s*(.*)$`)

func ParseAapt2Output(stage, output string) []Diagnostic {
	output = strings.TrimSpace(output)
	if output == "" {
		return nil
	}
	var diags []Diagnostic
	for _, m := range aapt2LocRe.FindAllStringSubmatch(output, -1) {
		d := Diagnostic{Code: "AAPT2_ERROR", Severity: DiagError, Stage: stage, Path: m[1], Message: strings.TrimSpace(m[4]), Cause: output, Hint: "fix the referenced Android resource or manifest entry"}
		fmtSscanfInt(m[2], &d.Line)
		fmtSscanfInt(m[3], &d.Column)
		diags = append(diags, d)
	}
	if len(diags) == 0 {
		diags = append(diags, Diagnostic{Code: "AAPT2_ERROR", Severity: DiagError, Stage: stage, Message: firstNonEmptyLine(output), Cause: output, Hint: "rerun with aapt2 output enabled and inspect resource XML/manifest syntax"})
	}
	return diags
}

func fmtSscanfInt(s string, dst *int) { _, _ = fmt.Sscanf(s, "%d", dst) }
