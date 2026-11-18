package pipeline

import (
	"bytes"
	"fmt"
	"strings"

	"mega-analyzer/pkg/internal/finding"
	"mega-analyzer/pkg/internal/types"
)

// VulnModMenuInjectionDetector records mod-menu and hooking-engine identifiers.
// A string match does not establish the library's origin or runtime use;
// packers and legitimate instrumentation can embed the same hooking engines.
type VulnModMenuInjectionDetector struct{}

func NewVulnModMenuInjectionDetector() *VulnModMenuInjectionDetector {
	return &VulnModMenuInjectionDetector{}
}

func (d *VulnModMenuInjectionDetector) Name() string { return "vuln_mod_menu_injection" }

func (d *VulnModMenuInjectionDetector) SupportsFile(fileType types.FileType, path string) bool {
	if fileType == types.FileTypeNative {
		return true
	}
	return strings.HasSuffix(strings.ToLower(path), ".so")
}

// modMenuSignatures are mod-menu / inline-hook identifiers, all lowercase.
var modMenuSignatures = []struct {
	needle string
	label  string
}{
	{"floatingmodmenu", "FloatingModMenu overlay service"},
	{"tdm_ahz", "TDM mod-menu (tdm.ahz.modmenu)"},
	{"libtdmmod", "libtdmmod injected loader"},
	{"modmenu", "generic mod-menu framework"},
	{"substratehookfunction", "Cydia Substrate function hook"},
	{"mshookfunction", "MSHookFunction inline hook"},
	{"dobbyhook", "Dobby inline-hook engine"},
	{"lgl mod menu", "LGL mod-menu framework"},
	{"bearmod", "BearMod injection framework"},
}

func (d *VulnModMenuInjectionDetector) Detect(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	c := ctx.ContentLower
	if len(c) == 0 {
		c = bytes.ToLower(ctx.Content)
	}
	if len(c) == 0 {
		return
	}
	var labels []string
	firstIdx := -1
	for _, sig := range modMenuSignatures {
		idx := bytes.Index(c, []byte(sig.needle))
		if idx < 0 {
			continue
		}
		labels = append(labels, sig.label)
		if firstIdx < 0 || idx < firstIdx {
			firstIdx = idx
		}
	}
	if len(labels) == 0 {
		return
	}
	if firstIdx < 0 {
		firstIdx = 0
	}
	m := newMatch(
		types.CategoryModMenuInjection, analysis.Path, lineAt(ctx.LineOffsets, firstIdx),
		fmt.Sprintf("Native mod-menu or hooking-engine identifiers matched: %s. This static match requires source and call-path review to determine how the library is used.", strings.Join(labels, ", ")),
		"mod_menu_native", true,
	)
	m.Severity = types.SeverityHigh
	m.EvidenceType = "string_match"
	m.ResolvedContext = strings.Join(labels, ", ")
	m.Explanation = &finding.Explanation{
		Status: "observation", Summary: m.Context,
		Limitations: []string{"Matching identifiers do not establish injected origin, tampering, malicious behavior or execution. Packers and legitimate instrumentation can include hooking engines."},
		NextChecks:  []string{"Inspect native call sites and compare library hashes with the original build; use runtime traces only when available from an isolated analysis environment."},
	}
	analysis.Matches = append(analysis.Matches, m)
}
