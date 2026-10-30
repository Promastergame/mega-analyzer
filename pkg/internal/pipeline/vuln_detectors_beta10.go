package pipeline

import (
	"bytes"
	"fmt"
	"strings"

	"mega-analyzer/pkg/internal/types"
)

// VulnModMenuInjectionDetector flags injected game "mod-menu" / runtime hooking
// native libraries. These are not part of the original app: they are added by
// repackers to hook and patch game logic in memory (cheats/god-mode/free
// purchases). Their presence is strong evidence of a tampered ("mod"/"cracked")
// build and is itself a code-injection risk (CWE-506 Embedded Malicious Code).
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

// modMenuSignatures — high-signal, low-false-positive markers of injected
// mod-menu / inline-hook engines. All lowercase (matched against ContentLower).
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
	hookEngine := false
	firstIdx := -1
	for _, sig := range modMenuSignatures {
		idx := bytes.Index(c, []byte(sig.needle))
		if idx < 0 {
			continue
		}
		labels = append(labels, sig.label)
		if strings.Contains(sig.needle, "hook") {
			hookEngine = true
		}
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
	hookNote := ""
	if hookEngine {
		hookNote = " An inline function-hooking engine is embedded, so game/app logic is patched in process memory at runtime."
	}
	m := newMatch(
		types.CategoryModMenuInjection, analysis.Path, lineAt(ctx.LineOffsets, firstIdx),
		fmt.Sprintf("Injected mod-menu / runtime hooking native library detected: %s. This native code is not part of the original app and indicates a repacked/tampered (\"mod\"/\"cracked\") build.%s Injected code runs with full app privileges and can enable cheats, bypass purchase/license checks, exfiltrate data or load further payloads (CWE-506).", strings.Join(labels, ", "), hookNote),
		"mod_menu_native", true,
	)
	m.Severity = types.SeverityHigh
	analysis.Matches = append(analysis.Matches, m)
}
