package main

// Wiring tests: applyNativeScan must carry the structured PE/CLI sections
// into the machine-code report, and the standalone Markdown must project
// them — the same data machine_code.json carries untouched.

import (
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/apkloader"
	"mega-analyzer/pkg/internal/peinspect"
	"mega-analyzer/pkg/internal/types"
)

func machineCodePETestScan() *apkloader.NativeScanReport {
	return &apkloader.NativeScanReport{
		TargetFormat: "pe",
		TargetArch:   "x86",
		Score:        5,
		Verdict:      "low-risk",
		Findings: []apkloader.NativeFinding{
			{ID: "no-aslr", Category: "hardening", Severity: "medium", Confidence: "high", Title: "ASLR off"},
		},
		PE: &peinspect.Metadata{
			Architecture:      "x86",
			EntryPointRVA:     0x1000,
			EntryPointSection: ".text",
			TLSCallbacks:      1,
			TLSStatus:         "callbacks outside image",
			OverlaySize:       8,
			AnalysisStatus:    "ok",
			Sections:          []peinspect.SectionView{{Name: ".text", Permissions: "r-x", VirtualSize: 0x100, RawSize: 0x200}},
			Signature:         peinspect.Signature{Status: "present", Kind: "embedded", Integrity: "unverifiable", Trust: "unknown"},
			Diagnostics:       []string{"suspicious section name"},
		},
		DotNet: &peinspect.DotNetInfo{
			IsDotNet:         true,
			AssemblyName:     "Evil",
			AssemblyVersion:  "1.0.0.0",
			Culture:          "neutral",
			EntryPoint:       "NS.Program.Main",
			TargetFramework:  ".NETFramework,Version=v4.0",
			PInvokes:         []string{"kernel32!VirtualAlloc"},
			DynamicLoadHints: []string{"Assembly::Load"},
			ILMethodsWalked:  2,
			ILCallSites: []peinspect.ILCallSite{
				{Caller: "NS.Program.Main", ILOffset: 0, Op: "call", Target: "Assembly::Load", Token: 0x0A000001},
			},
		},
	}
}

func TestApplyNativeScanCopiesPEStructure(t *testing.T) {
	scan := machineCodePETestScan()
	report := &types.MachineCodeReport{}
	applyNativeScan(report, scan)
	if report.Format != "pe" || report.Arch != "x86" || report.Score != 5 || report.Verdict != "low-risk" {
		t.Errorf("base fields not copied: %+v", report)
	}
	if len(report.Findings) != 1 || report.Findings[0].Title != "ASLR off" {
		t.Errorf("findings not copied: %+v", report.Findings)
	}
	if report.PE == nil || len(report.PE.Sections) != 1 || report.PE.EntryPointRVA != 0x1000 {
		t.Errorf("PE structure not copied: %+v", report.PE)
	}
	if report.DotNet == nil || len(report.DotNet.ILCallSites) != 1 || report.DotNet.AssemblyName != "Evil" {
		t.Errorf("DotNet summary not copied: %+v", report.DotNet)
	}
	applyNativeScan(report, nil) // must keep the report intact
	if report.PE == nil || report.DotNet == nil {
		t.Error("nil scan cleared the report")
	}
}

func TestRenderMachineCodeMarkdownPESections(t *testing.T) {
	report := &types.MachineCodeReport{Target: "a.exe"}
	applyNativeScan(report, machineCodePETestScan())
	md := renderMachineCodeMarkdown(report)
	for _, want := range []string{
		"## PE structure",
		".text",
		"RVA 0x1000",
		"present / integrity unverifiable",
		"suspicious section name",
		"## .NET assembly",
		"Evil, Version=1.0.0.0",
		"NS.Program.Main",
		"kernel32!VirtualAlloc",
		"Assembly::Load",
		"2 methods walked, 1 callsites",
		"| NS.Program.Main | call | Assembly::Load |",
		"## Findings",
		"ASLR off",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q:\n%s", want, md)
		}
	}
}

func TestRenderMachineCodeMarkdownNoPENoSections(t *testing.T) {
	report := &types.MachineCodeReport{Target: "lib.so", Format: "elf"}
	md := renderMachineCodeMarkdown(report)
	if strings.Contains(md, "## PE structure") || strings.Contains(md, "## .NET assembly") {
		t.Errorf("non-PE report must not render PE/.NET sections:\n%s", md)
	}
}
