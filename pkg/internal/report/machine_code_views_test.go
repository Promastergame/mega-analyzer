package report

// Tests for the machine-code PE/.NET view projections: the builder must map
// the structured analysis into the HTML/Markdown views, nil stays nil, and
// the IL callsite table stays display-capped while the JSON keeps the rest.

import (
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/peinspect"
	"mega-analyzer/pkg/internal/types"
)

func TestBuildMachineCodePEView(t *testing.T) {
	if buildMachineCodePEView(nil) != nil {
		t.Error("nil Metadata must yield a nil view")
	}
	v := buildMachineCodePEView(&peinspect.Metadata{
		EntryPointRVA:     0x1000,
		EntryPointVA:      0x401000,
		EntryPointSection: ".text",
		TLSCallbacks:      2,
		TLSStatus:         "ok",
		OverlaySize:       16,
		Sections:          []peinspect.SectionView{{Name: ".text", Permissions: "r-x", VirtualSize: 0x100, RawSize: 0x200}},
		Signature:         peinspect.Signature{Status: "present", Integrity: "valid", Signer: "CN"},
		Diagnostics:       []string{"d1"},
	})
	if !strings.Contains(v.EntryPoint, "0x1000") || !strings.Contains(v.EntryPoint, ".text") {
		t.Errorf("entry = %q", v.EntryPoint)
	}
	if len(v.Sections) != 1 || v.Sections[0].Name != ".text" || v.Sections[0].Permissions != "r-x" {
		t.Errorf("sections = %+v", v.Sections)
	}
	if !strings.Contains(v.Signature, "valid") || !strings.Contains(v.Signature, "CN") {
		t.Errorf("signature = %q", v.Signature)
	}
	if len(v.Diagnostics) != 1 {
		t.Errorf("diagnostics = %+v", v.Diagnostics)
	}
}

func TestBuildMachineCodeDotNetViewCap(t *testing.T) {
	if buildMachineCodeDotNetView(nil) != nil {
		t.Error("nil DotNetInfo must yield a nil view")
	}
	if buildMachineCodeDotNetView(&peinspect.DotNetInfo{}) != nil {
		t.Error("non-managed summary must yield a nil view")
	}
	dn := &peinspect.DotNetInfo{IsDotNet: true, AssemblyName: "A", AssemblyVersion: "1.0.0.0", Culture: "neutral", ILTruncated: true}
	for i := 0; i < 60; i++ {
		dn.ILCallSites = append(dn.ILCallSites, peinspect.ILCallSite{Caller: "M", Op: "call", Target: "T"})
	}
	v := buildMachineCodeDotNetView(dn)
	if len(v.CallSites) != maxViewCallSites || v.CallSitesMore != 10 {
		t.Errorf("sites=%d more=%d, want %d/10", len(v.CallSites), v.CallSitesMore, maxViewCallSites)
	}
	if !strings.Contains(v.ILStats, "truncated") {
		t.Errorf("stats = %q, want truncation note", v.ILStats)
	}
}

func TestBuildMachineCodeReportsWiresPEViews(t *testing.T) {
	b := NewViewBuilder(&types.AnalysisResult{
		MachineCodeReports: []types.MachineCodeReport{{
			Target: "a.exe",
			Format: "pe",
			PE:     &peinspect.Metadata{EntryPointRVA: 0x1000, Sections: []peinspect.SectionView{{Name: ".text"}}},
			DotNet: &peinspect.DotNetInfo{IsDotNet: true, AssemblyName: "A", ILCallSites: []peinspect.ILCallSite{{Caller: "M", Op: "call", Target: "T"}}},
		}},
	}, MarkdownOptions{})
	view := b.Build()
	if len(view.MachineCodeReports) != 1 {
		t.Fatalf("reports = %d, want 1", len(view.MachineCodeReports))
	}
	rep := view.MachineCodeReports[0]
	if rep.PE == nil || len(rep.PE.Sections) != 1 {
		t.Errorf("PE view missing: %+v", rep.PE)
	}
	if rep.DotNet == nil || len(rep.DotNet.CallSites) != 1 || rep.DotNet.CallSites[0].Target != "T" {
		t.Errorf("DotNet view missing: %+v", rep.DotNet)
	}

	var sbOut strings.Builder
	r := &MarkdownRenderer{sb: markdownWriter{&sbOut}}
	r.renderMachineCodeReports(view.MachineCodeReports)
	out := sbOut.String()
	for _, want := range []string{"PE structure", ".text", ".NET assembly", "| M | call | T |"} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown view missing %q:\n%s", want, out)
		}
	}

	var sb strings.Builder
	(&HTMLReporter{}).buildMachineCodeSection(&sb, HTMLReportView{Report: view})
	html := sb.String()
	for _, want := range []string{"PE structure", ".text", ".NET assembly", "Assembly", "M", "call"} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML view missing %q", want)
		}
	}
}
