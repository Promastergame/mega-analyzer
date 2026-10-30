package report

// UI projections of the structured PE / .NET analysis for the machine-code
// report views (HTML + Markdown). The JSON reports carry the full
// peinspect structs untouched; these views select the display-relevant
// subset so huge tables (sections, IL callsites) stay bounded in the UI.

import (
	"fmt"

	"mega-analyzer/pkg/internal/peinspect"
)

// maxViewCallSites caps the IL callsite table in the UI views; the remainder
// is counted in MachineCodeDotNetView.CallSitesMore.
const maxViewCallSites = 50

func buildMachineCodePEView(pe *peinspect.Metadata) *MachineCodePEView {
	if pe == nil {
		return nil
	}
	v := &MachineCodePEView{
		EntryPoint: fmt.Sprintf("RVA 0x%x (VA 0x%x, section %s)",
			pe.EntryPointRVA, pe.EntryPointVA, dash(pe.EntryPointSection)),
		TLS:      fmt.Sprintf("%d callbacks (%s)", pe.TLSCallbacks, dash(pe.TLSStatus)),
		Overlay:  fmt.Sprintf("%d bytes", pe.OverlaySize),
		Analysis: dash(pe.AnalysisStatus),
	}
	for _, s := range pe.Sections {
		v.Sections = append(v.Sections, MachineCodeSectionView{
			Name:        s.Name,
			Permissions: s.Permissions,
			VirtualSize: fmt.Sprintf("0x%x", s.VirtualSize),
			FileSize:    fmt.Sprintf("0x%x", s.RawSize),
		})
	}
	sig := pe.Signature
	v.Signature = fmt.Sprintf("%s / integrity %s", dash(sig.Status), dash(sig.Integrity))
	if sig.Signer != "" {
		v.Signature += " by " + sig.Signer
	}
	if sig.Verification != "" {
		v.Signature += " — " + sig.Verification
	}
	v.Diagnostics = append(v.Diagnostics, pe.Diagnostics...)
	return v
}

func buildMachineCodeDotNetView(dn *peinspect.DotNetInfo) *MachineCodeDotNetView {
	if dn == nil || !dn.IsDotNet {
		return nil
	}
	pkt := "null"
	if dn.PublicKeyToken != "" {
		pkt = dn.PublicKeyToken
	}
	v := &MachineCodeDotNetView{
		Assembly:   fmt.Sprintf("%s, Version=%s, Culture=%s, PublicKeyToken=%s", dn.AssemblyName, dn.AssemblyVersion, dn.Culture, pkt),
		EntryPoint: dash(dn.EntryPoint),
		Framework:  dash(dn.TargetFramework),
	}
	v.ILStats = fmt.Sprintf("%d methods walked, %d callsites", dn.ILMethodsWalked, len(dn.ILCallSites))
	if dn.ILTruncated {
		v.ILStats += " (truncated at cap)"
	}
	v.PInvokes = append(v.PInvokes, dn.PInvokes...)
	v.Hints = append(v.Hints, dn.DynamicLoadHints...)
	for i, cs := range dn.ILCallSites {
		if i >= maxViewCallSites {
			v.CallSitesMore = len(dn.ILCallSites) - maxViewCallSites
			break
		}
		v.CallSites = append(v.CallSites, MachineCodeILCallView{
			Caller: cs.Caller,
			Op:     cs.Op,
			Target: cs.Target,
		})
	}
	return v
}

func dash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
