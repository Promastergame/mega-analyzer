package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"mega-analyzer/pkg/internal/apkloader"
	"mega-analyzer/pkg/internal/peinspect"
	"mega-analyzer/pkg/internal/types"
)

// ═══════════════════════════════════════════════════════════════════════════════
// MACHINE CODE ANALYSIS — direct PE / ELF / .so binary forensics
//
// Routes targets that are raw native binaries (not APKs / DEX / Smali) to the
// Rust scan-native engine via cgo. Produces a stand-alone Markdown + JSON
// report under <output>/machine_code/. Intended for users analysing libraries
// extracted manually, malware blobs, or non-Android executables.
// ═══════════════════════════════════════════════════════════════════════════════

// IsLikelyMachineCodeTarget returns true if the target file extension
// strongly suggests a raw machine-code binary. Used by prepareTarget to
// auto-route when the user did not pass --scan-native.
func IsLikelyMachineCodeTarget(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".so", ".dll", ".exe", ".elf", ".dylib", ".bin", ".o", ".a", ".sys":
		return true
	}
	return false
}

// nativeMagicPrefixes lists the leading bytes that identify a raw
// machine-code binary regardless of file extension. Native *executables*
// (unlike .so/.dll libraries) are routinely shipped with no extension at
// all on Linux/Android — relying on filepath.Ext alone silently drops the
// standalone-machine-code path for them and lets them fall through to the
// APK/DEX pipeline, which then fails with "unrecognized input format".
var nativeMagicPrefixes = [][]byte{
	{0x7F, 'E', 'L', 'F'},    // ELF (Linux / Android native executables & libs)
	{'M', 'Z'},               // PE/COFF (Windows .exe / .dll)
	{0xCF, 0xFA, 0xED, 0xFE}, // Mach-O 64-bit, little-endian
	{0xCE, 0xFA, 0xED, 0xFE}, // Mach-O 32-bit, little-endian
	{0xFE, 0xED, 0xFA, 0xCF}, // Mach-O 64-bit, big-endian
	{0xFE, 0xED, 0xFA, 0xCE}, // Mach-O 32-bit, big-endian
}

// HasMachineCodeMagic peeks at the first bytes of path and reports whether
// they match a known native-binary signature. Used as a content-based
// fallback when the extension gives no signal (or an unfamiliar one) — the
// magic bytes for ELF/PE/Mach-O never collide with APK/ZIP ("PK\x03\x04"),
// DEX ("dex\n"), or any other format this analyzer routes on, so it is safe
// to try unconditionally rather than gating on "no extension".
func HasMachineCodeMagic(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	var buf [4]byte
	n, err := io.ReadFull(f, buf[:])
	if err != nil && n < 2 {
		return false
	}
	for _, magic := range nativeMagicPrefixes {
		if n >= len(magic) && bytesHasPrefix(buf[:n], magic) {
			return true
		}
	}
	return false
}

func bytesHasPrefix(b, prefix []byte) bool {
	if len(b) < len(prefix) {
		return false
	}
	for i, p := range prefix {
		if b[i] != p {
			return false
		}
	}
	return true
}

// nonNativeExtensions are extensions the rest of the pipeline already
// routes explicitly (APK / archive / DEX / patch families). Magic-byte
// sniffing is skipped for these so an SFX-style polyglot (e.g. a .zip with
// a prepended PE/MZ stub) still goes through the format it was named for
// instead of being hijacked into machine-code mode.
var nonNativeExtensions = map[string]bool{
	".apk": true, ".xapk": true, ".apks": true, ".apkm": true, ".aab": true,
	".obb": true, ".ipa": true, ".zip": true,
	".jar": true, ".war": true, ".ear": true, ".aar": true,
	".dex": true, ".vdex": true, ".odex": true, ".art": true, ".oat": true,
	".patch": true, ".diff": true,
}

func isKnownNonNativeExtension(path string) bool {
	return nonNativeExtensions[strings.ToLower(filepath.Ext(path))]
}

// (типы MachineCodeReport / MachineCodeStatistics теперь живут в pkg/internal/types)
// Здесь оставляем только конвертеры и рендереры.

// handleMachineCode runs the machine-code analysis path end-to-end.
// On platforms / builds without the Rust bridge it falls back to a
// pure-Go native analysis.
func (a *App) handleMachineCode(absTarget string) error {
	a.output.Info("══════ Machine-Code Analysis ══════")
	a.output.Info("Target: %s", absTarget)

	info, err := os.Stat(absTarget)
	if err != nil {
		return fmt.Errorf("stat machine-code target: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("machine-code mode expects a file, got directory: %s", absTarget)
	}

	data, err := os.ReadFile(absTarget)
	if err != nil {
		return fmt.Errorf("read machine-code target: %w", err)
	}

	startedAt := time.Now()

	report := &types.MachineCodeReport{
		GeneratedAt:   startedAt,
		EngineVersion: Version,
		Target:        absTarget,
		Size:          info.Size(),
		Statistics: types.MachineCodeStatistics{
			BySeverity: map[string]int{},
			ByCategory: map[string]int{},
		},
	}

	scan, rustRan, notes := nativeScanWithFallback(data)
	report.Notes = append(report.Notes, notes...)
	report.Verdict = "unavailable"
	applyNativeScan(report, scan)

	// Crack points + embedded secrets via the pure-Go symbol/string scan. These
	// run regardless of whether the Rust scanner was available. The numeric-PIN
	// heuristic specifically is fallback-only: the Rust scan already covers it
	// (plus linker string-merge recovery Go doesn't attempt), so running both
	// would double-report every short digit run.
	report.CrackPoints = apkloader.DetectNativeCrackPoints(data, absTarget)
	report.Findings = append(report.Findings, nativeSecretsToFindings(apkloader.NativeSecretFindings(data, absTarget, a.opts.MCRevealSecrets, !rustRan))...)

	outDir := a.opts.Output
	if outDir == "" {
		outDir = "analysis_output"
	}
	mcDir := filepath.Join(outDir, "machine_code")
	if err := os.MkdirAll(mcDir, 0o755); err != nil {
		return fmt.Errorf("create machine-code output dir: %w", err)
	}

	if err := writeMachineCodeReports(report, mcDir); err != nil {
		return err
	}

	elapsed := time.Since(startedAt)
	a.output.Success("Machine-code analysis done in %s", elapsed.Round(time.Millisecond))
	a.output.Info("Format: %s  Arch: %s  Verdict: %s  Score: %d/100",
		emptyOrDash(report.Format), emptyOrDash(report.Arch),
		emptyOrDash(report.Verdict), report.Score)
	a.output.Info("Findings: %d  →  %s", len(report.Findings),
		filepath.Join(mcDir, "MACHINE_CODE.md"))
	if report.PE != nil {
		a.output.Info("PE: %d sections  entry 0x%x (%s)  overlay %d bytes  signature %s/%s",
			len(report.PE.Sections), report.PE.EntryPointRVA,
			emptyOrDash(report.PE.EntryPointSection), report.PE.OverlaySize,
			emptyOrDash(report.PE.Signature.Status), emptyOrDash(report.PE.Signature.Integrity))
	}
	if report.DotNet != nil && report.DotNet.IsDotNet {
		trunc := ""
		if report.DotNet.ILTruncated {
			trunc = ", truncated"
		}
		a.output.Info(".NET: %s %s  entry %s  IL: %d methods, %d callsites%s",
			emptyOrDash(report.DotNet.AssemblyName), emptyOrDash(report.DotNet.AssemblyVersion),
			emptyOrDash(report.DotNet.EntryPoint),
			report.DotNet.ILMethodsWalked, len(report.DotNet.ILCallSites), trunc)
	}

	return nil
}

// nativeSecretsToFindings converts offline-classifier secret findings into
// machine-code findings so they ride the standalone JSON + Markdown report.
func nativeSecretsToFindings(secrets []types.ArtifactFinding) []types.MachineCodeFinding {
	out := make([]types.MachineCodeFinding, 0, len(secrets))
	for _, sf := range secrets {
		f := types.MachineCodeFinding{
			Category:    "EMBEDDED_SECRET",
			Severity:    sf.Severity.String(),
			Title:       "Embedded credential",
			Description: sf.Reason,
			Evidence:    sf.Payload,
		}
		if sf.PayloadFull != "" {
			f.PayloadFull = &sf.PayloadFull
		}
		out = append(out, f)
	}
	return out
}

// nativeScanWithFallback preserves whether Rust ran for Rust-only deduplication.
func nativeScanWithFallback(data []byte) (*apkloader.NativeScanReport, bool, []string) {
	scan, err := apkloader.ScanNativeWithRust(data)
	return resolveNativeScan(data, scan, err)
}

func resolveNativeScan(data []byte, scan *apkloader.NativeScanReport, err error) (*apkloader.NativeScanReport, bool, []string) {
	if err == nil && scan != nil {
		return scan, true, nil
	}
	reason := "Rust native scanner returned no result"
	if err != nil {
		reason = "Rust native scanner unavailable: " + err.Error()
	}
	if fallback, ok := apkloader.AnalyzeNativeGo(data); ok && fallback != nil {
		return fallback, false, []string{reason, "Using the Go native analyzer."}
	}
	return nil, false, []string{reason, "Go native analyzer did not recognize this file."}
}

// applyNativeScan copies one native scan into a machine-code report. Shared
// by the standalone and side-car flows so JSON, CLI and Markdown always see
// the same data, including the structured PE and .NET sections.
func applyNativeScan(report *types.MachineCodeReport, scan *apkloader.NativeScanReport) {
	if scan == nil {
		return
	}
	report.Format = scan.TargetFormat
	report.Arch = scan.TargetArch
	report.Score = scan.Score
	report.Verdict = scan.Verdict
	report.Hardening = types.MachineCodeHardening{
		NX:            scan.Hardening.NX,
		PIE:           scan.Hardening.PIE,
		Relro:         scan.Hardening.Relro,
		StackCanary:   scan.Hardening.StackCanary,
		FortifySource: scan.Hardening.FortifySource,
		Stripped:      scan.Hardening.Stripped,
		WxSections:    scan.Hardening.WxSections,
	}
	for _, f := range scan.Findings {
		report.Findings = append(report.Findings, types.MachineCodeFinding{
			Category:    f.Category,
			Severity:    f.Severity,
			Confidence:  f.Confidence,
			Title:       f.Title,
			Description: f.Description,
			Evidence:    f.Evidence,
			CWE:         f.CWE,
			Remediation: f.Remediation,
			FileOffset:  f.FileOffset,
			Payload:     f.Payload,
		})
	}
	report.PE = scan.PE
	report.DotNet = scan.DotNet
	report.Statistics = computeMachineCodeStats(scan)
}

func computeMachineCodeStats(scan *apkloader.NativeScanReport) types.MachineCodeStatistics {
	var findings []types.MachineCodeFinding
	if scan != nil {
		for _, f := range scan.Findings {
			findings = append(findings, types.MachineCodeFinding{Category: f.Category, Severity: f.Severity, CWE: f.CWE, Payload: f.Payload})
		}
	}
	return machineCodeFindingStats(findings)
}

func machineCodeFindingStats(findings []types.MachineCodeFinding) types.MachineCodeStatistics {
	stats := types.MachineCodeStatistics{TotalFindings: len(findings), BySeverity: map[string]int{}, ByCategory: map[string]int{}}
	for _, f := range findings {
		if sev := strings.TrimSpace(f.Severity); sev != "" {
			stats.BySeverity[sev]++
		}
		if cat := strings.TrimSpace(f.Category); cat != "" {
			stats.ByCategory[cat]++
		}
		if f.CWE != nil && *f.CWE != "" {
			stats.WithCWE++
		}
		if f.Payload != nil && *f.Payload != "" {
			stats.WeaponizedPayloads++
		}
	}
	return stats
}

func writeMachineCodeReports(report *types.MachineCodeReport, dir string) error {
	report.Statistics = machineCodeFindingStats(report.Findings)
	jsonPath := filepath.Join(dir, "machine_code.json")
	jsonBytes, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal machine-code json: %w", err)
	}
	if err := os.WriteFile(jsonPath, jsonBytes, 0o644); err != nil {
		return fmt.Errorf("write machine-code json: %w", err)
	}

	mdPath := filepath.Join(dir, "MACHINE_CODE.md")
	if err := os.WriteFile(mdPath, []byte(renderMachineCodeMarkdown(report)), 0o644); err != nil {
		return fmt.Errorf("write machine-code md: %w", err)
	}
	return nil
}

func renderMachineCodeMarkdown(r *types.MachineCodeReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Machine-Code Analysis\n\n")
	fmt.Fprintf(&b, "- **Target**: `%s`\n", r.Target)
	fmt.Fprintf(&b, "- **Size**: %d bytes\n", r.Size)
	fmt.Fprintf(&b, "- **Format**: %s\n", emptyOrDash(r.Format))
	fmt.Fprintf(&b, "- **Architecture**: %s\n", emptyOrDash(r.Arch))
	fmt.Fprintf(&b, "- **Verdict**: %s\n", emptyOrDash(r.Verdict))
	fmt.Fprintf(&b, "- **Risk score**: %d / 100\n", r.Score)
	fmt.Fprintf(&b, "- **Engine**: Mega-Analyzer %s\n", r.EngineVersion)
	fmt.Fprintf(&b, "- **Generated**: %s\n\n", r.GeneratedAt.Format(time.RFC3339))

	if len(r.Notes) > 0 {
		b.WriteString("## Notes\n\n")
		for _, n := range r.Notes {
			fmt.Fprintf(&b, "- %s\n", n)
		}
		b.WriteString("\n")
	}

	b.WriteString("## Hardening posture\n\n")
	b.WriteString("| Mitigation | Status |\n|---|---|\n")
	fmt.Fprintf(&b, "| NX / DEP | %s |\n", boolPtrStatus(r.Hardening.NX))
	fmt.Fprintf(&b, "| PIE / ASLR | %s |\n", boolPtrStatus(r.Hardening.PIE))
	fmt.Fprintf(&b, "| RELRO | %s |\n", emptyOrDash(r.Hardening.Relro))
	fmt.Fprintf(&b, "| Stack canary | %s |\n", boolPtrStatus(r.Hardening.StackCanary))
	fmt.Fprintf(&b, "| FORTIFY_SOURCE | %s |\n", boolPtrStatus(r.Hardening.FortifySource))
	fmt.Fprintf(&b, "| Stripped | %s |\n", boolPtrStatus(r.Hardening.Stripped))
	fmt.Fprintf(&b, "| W^X violations | %d |\n\n", r.Hardening.WxSections)

	renderMachineCodePESection(&b, r.PE)
	renderMachineCodeDotNetSection(&b, r.DotNet)

	if len(r.CrackPoints) > 0 {
		b.WriteString("## Crack points\n\n")
		b.WriteString("| Gate | Category | Confidence | Suggestion |\n|---|---|---|---|\n")
		for _, cp := range r.CrackPoints {
			fmt.Fprintf(&b, "| %s | %s | %.2f | %s |\n",
				emptyOrDash(cp.Method), emptyOrDash(cp.Category), cp.Confidence, emptyOrDash(cp.Suggestion))
		}
		b.WriteString("\n")
	}

	b.WriteString("## Statistics\n\n")
	fmt.Fprintf(&b, "- Findings: **%d**\n", r.Statistics.TotalFindings)
	fmt.Fprintf(&b, "- With CWE: %d\n", r.Statistics.WithCWE)
	fmt.Fprintf(&b, "- Weaponized payloads: %d\n\n", r.Statistics.WeaponizedPayloads)

	if len(r.Statistics.BySeverity) > 0 {
		b.WriteString("### By severity\n\n")
		for sev, count := range r.Statistics.BySeverity {
			fmt.Fprintf(&b, "- %s — %d\n", sev, count)
		}
		b.WriteString("\n")
	}

	if len(r.Statistics.ByCategory) > 0 {
		b.WriteString("### By category\n\n")
		for cat, count := range r.Statistics.ByCategory {
			fmt.Fprintf(&b, "- %s — %d\n", cat, count)
		}
		b.WriteString("\n")
	}

	if len(r.Findings) == 0 {
		b.WriteString("## Findings\n\n_No findings produced._\n")
		return b.String()
	}

	b.WriteString("## Findings\n\n")
	for i, f := range r.Findings {
		fmt.Fprintf(&b, "### %d. %s\n\n", i+1, emptyOrDash(f.Title))
		fmt.Fprintf(&b, "- **Category**: %s\n", emptyOrDash(f.Category))
		fmt.Fprintf(&b, "- **Severity**: %s\n", emptyOrDash(f.Severity))
		fmt.Fprintf(&b, "- **Confidence**: %s\n", emptyOrDash(f.Confidence))
		if f.CWE != nil && *f.CWE != "" {
			fmt.Fprintf(&b, "- **CWE**: %s\n", *f.CWE)
		}
		if f.FileOffset != nil {
			fmt.Fprintf(&b, "- **Offset**: 0x%x\n", *f.FileOffset)
		}
		if f.Description != "" {
			fmt.Fprintf(&b, "\n%s\n\n", f.Description)
		}
		if f.Evidence != "" {
			fmt.Fprintf(&b, "Evidence: `%s`\n\n", f.Evidence)
		}
		if f.Remediation != nil && *f.Remediation != "" {
			fmt.Fprintf(&b, "Remediation: %s\n\n", *f.Remediation)
		}
	}
	return b.String()
}

// renderMachineCodePESection projects the structured PE analysis into the
// standalone Markdown report: sections, entry point, TLS, overlay and the
// offline signature state. The same data rides machine_code.json untouched.
func renderMachineCodePESection(b *strings.Builder, pe *peinspect.Metadata) {
	if pe == nil {
		return
	}
	b.WriteString("## PE structure\n\n")
	fmt.Fprintf(b, "- **Entry point**: RVA 0x%x (VA 0x%x, section %s)\n",
		pe.EntryPointRVA, pe.EntryPointVA, emptyOrDash(pe.EntryPointSection))
	fmt.Fprintf(b, "- **TLS callbacks**: %d (%s)\n", pe.TLSCallbacks, emptyOrDash(pe.TLSStatus))
	fmt.Fprintf(b, "- **Overlay**: %d bytes\n", pe.OverlaySize)
	fmt.Fprintf(b, "- **Analysis**: %s\n", emptyOrDash(pe.AnalysisStatus))
	if len(pe.Sections) > 0 {
		b.WriteString("\n| Section | Permissions | Virtual size | File size |\n|---|---|---|---|\n")
		for _, s := range pe.Sections {
			fmt.Fprintf(b, "| %s | %s | 0x%x | 0x%x |\n", s.Name, s.Permissions, s.VirtualSize, s.RawSize)
		}
		b.WriteString("\n")
	}
	sig := pe.Signature
	fmt.Fprintf(b, "- **Signature**: %s / integrity %s", emptyOrDash(sig.Status), emptyOrDash(sig.Integrity))
	if sig.Signer != "" {
		fmt.Fprintf(b, " by %s", sig.Signer)
	}
	b.WriteString("\n")
	if sig.Verification != "" {
		fmt.Fprintf(b, "- **Verification**: %s\n", sig.Verification)
	}
	if sig.Note != "" {
		fmt.Fprintf(b, "- **Signature note**: %s\n", sig.Note)
	}
	for _, d := range pe.Diagnostics {
		fmt.Fprintf(b, "- **Diagnostic**: %s\n", d)
	}
	b.WriteString("\n")
}

// renderMachineCodeDotNetSection projects the CLI metadata summary with IL
// callsites. The callsite table is display-capped; the JSON report always
// carries the full list.
func renderMachineCodeDotNetSection(b *strings.Builder, dn *peinspect.DotNetInfo) {
	if dn == nil || !dn.IsDotNet {
		return
	}
	b.WriteString("## .NET assembly\n\n")
	pkt := "null"
	if dn.PublicKeyToken != "" {
		pkt = dn.PublicKeyToken
	}
	fmt.Fprintf(b, "- **Assembly**: %s, Version=%s, Culture=%s, PublicKeyToken=%s\n",
		emptyOrDash(dn.AssemblyName), emptyOrDash(dn.AssemblyVersion), emptyOrDash(dn.Culture), pkt)
	if dn.EntryPoint != "" {
		fmt.Fprintf(b, "- **Entry point**: %s\n", dn.EntryPoint)
	}
	if dn.TargetFramework != "" {
		fmt.Fprintf(b, "- **Target framework**: %s\n", dn.TargetFramework)
	}
	trunc := ""
	if dn.ILTruncated {
		trunc = " (truncated at cap)"
	}
	fmt.Fprintf(b, "- **IL**: %d methods walked, %d callsites%s\n", dn.ILMethodsWalked, len(dn.ILCallSites), trunc)
	for _, p := range dn.PInvokes {
		fmt.Fprintf(b, "- **P/Invoke**: %s\n", p)
	}
	for _, h := range dn.DynamicLoadHints {
		fmt.Fprintf(b, "- **Dynamic-load hint**: %s\n", h)
	}
	if len(dn.ILCallSites) > 0 {
		const maxRows = 50
		b.WriteString("\n| Caller | Op | Target |\n|---|---|---|\n")
		for i, cs := range dn.ILCallSites {
			if i >= maxRows {
				fmt.Fprintf(b, "| … | | %d more callsites in machine_code.json |\n", len(dn.ILCallSites)-maxRows)
				break
			}
			fmt.Fprintf(b, "| %s | %s | %s |\n", cs.Caller, cs.Op, cs.Target)
		}
		b.WriteString("\n")
	} else {
		b.WriteString("\n")
	}
}

func boolPtrStatus(b *bool) string {
	switch {
	case b == nil:
		return "unknown"
	case *b:
		return "enabled"
	default:
		return "missing"
	}
}

func emptyOrDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

// isNativeBinaryFile reports whether path looks like a raw native binary,
// either by extension (IsLikelyMachineCodeTarget) or, for extensionless
// files with no other claimed extension, by sniffing magic bytes
// (HasMachineCodeMagic). Shared by the standalone-mode detector
// (shouldRunMachineCode) and the APK side-car walk (runMachineCodeSidecar)
// so both catch extensionless native executables (the normal shape of a
// Linux/Android native binary) the same way.
func isNativeBinaryFile(path string) bool {
	if IsLikelyMachineCodeTarget(path) {
		return true
	}
	return !isKnownNonNativeExtension(path) && HasMachineCodeMagic(path)
}

// shouldRunMachineCode decides whether the App should dispatch to the
// standalone machine-code analysis path INSTEAD OF the regular APK/DEX pipeline.
//
// Standalone mode activates ONLY when the target is a raw native binary file.
// When the target is an APK, directory, or DEX file, the flag --scan-native
// is treated as an opt-in side-car scan that runs inside the normal pipeline.
//
// Activation rules:
//  1. Target is a regular file that looks like a native binary, by extension
//     (.so / .dll / .exe / .elf / .dylib …) or magic bytes → standalone flow.
//  2. Otherwise (APK / directory / DEX) → return false so the normal pipeline
//     handles it; --scan-native will trigger a post-analysis .so scan.
func (a *App) shouldRunMachineCode() bool {
	if a == nil || a.opts == nil || a.opts.Target == "" {
		return false
	}
	info, err := os.Stat(a.opts.Target)
	if err != nil || info.IsDir() {
		return false
	}
	if a.opts.MachineCode {
		return true
	}
	// Even if --scan-native was passed, do NOT bypass the APK pipeline
	// when the target is an APK or directory.
	return isNativeBinaryFile(a.opts.Target)
}

// runMachineCodeSidecar scans every .so file inside targetDir (the extracted
// APK directory) and produces full MachineCodeReports.  The reports are written
// to <outputDir>/machine_code/ and also returned so the caller can attach them
// to the main AnalysisResult.
func (a *App) runMachineCodeSidecar(targetDir, outputDir string) ([]types.MachineCodeReport, error) {
	var reports []types.MachineCodeReport

	if outputDir == "" {
		outputDir = "analysis_output"
	}
	mcDir := filepath.Join(outputDir, "machine_code")
	_ = os.MkdirAll(mcDir, 0o755)

	var soFiles []string
	filepath.Walk(targetDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !isNativeBinaryFile(path) {
			return nil
		}
		soFiles = append(soFiles, path)
		return nil
	})

	if len(soFiles) == 0 {
		return nil, nil
	}

	a.output.Info("═══ Machine-Code side-car scan: %d target file(s) ═══", len(soFiles))

	for _, soPath := range soFiles {
		data, err := os.ReadFile(soPath)
		if err != nil {
			a.output.Warning("failed to read %s: %v", soPath, err)
			continue
		}

		info, _ := os.Stat(soPath)
		var size int64
		if info != nil {
			size = info.Size()
		}

		report := types.MachineCodeReport{
			GeneratedAt:   time.Now(),
			EngineVersion: Version,
			Target:        soPath,
			Size:          size,
			Statistics: types.MachineCodeStatistics{
				BySeverity: map[string]int{},
				ByCategory: map[string]int{},
			},
		}

		scan, rustRan, notes := nativeScanWithFallback(data)
		report.Notes = append(report.Notes, notes...)
		report.Verdict = "unavailable"
		applyNativeScan(&report, scan)

		// Crack points + embedded secrets (pure-Go, Rust-free). Numeric-PIN
		// detection only runs here when the Rust scan didn't (see the matching
		// comment in handleMachineCode) to avoid double-reporting.
		report.CrackPoints = apkloader.DetectNativeCrackPoints(data, soPath)
		report.Findings = append(report.Findings, nativeSecretsToFindings(apkloader.NativeSecretFindings(data, soPath, a.opts.MCRevealSecrets, !rustRan))...)

		// Write per-file standalone report
		ext := filepath.Ext(soPath)
		soName := strings.TrimSuffix(filepath.Base(soPath), ext)
		soDir := filepath.Join(mcDir, soName)
		_ = os.MkdirAll(soDir, 0o755)
		_ = writeMachineCodeReports(&report, soDir)

		reports = append(reports, report)
		a.output.Success("  %s → score %d/100, %d findings", filepath.Base(soPath), report.Score, len(report.Findings))
	}

	return reports, nil
}
