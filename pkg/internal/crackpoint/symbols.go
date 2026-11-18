package crackpoint

import "strings"

// ═══════════════════════════════════════════════════════════════════════════════
// SYMBOL-BASED CRACK POINT DISCOVERY (format-agnostic)
// ═══════════════════════════════════════════════════════════════════════════════
//
// FindCrackPoints (crackpoint.go) is bound to a Dalvik ControlFlowGraph and only
// works for Android/smali targets. JAR, native (PE/ELF/Mach-O) and iOS targets
// have no CFG, but they DO expose method/field references, imported & exported
// symbols, linked libraries, entitlements and string constants.
//
// FindCrackPointsInSymbols runs the SAME gate / field / callback pattern tables
// over a flat symbol list, so the primary feature of the tool — finding license /
// premium / tamper gates — works across every supported format. The CFG path is
// left untouched.
// ═══════════════════════════════════════════════════════════════════════════════

// Platform identifies the binary format a symbol set came from. It tailors the
// patch suggestions: smali hints are meaningful for the JVM but nonsense for
// native or iOS code, where patching happens at the instruction level.
type Platform int

const (
	PlatformJVM Platform = iota
	PlatformNative
	PlatformIOS
)

func (p Platform) String() string {
	switch p {
	case PlatformNative:
		return "native"
	case PlatformIOS:
		return "ios"
	default:
		return "jvm"
	}
}

// SymbolKind classifies a SymbolRef so the scanner knows which pattern table to
// consult (fields use the boolean-field table; everything else uses the gate and
// callback tables).
type SymbolKind int

const (
	SymbolMethod SymbolKind = iota
	SymbolField
	SymbolImport
	SymbolExport
	SymbolString
	SymbolDylib
	SymbolEntitlement
)

func (k SymbolKind) String() string {
	switch k {
	case SymbolField:
		return "field"
	case SymbolImport:
		return "import"
	case SymbolExport:
		return "export"
	case SymbolString:
		return "string"
	case SymbolDylib:
		return "dylib"
	case SymbolEntitlement:
		return "entitlement"
	default:
		return "method"
	}
}

// SymbolRef is one format-agnostic symbol fed to the crack-point scanner: a
// method/field reference, an imported/exported native symbol, a decrypted string
// constant, a linked dylib, or an iOS entitlement key.
type SymbolRef struct {
	Name  string     // leaf name (method/field/import/export/dylib/entitlement)
	Kind  SymbolKind // how to interpret it
	Class string     // owning container: dotted JVM class, native binary, iOS bundle id
	Raw   string     // full reference text, used for signal messages and matching
}

// FindCrackPointsInSymbols scans a flat symbol list (no Dalvik CFG required) for
// gate / license / tamper patterns and returns the standard *AnalysisResult, so
// downstream conversion to types.CrackPoint is identical to the CFG path.
//
// Impact is left at 0 (there is no control-flow graph to walk for dependents);
// the renderer already guards on `Impact > 0`.
func (f *Finder) FindCrackPointsInSymbols(symbols []SymbolRef, container string, platform Platform) *AnalysisResult {
	result := &AnalysisResult{
		Categories: make(map[string]int),
		MethodDeps: make(map[string][]string),
	}
	if len(symbols) == 0 {
		return result
	}

	// Augment the shared gate table with platform-specific patterns.
	gates := f.gatePatterns
	switch platform {
	case PlatformNative:
		gates = mergeGatePatterns(f.gatePatterns, nativeGatePatterns())
	case PlatformIOS:
		gates = mergeGatePatterns(f.gatePatterns, iosGatePatterns())
	}

	// De-dup by category+name so a gate referenced many times yields one point.
	seen := make(map[string]bool)

	for _, sym := range symbols {
		name := strings.ToLower(strings.TrimSpace(sym.Name))
		raw := strings.ToLower(sym.Raw)
		hay := raw
		if hay == "" {
			hay = name
		}
		if hay == "" {
			continue
		}
		// Same analytics-SDK noise gate as the CFG invoke passes (the
		// AppsFlyer LVL exception inside isNoisyInvoke is preserved: that
		// module IS license verification, not attribution noise).
		if sym.Raw != "" && isNoisyInvoke(sym.Raw) {
			continue
		}

		if sym.Kind == SymbolField {
			for _, fp := range f.fieldPatterns {
				if strings.Contains(hay, fp) {
					f.addSymbolCrackPoint(result, seen, sym, container,
						CrackPointFieldCheck, f.categorizeField(fp), 0.75,
						"Boolean field pattern: "+fp)
					break
				}
			}
			continue
		}

		// Callbacks first (more specific), then gate patterns.
		if cb := firstContains(hay, f.callbackPatterns); cb != "" {
			f.addSymbolCrackPoint(result, seen, sym, container,
				CrackPointCallback, "callback", 0.80, "Callback pattern: "+cb)
			continue
		}
		for _, gp := range gates {
			// WebP checks its bitstream magic here, not the APK signature.
			// This is a symbol semantic distinction, independent of file name.
			if (platform == PlatformNative || platform == PlatformIOS) && (name == "vp8checksignature" || name == "vp8lchecksignature") {
				continue
			}
			if gp.namePattern == "ispro" && name != "ispro" && name != "isprouser" && name != "isproversion" && name != "isproactive" {
				continue
			}
			if strings.Contains(hay, gp.namePattern) {
				f.addSymbolCrackPoint(result, seen, sym, container,
					CrackPointGateMethod, gp.category, gp.weight,
					"Gate pattern: "+gp.namePattern)
				break
			}
		}
	}

	f.generateSuggestionsForPlatform(result, platform)

	result.TotalFound = len(result.CrackPoints)
	for _, cp := range result.CrackPoints {
		if cp.Confidence >= HighConfidenceThreshold {
			result.HighConfidence++
		}
		result.Categories[cp.Category]++
	}
	return result
}

func (f *Finder) addSymbolCrackPoint(result *AnalysisResult, seen map[string]bool, sym SymbolRef, container string, typ CrackPointType, category string, confidence float64, signal string) {
	name := strings.TrimSpace(sym.Name)
	if name == "" {
		name = sym.Raw
	}
	key := category + "|" + strings.ToLower(name)
	if seen[key] {
		return
	}
	seen[key] = true

	result.CrackPoints = append(result.CrackPoints, CrackPoint{
		ClassName:  container,
		MethodName: name,
		Type:       typ,
		Category:   category,
		Confidence: confidence,
		Signals: []string{
			signal,
			"symbol kind: " + sym.Kind.String(),
		},
	})
}

// firstContains returns the first needle contained in hay, or "".
func firstContains(hay string, needles []string) string {
	for _, n := range needles {
		if strings.Contains(hay, n) {
			return n
		}
	}
	return ""
}

// mergeGatePatterns returns base followed by extra without mutating base.
func mergeGatePatterns(base, extra []gatePattern) []gatePattern {
	out := make([]gatePattern, 0, len(base)+len(extra))
	out = append(out, base...)
	out = append(out, extra...)
	return out
}

// ═══════════════════════════════════════════════════════════════════════════════
// PLATFORM-SPECIFIC GATE PATTERNS
// ═══════════════════════════════════════════════════════════════════════════════

// nativeGatePatterns are anti-debug / anti-tamper / root indicators commonly
// found as imported functions or string constants in native binaries.
func nativeGatePatterns() []gatePattern {
	return []gatePattern{
		{"pt_deny_attach", "tamper", 0.95},
		{"ptrace", "tamper", 0.85},
		{"isdebuggerpresent", "debug", 0.90},
		{"checkremotedebuggerpresent", "debug", 0.85},
		{"ntqueryinformationprocess", "debug", 0.85},
		{"sysctl", "tamper", 0.60},
		// NB: no __stack_chk_fail here — the stack-canary reference is linked
		// into every normally-built binary and is not a crackable decision
		// point (canary presence is reported by the ELF analyzer instead).
		// Android-native root / hooking markers (also seen in .so string tables).
		{"/system/bin/su", "root", 0.90},
		{"/system/xbin/su", "root", 0.90},
		{"magisk", "root", 0.90},
		{"supersu", "root", 0.85},
		// Modern root implementations (string/import level).
		{"zygisk", "root", 0.90},
		{"kernelsu", "root", 0.90},
		{"apatch", "root", 0.85},
		{"adb_enabled", "debug", 0.75},
		{"frida", "tamper", 0.85},
		{"xposed", "tamper", 0.85},
	}
}

// iosGatePatterns cover StoreKit receipt validation, in-app purchase, biometric
// / keychain license gates and jailbreak markers. They include the native
// anti-debug set because iOS binaries are Mach-O too.
func iosGatePatterns() []gatePattern {
	return []gatePattern{
		// In-app purchase / receipt validation
		{"verifyreceipt", "billing", 0.90},
		{"validatereceipt", "billing", 0.90},
		{"appstorereceipt", "billing", 0.85},
		{"skpaymentqueue", "billing", 0.80},
		{"skpaymenttransaction", "billing", 0.80},
		{"canmakepayments", "billing", 0.80},
		{"transactionstate", "billing", 0.75},
		{"inapppurchase", "billing", 0.75},
		{"skproductsrequest", "billing", 0.70},
		// License / auth gates
		{"lacontext", "license", 0.85},
		{"evaluatepolicy", "license", 0.85},
		{"secitemcopymatching", "license", 0.70},
		// Jailbreak / tamper markers
		{"cydia", "tamper", 0.90},
		{"mobilesubstrate", "tamper", 0.90},
		{"checkra1n", "tamper", 0.90},
		{"unc0ver", "tamper", 0.90},
		{"taurine", "tamper", 0.90},
		{"palera1n", "tamper", 0.90},
		{"dopamine", "tamper", 0.85},
		{"/bin/bash", "tamper", 0.85},
		{"/etc/apt", "tamper", 0.85},
		// Native anti-debug (Mach-O)
		{"pt_deny_attach", "tamper", 0.95},
		{"ptrace", "tamper", 0.85},
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// PLATFORM-SPECIFIC SUGGESTIONS
// ═══════════════════════════════════════════════════════════════════════════════

// generateSuggestionsForPlatform routes to the JVM smali generator (unchanged)
// or to native / iOS guidance that never emits smali patch text.
func (f *Finder) generateSuggestionsForPlatform(result *AnalysisResult, platform Platform) {
	if platform == PlatformJVM {
		f.generateSuggestions(result)
		return
	}
	for i := range result.CrackPoints {
		cp := &result.CrackPoints[i]
		cp.SuggestedPatch = "" // no smali for native / iOS
		if platform == PlatformIOS {
			iosSuggestion(cp)
		} else {
			nativeSuggestion(cp)
		}
	}
}

func nativeSuggestion(cp *CrackPoint) {
	switch cp.Category {
	case "premium", "license", "billing":
		cp.SuggestedAction = "Patch the conditional branch that consumes the check result"
		cp.PatchRisk = "high"
		cp.PatchExplanation = "License/billing logic in native code: locate the comparison after the call and invert/NOP the branch, or force the return register. Requires a disassembler — no automated bytecode patch is produced."
	case "root", "emulator":
		cp.SuggestedAction = "Force the detection routine to return 0 (not detected)"
		cp.PatchRisk = "medium"
		cp.PatchExplanation = "Patch the function prologue to `mov eax,0 / ret` (or the ARM equivalent) so the environment check reports a clean device."
	case "debug", "tamper":
		cp.SuggestedAction = "Neutralise the anti-debug / tamper check"
		cp.PatchRisk = "medium"
		cp.PatchExplanation = "For ptrace(PT_DENY_ATTACH) / IsDebuggerPresent / NtQueryInformationProcess: NOP the call or force its result so the debugger/tamper guard is bypassed."
	default:
		cp.SuggestedAction = "Manual investigation needed (native)"
		cp.PatchRisk = "high"
		cp.PatchExplanation = "Disassemble the binary to locate and neutralise the check; no automated patch is generated for native code."
	}
}

func iosSuggestion(cp *CrackPoint) {
	switch cp.Category {
	case "billing":
		cp.SuggestedAction = "Bypass StoreKit receipt / purchase validation"
		cp.PatchRisk = "high"
		cp.PatchExplanation = "StoreKit receipt checks are client-trusted: patch the branch that consumes the validation result, or hook -[SKPaymentTransaction transactionState]. Server-side receipt validation cannot be bypassed on the client."
	case "license":
		cp.SuggestedAction = "Force the auth / biometric policy to succeed"
		cp.PatchRisk = "high"
		cp.PatchExplanation = "For LAContext.evaluatePolicy / keychain gates: patch the success callback or force the policy result; a runtime hook (Frida) is usually simpler than a static patch."
	case "tamper", "debug":
		cp.SuggestedAction = "Defeat the jailbreak / anti-debug detection"
		cp.PatchRisk = "medium"
		cp.PatchExplanation = "Patch the jailbreak/anti-debug routine to report a clean, non-debugged device (e.g. force the Cydia/MobileSubstrate file checks and ptrace(PT_DENY_ATTACH) to no-op)."
	default:
		cp.SuggestedAction = "Manual investigation needed (iOS)"
		cp.PatchRisk = "high"
		cp.PatchExplanation = "Inspect the Mach-O / Objective-C metadata to locate the gate; no automated patch is generated for iOS code."
	}
}
