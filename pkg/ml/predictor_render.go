package ml

import (
	"fmt"
	"io"
	"strings"
)


// ═══════════════════════════════════════════════════════════════════════════════
// TERMINAL RENDER (с MAIN FINDINGS, LIBRARY секцией, безопасными формулировками)
// ═══════════════════════════════════════════════════════════════════════════════

func (pp *PatchPredictor) RenderToTerminal(prediction *PatchPrediction) {
	w := pp.output

	fmt.Fprintln(w)
	fmt.Fprintln(w, "  ╔══════════════════════════════════════════╗")
	fmt.Fprintln(w, "  ║       POTENTIAL PATCH POINTS             ║")
	fmt.Fprintln(w, "  ║        ML Risk Analysis                  ║")
	fmt.Fprintln(w, "  ╚══════════════════════════════════════════╝")
	fmt.Fprintln(w)

	// 🆕 PARTIAL RESULTS WARNING
	if prediction.PartialResults {
		fmt.Fprintln(w, "  ╔════════════════════════════════════════════════╗")
		fmt.Fprintln(w, "  ║  🔴 WARNING: analysis timed out (partial only) ║")
		fmt.Fprintln(w, "  ║  Some methods may have been skipped.           ║")
		fmt.Fprintln(w, "  ╚════════════════════════════════════════════════╝")
		fmt.Fprintln(w)
	}

	pp.printTerminologyLegend(w)

	// 🆕 MAIN FINDINGS — самое важное вверх
	if len(prediction.MainFindings) > 0 {
		fmt.Fprintln(w, "  ════════════════════════════════════════")
		fmt.Fprintln(w, "  ⚠️  MAIN FINDINGS")
		fmt.Fprintln(w, "  ════════════════════════════════════════")
		for _, f := range prediction.MainFindings {
			fmt.Fprintf(w, "  • %s\n", f)
		}
		fmt.Fprintln(w)
	}

	// 🆕 TOP ISSUES
	if len(prediction.TopIssues) > 0 {
		fmt.Fprintln(w, "  TOP ISSUES")
		fmt.Fprintln(w, "  ──────────")
		for i, issue := range prediction.TopIssues {
			fmt.Fprintf(w, "  %d. %s\n", i+1, issue)
		}
		fmt.Fprintln(w)
	}

	// Summary
	s := prediction.Stats
	fmt.Fprintln(w, "  Summary")
	fmt.Fprintln(w, "  ───────")
	fmt.Fprintf(w, "  Files scanned     : %d\n", s.TotalFilesScanned)
	fmt.Fprintf(w, "  Methods analyzed  : %d\n", s.MethodsAnalyzed)
	fmt.Fprintf(w, "  Patch points      : %d\n", s.PatchPointsFound)
	fmt.Fprintf(w, "  🔴 High risk      : %d\n", s.HighRiskCount)
	fmt.Fprintf(w, "  🟡 Medium risk    : %d\n", s.MediumRiskCount)
	fmt.Fprintf(w, "  🔎 Audit findings : %d\n", s.AuditFindingsCount+s.MalwareFindingsCount)
	fmt.Fprintf(w, "  📦 Library noise  : %d (deprioritized)\n", s.LibraryFindingsCount)
	fmt.Fprintln(w)

	if s.PatchPointsFound == 0 && s.AuditFindingsCount+s.MalwareFindingsCount == 0 {
		fmt.Fprintln(w, "  No patch points detected. No audit findings detected.")
		fmt.Fprintln(w)
		return
	}

	if len(s.TopCategories) > 0 {
		fmt.Fprintln(w, "  Categories Found")
		fmt.Fprintln(w, "  ────────────────")
		for _, cat := range s.TopCategories {
			fmt.Fprintf(w, "    %-25s %d points\n", cat.Name, cat.Count)
		}
		fmt.Fprintln(w)
	}

	if len(prediction.MalwareIndicators) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  🔎 SECURITY AUDIT — High-confidence Findings")
		fmt.Fprintln(w, "  ════════════════════════════════════════════")
		for i, point := range prediction.MalwareIndicators {
			pp.renderAuditPoint(w, i+1, &point)
		}
	}

	if len(prediction.AuditFindings) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  🔎 SECURITY AUDIT — Review")
		fmt.Fprintln(w, "  ═════════════════════════")
		for i, point := range prediction.AuditFindings {
			pp.renderAuditPoint(w, i+1, &point)
		}
	}

	// HIGH RISK (только app code теперь!)
	if len(prediction.HighRisk) > 0 {
		fmt.Fprintln(w, "  🔴 HIGH RISK — App Code (priority)")
		fmt.Fprintln(w, "  ════════════════════════════════════")
		for i, point := range prediction.HighRisk {
			pp.renderPoint(w, i+1, &point)
		}
	}

	if len(prediction.MediumRisk) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  🟡 MEDIUM RISK — App Code")
		fmt.Fprintln(w, "  ══════════════════════════")
		for i, point := range prediction.MediumRisk {
			pp.renderPoint(w, i+1, &point)
		}
	}

	if len(prediction.LowRisk) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  🟢 LOW RISK")
		fmt.Fprintln(w, "  ══════════")
		for i, point := range prediction.LowRisk {
			fmt.Fprintf(w, "  %d. %s → %s (%.0f%%)\n",
				i+1, ShortFilePath(point.FilePath), point.MethodName, point.RiskScore)
		}
	}

	// 🆕 LIBRARY FINDINGS — отдельным блоком, в конце
	if len(prediction.LibraryFindings) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  ════════════════════════════════════════════════")
		fmt.Fprintln(w, "  📦 LIBRARY FINDINGS (low priority — third-party)")
		fmt.Fprintln(w, "  ════════════════════════════════════════════════")
		fmt.Fprintln(w, "  These are matches inside known libraries (BouncyCastle/SpongyCastle,")
		fmt.Fprintln(w, "  jose4j, Braze, Microsoft SDK, etc.) — usually NOT the target of")
		fmt.Fprintln(w, "  cracking. Review only if you suspect tampering with the library itself.")
		fmt.Fprintln(w)

		for i, point := range prediction.LibraryFindings {
			tag := "[LIB]"
			if point.LibraryName != "" {
				tag = fmt.Sprintf("[LIB:%s]", point.LibraryName)
			}
			fmt.Fprintf(w, "  %d. %s %s\n", i+1, tag, ShortFilePath(point.FilePath))
			fmt.Fprintf(w, "     %s() — risk %.0f%% — %s\n",
				point.MethodName, point.RiskScore, point.CategoryName)
		}
	}

	fmt.Fprintln(w)
}

func (pp *PatchPredictor) printTerminologyLegend(w io.Writer) {
	fmt.Fprintln(w, "  Terminology")
	fmt.Fprintln(w, "  ───────────")
	if pp.config.Mode == PatchModeDefensive {
		fmt.Fprintln(w, "  🛡️  Defensive Mode — Strengthening security")
		fmt.Fprintln(w, "  • Weakness  - Where check can be bypassed")
		fmt.Fprintln(w, "  • Impact    - What an attacker could achieve")
	} else {
		fmt.Fprintln(w, "  ⚔️  Research Mode — Security analysis")
		fmt.Fprintln(w, "  • Bypass             - Circumvent high-risk checks")
		fmt.Fprintln(w, "  • Exploit suggestion - Circumvent medium/low-risk checks")
	}
	fmt.Fprintln(w)
}

func (pp *PatchPredictor) renderPoint(w io.Writer, index int, point *PatchPoint) {
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %d. %s\n", index, ShortFilePath(point.FilePath))
	fmt.Fprintf(w, "     Method:     %s\n", MethodSignatureShort(&MethodInfo{
		Name:       point.MethodName,
		ReturnType: point.ReturnType,
	}))
	fmt.Fprintf(w, "     Risk:       %.0f%% | Confidence: %.0f%%\n",
		point.RiskScore, point.Confidence*100)
	fmt.Fprintf(w, "     Category:   %s\n", point.CategoryName)

	if point.PatternID != "" {
		fmt.Fprintf(w, "     Pattern:    %s\n", point.PatternDesc)
	}

	// 🆕 БЕЗОПАСНЫЕ ФОРМУЛИРОВКИ
	fmt.Fprintf(w, "     Weakness:   %s\n", pp.weaknessText(point))
	fmt.Fprintf(w, "     Impact:     %s\n", pp.impactText(point))

	if len(point.WhyVulnerable) > 0 {
		fmt.Fprintln(w, "     Why:")
		max := 3
		if len(point.WhyVulnerable) < max {
			max = len(point.WhyVulnerable)
		}
		for _, reason := range point.WhyVulnerable[:max] {
			fmt.Fprintf(w, "       • %s\n", reason)
		}
	}

	if len(point.MatchedParts) > 0 {
		parts := point.MatchedParts
		if len(parts) > 4 {
			parts = parts[:4]
		}
		fmt.Fprintf(w, "     Matched:    %s\n", strings.Join(parts, ", "))
	}
}

func (pp *PatchPredictor) renderAuditPoint(w io.Writer, index int, point *PatchPoint) {
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %d. %s\n", index, ShortFilePath(point.FilePath))
	fmt.Fprintf(w, "     Method:     %s\n", MethodSignatureShort(&MethodInfo{
		Name:       point.MethodName,
		ReturnType: point.ReturnType,
	}))
	fmt.Fprintf(w, "     Score:      %.0f%% | Confidence: %.0f%%\n",
		point.RiskScore, point.Confidence*100)
	if point.VulnSignals == nil || len(point.VulnSignals.Signals) == 0 {
		fmt.Fprintln(w, "     Finding:    Security audit signal")
		return
	}

	signals := point.VulnSignals.Signals
	max := 3
	if len(signals) < max {
		max = len(signals)
	}
	for i := 0; i < max; i++ {
		signal := signals[i]
		if i == 0 {
			fmt.Fprintf(w, "     Finding:    [%s] %s\n", signal.Severity, signal.Description)
		} else {
			fmt.Fprintf(w, "                 [%s] %s\n", signal.Severity, signal.Description)
		}
		if len(signal.Evidence) > 0 {
			ev := signal.Evidence
			if len(ev) > 3 {
				ev = ev[:3]
			}
			fmt.Fprintf(w, "     Evidence:   %s\n", strings.Join(ev, " | "))
		}
		fmt.Fprintf(w, "     Action:     %s\n", auditActionText(signal.Kind))
	}
}

func auditActionText(kind VulnKind) string {
	switch kind {
	// --- Secrets, keys, transport & TLS ---
	case VulnHardcodedSecret, VulnHardcodedCryptoKey:
		return "Rotate exposed credentials/keys; store secrets server-side or in the Android Keystore and restrict keys by package/signing cert."
	case VulnInsecureTransport, VulnCleartextHTTP:
		return "Require HTTPS for all production API/auth traffic and block cleartext in the Network Security Config."
	case VulnDebugBackend:
		return "Remove debug/staging endpoints from release builds or guard them behind non-shippable build variants."
	case VulnEndpointOverride:
		return "Lock trusted backend hosts in release builds and validate server identity before accepting responses."
	case VulnHTTPSCertBypass:
		return "Use platform/default trust validation or certificate pinning; remove permissive TrustManager/HostnameVerifier."
	case VulnCertTransparency:
		return "Enforce certificate transparency/pinning correctly; never disable CT checks in production."
	case VulnWeakJWTHandling:
		return "Reject unsigned/alg=none tokens and validate token signatures and claims server-side."
	case VulnOAuthBypass:
		return "Validate OAuth state/PKCE and exchange authorization codes server-side; never trust client-issued grants."
	case VulnWeakCrypto:
		return "Replace weak/legacy ciphers with vetted primitives (AES-GCM, SHA-256+) and proper key management."
	case VulnWeakRandom:
		return "Use SecureRandom for security-sensitive values; never derive tokens from java.util.Random or Math.random."
	case VulnUnsafeDeserialization:
		return "Avoid deserializing untrusted data; use typed parsers/allowlists instead of raw Serializable/Parcelable input."
	// --- Account, auth & session ---
	case VulnClientAccountTrust:
		return "Make registration/auth/account status server-authoritative; treat local flags as a cache only."
	case VulnAuthCheckBypass:
		return "Move the authorization decision server-side and re-verify it on every privileged request."
	case VulnSessionTokenWeak:
		return "Issue high-entropy session tokens server-side, rotate them, and validate them on each call."
	// --- Monetization & entitlements ---
	case VulnPremiumClientGate, VulnPremiumFeatureGate:
		return "Verify entitlements server-side (validate Play Billing on the backend); treat the local unlock flag as a cache only."
	case VulnLicenseCheckClient, VulnLicenseLocalOnly:
		return "Validate the license / Play Integrity verdict server-side instead of in a client-side callback."
	case VulnPaymentClientSide:
		return "Verify purchase tokens and signatures on the server against the store API before granting value."
	case VulnTrialPeriodCheck:
		return "Track trial/subscription windows server-side; never trust the device clock or a local flag."
	case VulnClientSideCurrency:
		return "Keep the in-game economy server-authoritative and reconcile balances on the backend."
	case VulnAgeVerification:
		return "Perform age/consent gating server-side and store the verified result out of the client's reach."
	// --- Anti-tamper, attestation & environment probes ---
	case VulnTamperCheckBypass:
		return "Attest app integrity with Play Integrity on the server; do not rely on a local tamper verdict."
	case VulnRootDetectionBypass:
		return "Treat root detection as one signal only; enforce sensitive actions with server-side attestation."
	case VulnEmulatorCheckBypass, VulnAntiVMParanoid, VulnDeviceFarmDetect:
		return "Rely on server-side attestation instead of brittle Build.*/emulator probes that also flag real devices."
	case VulnDebugCheckBypass:
		return "Do not gate security on client debug flags; verify sensitive operations server-side."
	case VulnDeviceBinding:
		return "Bind sessions to server-verified device identity rather than spoofable local identifiers."
	case VulnHardwareAttestation:
		return "Verify hardware key-attestation certificates server-side against Google's roots."
	case VulnBiometricBypass, VulnBiometricLocalOnly:
		return "Gate biometric-protected actions on a server-verified crypto object, not a local boolean result."
	case VulnKernelSUDetect, VulnLSPosedDetect, VulnAppCloneDetect, VulnGeoBlock, VulnSpeedHackDetect, VulnFridaArtifacts:
		return "Treat this environment/anti-cheat/instrumentation probe as advisory and enforce the real rule on the server."
	// --- Injection, storage & IPC ---
	case VulnSQLInjection, VulnContentInjection:
		return "Use parameterized queries/selectionArgs; never build SQL or content queries from untrusted input."
	case VulnPathTraversal:
		return "Canonicalize file paths and confine them to the app sandbox; reject ../ traversal segments."
	case VulnMutablePendingIntent:
		return "Set FLAG_IMMUTABLE on PendingIntents and target them at explicit components."
	case VulnPasswordLeak, VulnLogSensitive, VulnSharedPrefsSecret:
		return "Stop logging or storing secrets in plaintext; use EncryptedSharedPreferences/Keystore and strip sensitive logs."
	// --- WebView & dynamic code ---
	case VulnWebViewBridge, VulnWebViewConfig, VulnWebViewFileAccess:
		return "Restrict WebView origins, disable JS/file access for untrusted content, and audit JavaScript bridges."
	case VulnDynamicCodeLoading, VulnObfuscatedDexDecrypt:
		return "Avoid loading code/DEX at runtime; if unavoidable, verify signatures before loading."
	case VulnReflectionWithCrypto, VulnJNIBridgeAbuse:
		return "Audit reflection/JNI bridges that hide crypto or native calls and constrain their inputs."
	case VulnNativeExternalLoad:
		return "Load native libraries only from the app's protected storage and verify their integrity."
	// --- Malware-class behaviour (investigate, not a shippable feature) ---
	case VulnHardcodedC2, VulnWebSocketC2:
		return "Investigate the hardcoded C2/WebSocket endpoint; this is a strong malware indicator, not a shippable feature."
	case VulnRuntimeExec, VulnRootCommandExec:
		return "Investigate runtime command / root execution; confirm it is legitimate before shipping."
	case VulnSMSInterception, VulnTelephonyAbuse:
		return "Investigate SMS/telephony access; premium-SMS or interception behaviour is a malware red flag."
	case VulnOverlayAttack, VulnScreenOverlay, VulnAccessibilityAbuse:
		return "Investigate overlay/accessibility abuse commonly used for tapjacking or credential theft."
	case VulnKeylogger, VulnScreenCapture, VulnClipboardHijack, VulnClipboardReadSensitive, VulnLocationStealth:
		return "Investigate covert capture (keystrokes/screen/clipboard/location); a serious privacy and malware indicator."
	case VulnCryptoMining, VulnAppDropper:
		return "Investigate cryptomining/dropper behaviour and treat it as malware pending manual review."
	default:
		return "Review the code path and enforce server-side authorization, validation, and least privilege."
	}
}

// getPatchLabel returns mode-specific label for patches
// In defensive mode: "Impact" or "Weakness"
// In research mode: "Bypass" or "Exploit suggestion"
func (pp *PatchPredictor) getPatchLabel(isHighRisk bool) string {
	if pp.config.Mode == PatchModeDefensive {
		if isHighRisk {
			return "Impact"
		}
		return "Weakness"
	}
	// research mode
	if isHighRisk {
		return "Bypass"
	}
	return "Exploit suggestion"
}

// 🆕 weaknessText / impactText — безопасные формулировки
func (pp *PatchPredictor) weaknessText(p *PatchPoint) string {
	switch p.Category {
	case PatchCatBilling:
		return "Signature/receipt verification can be bypassed"
	case PatchCatLicense:
		return "License validation can be short-circuited"
	case PatchCatPremium:
		return "Premium entitlement check can be skipped"
	case PatchCatSubscription:
		return "Subscription state check can be bypassed"
	case PatchCatTamper:
		return "Tamper detection can be disabled"
	case PatchCatAds:
		return "Ad-display logic can be neutralized"
	case PatchCatFeatureGate:
		return "Feature flag can be force-enabled"
	case PatchCatInstaller:
		return "Installer-source check can be spoofed"
	case PatchCatServerAuth:
		return "Client-side server-auth decision may be trusted too broadly"
	case PatchCatDRM:
		return "Content protection relies on client-side decision points"
	case PatchCatCurrency:
		return "Currency validation may rely on client-side state"
	default:
		return "Check is structurally bypassable"
	}
}

func (pp *PatchPredictor) impactText(p *PatchPoint) string {
	switch p.Category {
	case PatchCatBilling:
		return "Unauthorized purchases may be accepted as valid"
	case PatchCatLicense:
		return "Unlicensed copies could appear licensed"
	case PatchCatPremium:
		return "Free users could access paid features"
	case PatchCatSubscription:
		return "Expired subscriptions may remain active"
	case PatchCatTamper:
		return "Modified APK may run undetected"
	case PatchCatAds:
		return "Ads may be hidden / disabled"
	case PatchCatFeatureGate:
		return "Locked features may be unlocked"
	case PatchCatInstaller:
		return "App may run from unofficial sources"
	case PatchCatServerAuth:
		return "Auth/session decisions may need stronger server-side enforcement"
	case PatchCatDRM:
		return "Protected content may need stronger server-side entitlement checks"
	case PatchCatCurrency:
		return "Economy state should be treated as server-authoritative"
	default:
		return "Security control may be evaded"
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONVENIENCE
// ═══════════════════════════════════════════════════════════════════════════════

func (pp *PatchPredictor) PredictAndRender(targetDir string) error {
	prediction, err := pp.PredictFromDirectory(targetDir)
	if err != nil {
		return err
	}
	pp.RenderToTerminal(prediction)
	return nil
}

func (pp *PatchPredictor) GetPrediction(targetDir string) (*PatchPrediction, error) {
	return pp.PredictFromDirectory(targetDir)
}

// ═══════════════════════════════════════════════════════════════════════════════
// 🔥 СОЧНЫЕ МЕТОДЫ - управление фильтрами и scoring
// ═══════════════════════════════════════════════════════════════════════════════

// EnableNoiseFilter включает/выключает фильтрацию шума
func (pp *PatchPredictor) EnableNoiseFilter(enable bool) {
	pp.enableNoiseFilter = enable
}

// EnableInterestingScore включает/выключает interesting scoring
func (pp *PatchPredictor) EnableInterestingScore(enable bool) {
	pp.enableInterestingScore = enable
}

// SetNoiseFilter устанавливает кастомный noise filter
func (pp *PatchPredictor) SetNoiseFilter(filter NoiseFilter) {
	pp.noiseFilter = filter
}

// SetInterestingScorer устанавливает кастомный interesting scorer
func (pp *PatchPredictor) SetInterestingScorer(scorer InterestingScorer) {
	pp.interestingScorer = scorer
}

// SetEntryPointDetector устанавливает кастомный entry point detector
func (pp *PatchPredictor) SetEntryPointDetector(detector EntryPointDetector) {
	pp.entryPointDetector = detector
}

// GetNoiseFilterStats возвращает статистику фильтрации
func (pp *PatchPredictor) GetNoiseFilterStats() map[string]interface{} {
	if pp.noiseFilter == nil {
		return nil
	}

	stats := make(map[string]interface{})
	stats["enabled"] = pp.enableNoiseFilter
	stats["filter_type"] = "DefaultNoiseFilter"

	// Если есть статистика в фильтре, добавляем её
	if enhancedFilter, ok := pp.noiseFilter.(*DefaultNoiseFilter); ok {
		stats["total_filtered"] = enhancedFilter.GetTotalFiltered()
		stats["filter_reasons"] = enhancedFilter.GetFilterReasons()
	}

	return stats
}

// GetInterestingScorerStats возвращает статистику interesting scoring
func (pp *PatchPredictor) GetInterestingScorerStats() map[string]interface{} {
	if pp.interestingScorer == nil {
		return nil
	}

	stats := make(map[string]interface{})
	stats["enabled"] = pp.enableInterestingScore
	stats["scorer_type"] = "DefaultInterestingScorer"

	return stats
}

// GetEntryPointDetectorStats возвращает статистику entry point detection
func (pp *PatchPredictor) GetEntryPointDetectorStats() map[string]interface{} {
	if pp.entryPointDetector == nil {
		return nil
	}

	stats := make(map[string]interface{})
	stats["detector_type"] = "DefaultEntryPointDetector"

	return stats
}

// ImportFeedbackMetrics loads production feedback metrics into the predictor's
// PatternTracker before scoring. This makes feedback_learning usable from CLI
// runs instead of only examples/tests.
func (pp *PatchPredictor) ImportFeedbackMetrics(path string) error {
	if pp == nil || pp.patternTracker == nil || strings.TrimSpace(path) == "" {
		return nil
	}
	return pp.patternTracker.LoadFromFile(path)
}

// ExportFeedbackMetrics writes the current pattern metrics after a run.
func (pp *PatchPredictor) ExportFeedbackMetrics(path string) error {
	if pp == nil || pp.patternTracker == nil || strings.TrimSpace(path) == "" {
		return nil
	}
	return pp.patternTracker.SaveToFile(path)
}
