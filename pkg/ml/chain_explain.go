package ml

import (
	"fmt"
	"io"
	"strings"
)

// Attack-chain explanations ("po cepochkam") and smarter patch-strategy notes.
//
// This file is additive: it introduces richer, chain-oriented reasoning for the
// terminal patch report plus a guard that stops the patcher from emitting
// destructive "neuter the whole method" diffs for matches that are not real
// client-side gates. Nothing here changes how patches are written to disk; it
// only improves how points are explained and which points are offered an
// automatic bypass patch.

// explainVerbose is toggled by the CLI --explain flag via SetExplainVerbose.
// When false, renderers still print a compact one-line attack chain. When true
// they additionally print the step-by-step chain and the patch-strategy note.
var explainVerbose bool

// SetExplainVerbose wires the CLI --explain flag into the ML renderers.
func SetExplainVerbose(v bool) { explainVerbose = v }

// ExplainVerbose reports whether verbose chain explanations are enabled.
func ExplainVerbose() bool { return explainVerbose }

// chainStep is a single named link in an attack chain.
type chainStep struct {
	Label string
	Text  string
}

// attackChainSteps builds the entry -> gate -> effect -> fix chain for a point.
// The chain is derived from the resolved monetization/security category, so the
// explanation names each concrete link instead of repeating a generic sentence.
func attackChainSteps(p *PatchPoint) []chainStep {
	method := p.MethodName
	if method == "" {
		method = "check()"
	}
	gate := fmt.Sprintf("%s trusts the client-side result of %s", shortClass(p.ClassName), method)

	switch p.Category {
	case PatchCatPremium, PatchCatFeatureGate:
		return []chainStep{
			{"Entry", "a UI or feature action asks whether this is unlocked"},
			{"Gate", gate + " (boolean entitlement getter)"},
			{"Effect", "forcing true unlocks premium/locked features for free"},
			{"Server fix", "verify entitlements server-side (Play Billing verify on backend); treat the local flag as a cache only"},
		}
	case PatchCatSubscription:
		return []chainStep{
			{"Entry", "the app checks whether the subscription is active"},
			{"Gate", gate + " (subscription-state getter)"},
			{"Effect", "an expired subscription can be made to look active"},
			{"Server fix", "confirm subscription status from the store/backend on each privileged use"},
		}
	case PatchCatBilling:
		return []chainStep{
			{"Entry", "a purchase or receipt is validated after checkout"},
			{"Gate", gate + " (receipt/signature comparison)"},
			{"Effect", "a forged or replayed purchase can be accepted"},
			{"Server fix", "verify purchase tokens and signatures on the server against the store API"},
		}
	case PatchCatLicense:
		return []chainStep{
			{"Entry", "a Play LVL / license callback returns allow or deny"},
			{"Gate", gate + " (license verdict consumed locally)"},
			{"Effect", "an unlicensed copy can appear licensed"},
			{"Server fix", "validate the license/Play Integrity verdict server-side, not in the client callback"},
		}
	case PatchCatServerAuth:
		return []chainStep{
			{"Entry", "a request needs an authenticated or authorized session"},
			{"Gate", gate + " (auth/session decision made on device)"},
			{"Effect", "auth or session state can be trusted too broadly"},
			{"Server fix", "make the auth/session decision server-authoritative and re-check every privileged call"},
		}
	case PatchCatCurrency:
		return []chainStep{
			{"Entry", "a coins/gems/economy balance is read or spent"},
			{"Gate", gate + " (economy value trusted from client state)"},
			{"Effect", "balances can be forged or replayed"},
			{"Server fix", "keep the economy server-authoritative and reconcile balances on the backend"},
		}
	case PatchCatTamper:
		return []chainStep{
			{"Entry", "the app verifies its own signature or integrity"},
			{"Gate", gate + " (tamper/integrity self-check)"},
			{"Effect", "a repacked or modified APK can pass undetected"},
			{"Server fix", "attest integrity with Play Integrity server-side; do not rely on the local verdict"},
		}
	case PatchCatInstaller:
		return []chainStep{
			{"Entry", "the app checks the installing package source"},
			{"Gate", gate + " (installer-source comparison)"},
			{"Effect", "sideloaded builds can spoof an official installer"},
			{"Server fix", "treat installer source as a hint only and enforce entitlements server-side"},
		}
	case PatchCatDRM:
		return []chainStep{
			{"Entry", "protected content requests a play or decrypt decision"},
			{"Gate", gate + " (client-side DRM/entitlement decision)"},
			{"Effect", "content protection may be bypassed"},
			{"Server fix", "issue content keys/entitlements from the server after a verified check"},
		}
	default:
		return []chainStep{
			{"Entry", "a caller reaches " + method + "()"},
			{"Gate", "no resolved monetization/auth gate - heuristic/structural match"},
			{"Effect", "control flow can be altered, but no specific check is known to unlock"},
			{"Review", "confirm by hand what this method guards before treating it as a bypass"},
		}
	}
}

// signalChainHint returns a one-line, signal-specific chain hint, or "".
func signalChainHint(p *PatchPoint) string {
	if p.VulnSignals == nil || len(p.VulnSignals.Signals) == 0 {
		return ""
	}
	switch p.VulnSignals.Signals[0].Kind {
	case VulnSQLInjection, VulnContentInjection:
		return "input -> string-built SQL -> query: bind parameters, never concatenate"
	case VulnPathTraversal:
		return "external name -> File path -> I/O: canonicalize and confine to the sandbox"
	case VulnCleartextHTTP, VulnInsecureTransport:
		return "app -> http:// endpoint -> MITM: require HTTPS + Network Security Config"
	case VulnWeakRandom:
		return "seed -> java.util.Random -> token: switch to SecureRandom"
	case VulnMutablePendingIntent:
		return "component -> mutable PendingIntent -> hijack: set FLAG_IMMUTABLE"
	case VulnPasswordLeak, VulnHardcodedSecret:
		return "secret -> plaintext store/log -> exfil: move server-side and rotate"
	case VulnWebViewBridge, VulnWebViewConfig:
		return "untrusted page -> JS bridge -> native call: restrict origins and bridge methods"
	case VulnAntiVMParanoid, VulnEmulatorCheckBypass:
		return "Build.* probes -> emulator verdict -> block: use server-side attestation instead"
	}
	return ""
}

// renderChainExplanation prints the attack chain for a patch point. It always
// prints a compact single-line chain; with --explain it also prints the
// numbered steps and the chosen patch-strategy rationale. Safe for any point.
func renderChainExplanation(w io.Writer, p *PatchPoint) {
	if p == nil {
		return
	}
	steps := attackChainSteps(p)
	if len(steps) == 0 {
		return
	}
	labels := make([]string, 0, len(steps))
	for _, s := range steps {
		labels = append(labels, s.Label)
	}
	fmt.Fprintln(w, "  Chain: "+strings.Join(labels, " -> "))
	if hint := signalChainHint(p); hint != "" {
		fmt.Fprintln(w, "         "+hint)
	}
	if !explainVerbose {
		return
	}
	for i, s := range steps {
		fmt.Fprintf(w, "    %d. %-11s %s", i+1, s.Label+":", s.Text)
		fmt.Fprintln(w)
	}
	if note := patchStrategyRationale(p); note != "" {
		fmt.Fprintln(w, "    -> Strategy: "+note)
	}
}

// patchStrategyRationale explains, in one line, why the chosen bypass strategy
// fits this point - or why no automatic patch is offered.
func patchStrategyRationale(p *PatchPoint) string {
	if shouldSuppressAutoPatch(p) {
		return "diagnostic-only; auto-neutering a non-gate or structural method would break behaviour without bypassing a check"
	}
	rt := strings.ToLower(strings.TrimSpace(p.ReturnType))
	switch {
	case rt == "boolean" || rt == "z":
		return "boolean gate -> force the allow verdict (const/4 v0, 0x1; return v0) with correct register width"
	case rt == "int" || rt == "i" || rt == "integer":
		return "numeric gate -> return the permissive constant the callers treat as success"
	case rt == "void" || rt == "v":
		return "void enforcement -> skip the body via an early return-void at the first executable instruction"
	default:
		return "object/other gate -> return the trusted allow value while preserving method shape"
	}
}

// frameworkOverrideMethods are well-known Android/UI/lifecycle callbacks that
// are almost never real security gates. Forcing an early return-void into them
// corrupts rendering or lifecycle behaviour without bypassing anything - these
// are exactly the "dumb" patches that made the old report noisy.
var frameworkOverrideMethods = map[string]bool{
	"ondraw": true, "draw": true, "dispatchdraw": true, "onmeasure": true,
	"onlayout": true, "onsizechanged": true, "doframe": true, "invalidate": true,
	"requestlayout": true, "dismiss": true, "show": true, "onconfigurationchanged": true,
	"setgroupvisible": true, "setgroupenabled": true, "notifydatasetchanged": true,
	"onanimationupdate": true, "run": true, "onactivityresult": true, "apply": true,
	"removeitem": true, "setprompt": true, "addintentoptions": true,
}

// isFrameworkOverride reports whether name is a framework/UI override that
// should not receive an automatic bypass patch.
func isFrameworkOverride(name string) bool {
	return frameworkOverrideMethods[strings.ToLower(strings.TrimSpace(name))]
}

// shouldSuppressAutoPatch reports whether a patch point is NOT a genuine
// client-side gate and should be shown as diagnostic-only instead of receiving
// a destructive whole-method neuter patch. The rule is deliberately
// conservative: categorized, high-risk monetization/auth gates are still patched.
func shouldSuppressAutoPatch(p *PatchPoint) bool {
	if p == nil {
		return false
	}
	if isFrameworkOverride(p.MethodName) || isSDKOrFrameworkPatchNoise(p) {
		return true
	}
	if strings.TrimSpace(string(p.Category)) == "" && strings.TrimSpace(p.CategoryName) == "" {
		if p.RiskScore < 70 {
			return true
		}
	}
	return false
}

// shortClass returns a compact class name (last two path segments) for chain
// narration. It never panics on empty input.
func shortClass(class string) string {
	c := strings.TrimSpace(class)
	if c == "" {
		return "the app"
	}
	c = strings.TrimPrefix(c, "L")
	c = strings.TrimSuffix(c, ";")
	c = strings.ReplaceAll(c, ".", "/")
	parts := strings.Split(c, "/")
	if len(parts) >= 2 {
		return parts[len(parts)-2] + "/" + parts[len(parts)-1]
	}
	return parts[len(parts)-1]
}
