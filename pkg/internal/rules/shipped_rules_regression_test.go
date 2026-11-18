package rules

import (
	"testing"

	"mega-analyzer/pkg/internal/configs"
)

// Regression tests against the SHIPPED rule configs (embedded via
// pkg/internal/configs). Motivated by the 2026-11-04 markor corpus scan: a
// benign markdown editor fired CRITICAL "Crypto Wallet Seed/Key Theft" on the
// substring "seed" inside the Kotlin stdlib RNG error message
// ("Setting seed is not supported.") plus two ubiquitous permissions.
func loadShippedRuleSets(t *testing.T) *Engine {
	t.Helper()
	e := NewEngine()
	for _, name := range []string{"banking_threats.json", "malware_combos.json"} {
		data, ok := configs.File(name)
		if !ok {
			t.Fatalf("shipped rule set %s not found", name)
		}
		if err := e.LoadRulesFromBytes(name, data); err != nil {
			t.Fatalf("load %s: %v", name, err)
		}
	}
	return e
}

func firedRuleIDs(t *testing.T, e *Engine, ctx *ConditionContext) map[string]RuleEvaluationResult {
	t.Helper()
	out := make(map[string]RuleEvaluationResult)
	for _, res := range e.EvaluateAll(ctx) {
		out[res.RuleID] = res
	}
	return out
}

func markorLikeContext() *ConditionContext {
	ctx := &ConditionContext{
		Permissions: []string{
			"android.permission.INTERNET",
			"android.permission.READ_EXTERNAL_STORAGE",
			"android.permission.WRITE_EXTERNAL_STORAGE",
		},
		APICalls: []string{
			"Landroid/webkit/WebView;",
			"evaluateJavascript",
			"addJavascriptInterface",
			"listFiles",
			"SharedPreferences",
			"putString",
			"SecretKeySpec",
			"getBytes",
			"Cipher.getInstance",
			"Base64.decode",
			"CustomTabsIntent",
			"setToolbarColor",
			"resolveActivity",
			"queryIntentActivities",
			"loadUrl",
			"setVisibility",
		},
		Strings: []string{"Setting seed is not supported."},
	}
	ctx.Build()
	return ctx
}

func TestShippedRulesStaySilentOnBenignEditorContext(t *testing.T) {
	e := loadShippedRuleSets(t)
	fired := firedRuleIDs(t, e, markorLikeContext())
	for _, id := range []string{
		"bank_crypto_wallet_steal",       // "seed" substring FP
		"bank_overlay_webview_js_bridge", // no SYSTEM_ALERT_WINDOW
		"bank_target_resolver_probe",     // resolve-only, no enumeration
		"rat_file_manager",               // no upload channel
		"adware_hidden_browser",          // no ad-network identifiers
	} {
		if _, ok := fired[id]; ok {
			t.Errorf("%s fired on benign-editor context; rule regression", id)
		}
	}
}

func TestShippedRulesStillCatchRealThreatContexts(t *testing.T) {
	e := loadShippedRuleSets(t)

	// Wallet stealer: wallet package paths + seed-phrase material.
	wallet := &ConditionContext{
		Permissions: []string{"android.permission.INTERNET", "android.permission.READ_EXTERNAL_STORAGE"},
		APICalls:    []string{"listFiles"},
		Strings: []string{
			"/data/data/io.metamask/files", "com.wallet.crypto.trustapp",
			"mnemonic export", "wallet.dat",
		},
	}
	wallet.Build()
	if _, ok := firedRuleIDs(t, e, wallet)["bank_crypto_wallet_steal"]; !ok {
		t.Error("wallet stealer context did not fire bank_crypto_wallet_steal")
	}

	// Overlay banking trojan: bridge trio + the overlay window permission.
	overlay := &ConditionContext{
		Permissions: []string{"android.permission.INTERNET", "android.permission.SYSTEM_ALERT_WINDOW"},
		APICalls:    []string{"evaluateJavascript", "addJavascriptInterface", "WebView;"},
	}
	overlay.Build()
	if _, ok := firedRuleIDs(t, e, overlay)["bank_overlay_webview_js_bridge"]; !ok {
		t.Error("overlay bridge context did not fire bank_overlay_webview_js_bridge")
	}

	// RAT file manager: enumeration + an actual upload channel.
	rat := &ConditionContext{
		Permissions: []string{
			"android.permission.READ_EXTERNAL_STORAGE",
			"android.permission.WRITE_EXTERNAL_STORAGE",
			"android.permission.INTERNET",
		},
		APICalls: []string{"listFiles", "setDoOutput"},
	}
	rat.Build()
	if _, ok := firedRuleIDs(t, e, rat)["rat_file_manager"]; !ok {
		t.Error("RAT context did not fire rat_file_manager")
	}

	// Banking app probe: intent resolution + installed-app enumeration.
	probe := &ConditionContext{
		Permissions: []string{"android.permission.QUERY_ALL_PACKAGES", "android.permission.INTERNET"},
		APICalls:    []string{"queryIntentActivities", "getInstalledPackages"},
	}
	probe.Build()
	if _, ok := firedRuleIDs(t, e, probe)["bank_target_resolver_probe"]; !ok {
		t.Error("probe context did not fire bank_target_resolver_probe")
	}

	// The demoted custom-tabs signal stays enabled but must not outrank a
	// review hint: severity low, score well below the HIGH tier.
	benignFired := firedRuleIDs(t, e, markorLikeContext())
	if res, ok := benignFired["phishing_custom_tabs"]; ok {
		if res.Severity == "critical" || res.Severity == "high" || res.Severity == "medium" {
			t.Errorf("phishing_custom_tabs still %s/%d; expected demoted review signal", res.Severity, res.Score)
		}
	}
}

func mediaAppContext() *ConditionContext {
	return &ConditionContext{
		Permissions: []string{
			"android.permission.INTERNET",
			"android.permission.RECEIVE_BOOT_COMPLETED",
			"android.permission.WAKE_LOCK",
			"android.permission.SYSTEM_ALERT_WINDOW",
		},
		APICalls: []string{
			"Runtime.getRuntime", "exec", "ClassLoader", "loadClass", "getMethod",
			"WebView", "loadUrl", "CookieManager", "getCookie",
		},
		Strings: []string{"mining"},
	}
}

func TestShippedRulesStaySilentOnMediaAppContext(t *testing.T) {
	e := loadShippedRuleSets(t)
	ctx := mediaAppContext()
	ctx.Build()
	fired := firedRuleIDs(t, e, ctx)
	for _, id := range []string{"rat_remote_shell", "crypto_miner", "dropper_reflection_loading", "adware_aggressive"} {
		if result, ok := fired[id]; ok {
			t.Errorf("%s fired on media plumbing without its distinguishing evidence: %+v", id, result)
		}
	}
	if result, ok := fired["bank_session_cookie_steal"]; !ok || result.FindingKind != "inventory" || result.Score != 0 || result.Severity != "info" || len(result.Limitations) == 0 {
		t.Errorf("ordinary cookie access must remain a qualified inventory observation: %+v", result)
	}
}

func TestShippedMediaRulesRetainDistinguishingEvidence(t *testing.T) {
	e := loadShippedRuleSets(t)
	for _, tc := range []struct {
		id     string
		apis   []string
		values []string
	}{
		{"rat_remote_shell", []string{"Ljava/net/Socket;"}, nil},
		{"crypto_miner", nil, []string{"stratum"}},
		{"dropper_reflection_loading", []string{"DexClassLoader"}, nil},
		{"adware_aggressive", nil, []string{"doubleclick.net"}},
	} {
		t.Run(tc.id, func(t *testing.T) {
			ctx := mediaAppContext()
			ctx.APICalls = append(ctx.APICalls, tc.apis...)
			ctx.Strings = append(ctx.Strings, tc.values...)
			ctx.Build()
			if _, ok := firedRuleIDs(t, e, ctx)[tc.id]; !ok {
				t.Errorf("%s lost its distinguishing positive case", tc.id)
			}
		})
	}
}

// TestShippedRulesStaySilentOnCallerIDAppContext covers the truecaller FP
// cluster (2026-11-05): a caller-ID app legitimately combines notification
// listener, SMS reading, a dialer USSD API, floating overlay windows, and
// SDK DEX loading — none of that is an ATS, USSD hijack, or dropper.
func TestShippedRulesStaySilentOnCallerIDAppContext(t *testing.T) {
	e := loadShippedRuleSets(t)
	ctx := &ConditionContext{
		Permissions: []string{
			"android.permission.INTERNET",
			"android.permission.RECEIVE_SMS",
			"android.permission.CALL_PHONE",
			"android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
			"android.permission.SYSTEM_ALERT_WINDOW",
		},
		APICalls: []string{
			"performAction",
			"sendUssdRequest",
			"DexClassLoader",
			"WebView",
			"evaluateJavascript",
			"addJavascriptInterface",
		},
	}
	ctx.Build()
	fired := firedRuleIDs(t, e, ctx)
	for _, id := range []string{
		"bank_ats_full_chain",            // no BIND_ACCESSIBILITY_SERVICE
		"bank_call_forward_ussd",         // no forwarding MMI codes
		"bank_overlay_webview_js_bridge", // demoted to review signal
		"dropper_dex_loading",            // demoted to review signal
	} {
		if res, ok := fired[id]; ok {
			if res.Severity == "critical" {
				t.Errorf("%s fired CRITICAL on caller-ID context; rule regression", id)
			}
		}
	}

	ats := &ConditionContext{
		Permissions: []string{"android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.INTERNET"},
		APICalls:    []string{"dispatchGesture"},
	}
	ats.Build()
	if _, ok := firedRuleIDs(t, e, ats)["bank_ats_full_chain"]; !ok {
		t.Error("gesture-injecting a11y context did not fire bank_ats_full_chain")
	}
	ussd := &ConditionContext{
		Permissions: []string{"android.permission.CALL_PHONE", "android.permission.INTERNET"},
		APICalls:    []string{"sendUssdRequest"},
		Strings:     []string{"**21*attacker_number#"},
	}
	ussd.Build()
	if _, ok := firedRuleIDs(t, e, ussd)["bank_call_forward_ussd"]; !ok {
		t.Error("forwarding-code context did not fire bank_call_forward_ussd")
	}
}
