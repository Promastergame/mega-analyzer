package configs

import (
	"testing"

	"mega-analyzer/pkg/internal/rules"
)

// This deliberately has no trusted app/SDK namespace. The same API primitives
// can occur in a RAT, a screen-sharing tool, an installer or accessibility UI.
// Their presence should survive as evidence, without establishing purpose.
func TestAPIPrimitivesDoNotEstablishMaliciousPurpose(t *testing.T) {
	e := loadShippedEngine(t)
	ctx := &rules.ConditionContext{
		Permissions: []string{
			"android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.INTERNET",
			"android.permission.SYSTEM_ALERT_WINDOW", "android.permission.DISABLE_KEYGUARD",
			"android.permission.WAKE_LOCK", "android.permission.RECEIVE_BOOT_COMPLETED",
			"android.permission.RECEIVE_SMS", "android.permission.QUERY_ALL_PACKAGES",
			"android.permission.CALL_PHONE",
		},
		APICalls: []string{
			"AccessibilityNodeInfo", "performAction", "findAccessibilityNodeInfosByViewId",
			"dispatchGesture", "GestureDescription", "performGlobalAction", "AlarmManager",
			"AccessibilityManager", "isEnabled", "getEnabledAccessibilityServiceList",
			"getInstalledPackages", "getPackageInfo", "resolveActivity", "queryIntentActivities",
			"WebView", "evaluateJavascript", "addJavascriptInterface",
			"ClipboardManager", "addPrimaryClipChangedListener", "MediaProjection", "createVirtualDisplay",
			"FirebaseMessagingService", "onMessageReceived", "RemoteMessage", "WebSocket",
			"PackageInstaller", "createSession", "sendUssdRequest", "VpnService",
		},
		Classes: []string{"com/obfuscated/UnknownCode"},
	}
	results := make(map[string]rules.RuleEvaluationResult)
	for _, result := range e.EvaluateAll(ctx) {
		results[result.RuleID] = result
	}
	for _, id := range []string{
		"bank_overlay_a11y_modern", "bank_overlay_webview_js_bridge", "bank_cred_clipboard_steal",
		"bank_ats_gesture_injection", "bank_ats_full_chain", "bank_ats_sleep_fraud",
		"bank_target_package_scan", "bank_target_resolver_probe", "bank_c2_firebase",
		"bank_c2_websocket_realtime", "bank_antifraud_accessibility_check_bypass", "bank_combo_sharkbot_ats",
		"banking_auto_transfer", "spyware_screen_recording", "spyware_clipboard_monitor",
		"dropper_package_installer_abuse", "ussd_abuse", "c2_websocket", "c2_firebase_abuse", "network_proxy_mitm",
	} {
		t.Run(id, func(t *testing.T) {
			result, ok := results[id]
			if !ok || len(result.Evidence) == 0 {
				t.Fatalf("API evidence must remain visible: %+v", result)
			}
			if result.FindingKind != "inventory" || result.Score != 0 || result.Severity != "info" {
				t.Fatalf("API presence established malicious purpose: %+v", result)
			}
			if len(result.Limitations) == 0 || len(result.NextChecks) == 0 {
				t.Fatalf("observation lacks its verification conditions: %+v", result)
			}
		})
	}
}

func TestCapabilityCorrectionsKeepDistinguishingThreatEvidence(t *testing.T) {
	e := loadShippedEngine(t)
	for _, tc := range []struct {
		id  string
		ctx *rules.ConditionContext
	}{
		{"bank_crypto_wallet_steal", &rules.ConditionContext{
			Permissions: []string{"android.permission.INTERNET", "android.permission.READ_EXTERNAL_STORAGE"},
			APICalls:    []string{"listFiles"},
			Strings:     []string{"/data/data/io.metamask/files", "com.wallet.crypto.trustapp", "mnemonic export", "wallet.dat"},
		}},
		{"rat_remote_shell", &rules.ConditionContext{
			Permissions: []string{"android.permission.INTERNET", "android.permission.RECEIVE_BOOT_COMPLETED"},
			APICalls:    []string{"Runtime.getRuntime", "exec", "Ljava/net/Socket;"},
		}},
	} {
		t.Run(tc.id, func(t *testing.T) {
			for _, result := range e.EvaluateAll(tc.ctx) {
				if result.RuleID == tc.id {
					if result.Score == 0 || result.FindingKind == "inventory" {
						t.Fatalf("distinguishing threat evidence was downgraded: %+v", result)
					}
					return
				}
			}
			t.Fatal("distinguishing threat evidence was lost")
		})
	}
}
