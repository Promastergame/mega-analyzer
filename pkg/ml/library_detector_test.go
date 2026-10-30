package ml

import "testing"

func TestIsKnownLibrary(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
		name     string
	}{
		// SpongyCastle
		{"smali/org/spongycastle/crypto/signers/DSADigestSigner.smali", true, "SpongyCastle"},
		{"smali\\org\\spongycastle\\crypto\\signers\\DSADigestSigner.smali", true, "SpongyCastle_windows"},

		// jose4j
		{"smali/org/jose4j/jws/JsonWebSignature.smali", true, "jose4j"},

		// Google Billing — это ЦЕЛЕВОЙ КОД для патчинга, НЕ библиотека!
		{"smali/com/android/billingclient/api/BillingClient$Builder.smali", false, "billing_client"},
		{"smali\\com\\android\\billingclient\\api\\BillingClient$Builder.smali", false, "billing_client_windows"},

		// Google Play Licensing — это ЦЕЛЕВОЙ КОД для патчинга, НЕ библиотека!
		{"smali/com/googleplay/licensing/APKExpansionPolicy.smali", false, "play_licensing"},

		// Braze
		{"smali/com/braze/BrazeActivityLifecycleCallbackListener.smali", true, "Braze"},

		// JUnit
		{"smali/org/junit/runners/model/FrameworkMethod.smali", true, "junit"},

		// Chromium
		{"smali/org/chromium/support_lib_boundary/util/BoundaryInterfaceReflectionUtil.smali", true, "chromium"},

		// Microsoft
		{"smali/com/microsoft/xal/browser/BrowserSelector.smali", true, "microsoft"},

		// FMOD
		{"smali/org/fmod/FMOD.smali", true, "fmod"},

		// App code (should NOT be library)
		{"smali/com/example/myapp/MainActivity.smali", false, "app_code"},
		{"smali/com/mycompany/game/GameActivity.smali", false, "app_code2"},

		// Ad-mediation / OMID / attribution noise (plagueinc-driven).
		{"smali/com/mbridge/msdk/video/module/MBridgeNativeEndCardView.smali", true, "mbridge"},
		{"smali/com/iab/omid/library/vungle/publisher/b.smali", true, "omid_vungle"},
		{"smali/com/digitalturbine/ignite/authenticator/decorator/e.smali", true, "digitalturbine"},
		{"smali/com/bytedance/pcc/pcc/qf.smali", true, "bytedance_pcc"},
		{"smali/com/tiktok/appevents/TTPurchaseInfo.smali", true, "tiktok_appevents"},
		{"smali/gatewayprotocol/v1/UniversalRequestKt$PayloadKt$Dsl.smali", true, "gatewayprotocol"},
		{"smali/com/apm/insight/runtime/d.smali", true, "apm_insight"},
		{"smali/com/safedk/android/SafeDK.smali", true, "safedk"},
		{"smali/com/pgl/ssdk/h.smali", true, "pangle_pgl"},
		{"smali/com/bykv/vk/openvk/pcc/pcc/pcc/gm/gm.smali", true, "bykv"},
		// Same verdicts without the smali/ root segment (flat materialized trees).
		{"com/mbridge/msdk/foundation/controller/e.smali", true, "mbridge_flat"},
		{"gatewayprotocol/v1/CachedAssetsConfigurationKt$Dsl.smali", true, "gatewayprotocol_flat"},

		// Kids-safe ad SDKs (subwaysurf-driven).
		{"smali/tv/superawesome/sdk/AdManager.smali", true, "superawesome"},
		{"tv/superawesome/sdk/AdManager.smali", true, "superawesome_flat"},
		{"smali/com/kpadplayer/sdk/KPAdPlayer.smali", true, "kpadplayer"},
		{"com/kpadplayer/sdk/KPAdPlayer.smali", true, "kpadplayer_flat"},
		{"smali/com/kidoz/sdk/KidozSDK.smali", true, "kidoz"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsKnownLibrary(tt.path)
			if result != tt.expected {
				t.Errorf("IsKnownLibrary(%q) = %v, want %v", tt.path, result, tt.expected)
			}
		})
	}
}

func TestIsLibraryPath_AdNoise(t *testing.T) {
	// Flat (materialized-tree) paths: prefix match, no smali/ root segment.
	for _, p := range []string{
		"com/mbridge/msdk/video/module/MBridgeNativeEndCardView.smali",
		"com/iab/omid/library/ironsrc/publisher/b.smali",
		"com/digitalturbine/ignite/authenticator/decorator/e.smali",
		"com/bytedance/pcc/pcc/qf.smali",
		"com/tiktok/appevents/TTPurchaseInfo.smali",
		"gatewayprotocol/v1/UniversalRequestKt$PayloadKt$Dsl.smali",
		"com/apm/insight/runtime/d.smali",
		"com/safedk/android/SafeDK.smali",
		"com/pgl/ssdk/h.smali",
		"com/bykv/vk/openvk/pcc/pcc/pcc/gm/gm.smali",
		"com/pangle/overseas/example.smali",
		"tv/superawesome/sdk/AdManager.smali",
		"com/kpadplayer/sdk/KPAdPlayer.smali",
		"com/kidoz/sdk/KidozSDK.smali",
	} {
		if !IsLibraryPath(p) {
			t.Errorf("IsLibraryPath(%q) = false, want true", p)
		}
	}
	// App code must stay visible to the patcher.
	for _, p := range []string{
		"com/miniclip/plagueinc/PurchaseManager.smali",
		"com/miniclip/plagueinc/Security.smali",
	} {
		if IsLibraryPath(p) {
			t.Errorf("IsLibraryPath(%q) = true, want false (app code)", p)
		}
	}
}

func TestLibraryName(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"smali/org/spongycastle/crypto/signers/DSADigestSigner.smali", "SpongyCastle"},
		{"smali/org/jose4j/jws/JsonWebSignature.smali", "jose4j"},
		{"smali/com/braze/Braze.smali", "Braze"},
		{"smali/tv/superawesome/sdk/AdManager.smali", "SuperAwesome"},
		{"smali/com/kpadplayer/sdk/KPAdPlayer.smali", "KPAdPlayer"},
		{"smali/com/kidoz/sdk/KidozSDK.smali", "Kidoz"},
		{"smali/org/junit/Test.smali", "JUnit"},
		// Google Billing is NOT a library — should return empty
		{"smali/com/android/billingclient/api/BillingClient.smali", ""},
		{"smali/com/googleplay/licensing/Policy.smali", ""},
		// App code
		{"smali/com/example/myapp/MainActivity.smali", ""},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := LibraryName(tt.path)
			if result != tt.expected {
				t.Errorf("LibraryName(%q) = %q, want %q", tt.path, result, tt.expected)
			}
		})
	}
}
