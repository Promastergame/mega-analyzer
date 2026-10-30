package ml

// AdvancedGatePatterns — device binding, remote config gates, screen capture abuse.
var AdvancedGatePatterns = []VulnerablePattern{
	{
		ID:          "DEVICE_BINDING_ANDROID_ID",
		Category:    PatchCatServerAuth,
		Description: "Device binding via ANDROID_ID / Settings.Secure",
		MethodNames: []string{
			"getdeviceid", "getandroidid", "getuniqueid", "binddevice",
			"validatedevice", "checkdevice",
		},
		ClassPatterns: []string{
			"license", "auth", "security", "device", "binding",
		},
		RequiredCalls: []string{
			"settings$secure;->getstring",
			"android_id",
			"telephonymanager;->getdeviceid",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnTrue,
		Weight:        1.5,
		MinMatchScore: 14,
	},
	{
		ID:          "REMOTE_CONFIG_PREMIUM_GATE",
		Category:    PatchCatFeatureGate,
		Description: "Firebase Remote Config premium/feature flag gate",
		MethodNames: []string{
			"isfeatureenabled", "getfeatureflag", "checkremoteconfig",
			"ispremiumenabled", "isproenabled",
		},
		ClassPatterns: []string{
			"remoteconfig", "featureflag", "firebase",
		},
		RequiredCalls: []string{
			"firebase/remoteconfig", "getboolean",
			"remoteconfig;->get",
		},
		StringPatterns: []string{
			"premium", "pro_enabled", "feature_", "paywall",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnTrue,
		Weight:        1.4,
		MinMatchScore: 13,
	},
	{
		ID:          "SCREEN_CAPTURE_MEDIAPROJECTION",
		Category:    PatchCatTamper,
		Description: "MediaProjection / screen capture gate (banking trojan indicator)",
		MethodNames: []string{
			"startscreencapture", "capturescreen", "recordscreen",
			"requestscreencapture", "onscreencaptured",
		},
		ClassPatterns: []string{
			"mediaprojection", "screencapture", "overlay", "accessibility",
		},
		RequiredCalls: []string{
			"mediaprojectionmanager",
			"createscreencaptureintent",
			"mediaprojection;->createvirtualdisplay",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnFalse,
		Weight:        1.6,
		MinMatchScore: 15,
	},
	{
		ID:          "PLAY_INTEGRITY_STANDARD",
		Category:    PatchCatIntegrity,
		Description: "Play Integrity Standard API token request gate",
		MethodNames: []string{
			"requestintegritytoken", "checkstandardintegrity",
			"getstandardintegritytoken",
		},
		ClassPatterns: []string{
			"play/core/integrity", "standardintegrity",
		},
		RequiredCalls: []string{
			"standardintegritymanager",
			"requestintegritytoken",
			"integritytokenresponse",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        1.55,
		MinMatchScore: 14,
	},
}
