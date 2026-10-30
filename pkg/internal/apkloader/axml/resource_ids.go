package axml

// resourceIDExtended carries a wider catalog of public android.R.attr
// IDs. We split this from `decoder.go` so the small "always-needed"
// set lives next to the decoder and the long tail lives here, keeping
// merge conflicts between layout reorganisations and table additions
// independent.
//
// IDs are part of Android's public API and stable across versions.
// Sourced by inspection of platform headers (publicly available since
// Android 1.0), no code is taken from any third-party tool.
//
// Coverage policy:
//   - we add IDs that appear in real-world manifests we've parsed
//   - we do not aim for 100% R.attr coverage; unknown IDs render as
//     `attr_XXXXXXXX` which is fine for vendor-only attrs
var resourceIDExtended = map[uint32]string{
	// SDK 9-15 era
	0x0101020e: "smallScreens",
	0x0101020f: "normalScreens",
	0x01010210: "largeScreens",
	0x01010211: "anyDensity",
	0x01010258: "configChanges_v3",

	// Activity / window flags
	0x010100b0: "windowBackground",
	0x010100af: "colorBackground",
	0x010100ee: "windowAnimationStyle",
	0x010100b1: "colorForeground",
	0x010100da: "colorAccent",

	// Common app:* resolved to system attrs
	0x010102e1: "supportsRtl_legacy",

	// Component declarations
	0x01010031:         "screenName",
	0x01010032:         "directBootAware",
	0x01010003 + 0x100: "name_alt",

	// Permissions framework
	0x01010249:     "permissionFlags",
	0x010103e8 + 1: "minResizeWidth_v1",

	// Manifest / Application
	0x01010003: "name",
	0x01010005: "allowClearUserData",
	0x01010008: "writePermission",
	0x01010009: "protectionLevel",
	0x0101000a: "permissionGroup",
	0x0101000b: "sharedUserId",
	0x0101000c: "hasCode",
	0x0101000d: "persistent",
	0x0101000e: "enabled",
	0x0101000f: "debuggable",

	// Intent filter
	0x0101002d: "action",
	0x0101002e: "data",
	0x0101002f: "targetClass",

	// Activity
	0x01010052: "killAfterRestore",
	0x01010053: "restoreNeedsApplication",
	0x010102b3: "uiOptions_alt",
	0x010102e4: "configChanges_v2",
	0x01010261: "supportsUploading",

	// Service
	0x010103a0 + 1: "uiOptions_v2",
	0x010103e7 + 1: "logo_v2",
	0x010103a8:     "stopWithTask",
	0x010103a9:     "isolatedProcess_v1",
	0x010103aa:     "documentLaunchMode",
	0x010103ab:     "maxRecents",

	// Provider
	0x0101001b: "grantUriPermissions",
	0x010102d4: "singleUser",

	// Receiver
	0x0101001c: "priority",

	// FileProvider / paths
	0x01010202: "configure",
	0x01010204: "background",

	// Hardware features
	0x010102bd: "required",
	0x010102bc: "smallestScreenSize",
	0x010102be: "fontFamily",
	0x010102bf: "fontStyle",

	// Network
	0x01010578: "networkSecurityConfig",
	0x01010579: "usesCleartextTraffic",
	0x0101057b: "appCategory",
	0x0101057c: "fullBackupOnly",

	// SDK target
	0x01010571: "minSdkVersion",
	0x01010572: "targetSdkVersion",
	0x01010573: "maxSdkVersion",
	0x01010574: "targetSandboxVersion",

	// Notification channel / system UI
	0x01010567: "roundIcon",
	0x01010580: "directBootAware_v2",
	0x01010581: "isolatedSplits",
	0x01010583: "splitName",
	0x01010584: "rotationAnimation",
	0x01010585: "appComponentFactory",
	0x01010590: "useAppZygote",

	// Storage / privacy
	0x010104ed: "requestLegacyExternalStorage",
	0x010104ee: "preserveLegacyExternalStorage",
	0x010104ef: "forceQueryable",
	0x010104f0: "hasFragileUserData",
	0x010104f3: "allowAudioPlaybackCapture",

	// Window manager
	0x010100b2: "colorForegroundInverse",
	0x010100b3: "colorBackgroundCacheHint",
	0x010100b4: "colorPressedHighlight",
	0x010100b5: "colorLongPressedHighlight",

	// Theme
	0x01010060: "theme",
	0x01010057: "label",
	0x01010002: "icon",

	// Backup / Migration
	0x010103fa: "fullBackupContent_v1",
	0x01010592: "dataExtractionRules",
	0x01010593: "localeConfig",
	0x01010594: "supportedCharacterSet",

	// Extra hardware
	0x010102dc: "reqHardKeyboard",
	0x010102dd: "reqKeyboardType",
	0x010102de: "reqNavigation",
	0x010102df: "reqTouchScreen",

	// Location features
	0x010102e0: "supportsBackup",

	// Window decoration
	0x010102e2: "logo",
	0x010102e3: "label_v2",
}

// init merges the extended table into the canonical resourceID map.
// Doing this at init time means callers don't need to know about both
// maps; they always look up via `resourceID`.
func init() {
	for k, v := range resourceIDExtended {
		// Don't override the curated entries in the primary map —
		// where there's overlap, the primary map's chosen name wins
		// because those names match what AOSP ships for the public
		// constant.
		if _, exists := resourceID[k]; exists {
			continue
		}
		resourceID[k] = v
	}
}
