package ml

// ═══════════════════════════════════════════════════════════════════════════════
// SECURITY KEYWORDS — unified security-related keywords across pkg/ml
// ═══════════════════════════════════════════════════════════════════════════════
// This file contains unified security-related keyword lists used across multiple
// components (noise_filter, decoy_detector, semantic_gate, etc.) to eliminate
// duplication and ensure consistency.

// SecurityWhitelistKeywords contains keywords that identify security-related methods
// that should NEVER be filtered, even if they look like "generic getter/setter".
var SecurityWhitelistKeywords = []string{
	// License / Registration
	"license", "licensed", "registration", "registered", "activated",
	// Premium / Pro / VIP
	"premium", "pro", "proversion", "fullversion", "vip", "gold", "platinum",
	"paid", "membership",
	// Purchase / Billing
	"purchase", "purchased", "billing", "bought", "owned",
	// Subscription
	"subscri", "subscribe", "subscription",
	// Ads
	"adfree", "adremov", "noads", "showad", "displayad", "loadad",
	"interstitial", "rewarded", "banner",
	// Root / Emulator / Debug / Tamper
	"root", "rooted", "superuser", "magisk",
	"emulator", "emulat", "simulator",
	"debug", "debugger", "debuggable",
	"tamper", "tampered", "integrity", "modified",
	// Hook / Frida / Xposed
	"hook", "hooked", "frida", "xposed", "lsposed",
	// Signature / Certificate
	"signature", "certificate", "signing",
	// Trial / Expiry
	"trial", "expir", "expired",
	// Feature / Unlock
	"unlock", "unlocked", "feature", "entitlement",
	// Currency / Coins / Economy
	"coins", "gems", "diamonds", "currency", "credits",
	"stars", "energy", "lives", "points", "balance",
	"wallet", "inventory",
	// Server / Auth / Token
	"token", "auth", "session", "jwt",
	// DRM
	"drm", "widevine", "playready",
	// SafetyNet / Play Integrity
	"safetynet", "attestation", "playintegrity",
	// Installer / Store
	"installer", "playstore", "sideload",
	// Anti-cheat
	"cheat", "anticheat", "hack",
	// Encryption / Save
	"encrypt", "decrypt", "cipher",
	// Verify / Validate / Check (combined with security context)
	"verifylicense", "validatepurchase", "checksubscription",
	"verifysignature", "checkintegrity", "validatetoken",
	// Security / Anti-cheat
	"security", "secure", "verify", "valid", "check",
	"anticheat", "anti_cheat", "protection", "guard",
	// DRM / License servers
	"licensing", "activation", "validation",
	// Cryptography
	"crypto", "hash",
	// Network security
	"ssl", "tls", "pinning",
	// Device integrity
	"device", "fingerprint", "attest",
}

// SecurityClassHints contains path/class patterns that indicate security-related code.
var SecurityClassHints = []string{
	"/billing", "/license", "/premium", "/security", "/integrity",
	"/purchase", "/subscription", "/auth", "/drm", "/anti",
}

// SecurityClassKeywords contains class-level keywords that indicate security-related code.
// If a class contains these words, all methods inside get immunity from generic filtering.
var SecurityClassKeywords = []string{
	"license", "billing", "purchase", "premium", "subscription",
	"security", "checker", "validator", "verifier", "protector",
	"guard", "shield", "integrity", "tamper", "root",
	"emulator", "hook", "frida", "xposed", "trial",
	"feature", "unlock", "currency", "wallet", "economy",
	"auth", "token", "drm", "safetynet", "anticheat",
	"ads", "admanager", "adcontroller",
}

// SecurityInvokes contains API call patterns that indicate security-related operations.
var SecurityInvokes = []string{
	"billingclient", "integritymanager", "safetynet", "playintegrity",
	"sharedpreferences", "getboolean", "purchase", "license",
	"acknowledgepurchase", "querypurchases", "android_id",
	"settings$secure", "firebase/remoteconfig",
}

// SecurityNameKeywords contains name patterns that indicate security-related methods.
var SecurityNameKeywords = []string{
	// License / Registration
	"license", "licensed", "registration",
	// Premium / Pro / VIP
	"premium", "pro", "vip", "paid", "membership",
	// Purchase / Billing
	"purchase", "billing", "bought", "owned",
	// Subscription
	"subscri",
	// Root / Emulator / Debug / Tamper
	"root", "emulat", "debug", "tamper",
	// Integrity / Signature / Certificate
	"integrity", "signature", "cert",
	// Hook / Frida / Xposed / Magisk
	"hook", "frida", "xposed", "magisk",
	// Trial / Expiry
	"trial", "expir",
	// Feature / Unlock / Entitlement
	"unlock", "feature", "entitle",
	// Currency / Economy (games)
	"coins", "gems", "currency", "gold", "credit",
	"lives", "energy", "diamond", "stars", "points",
	"balance", "wallet", "inventory",
	// Verify / Validate / Authenticate
	"verify", "valid", "authentic", "genuine", "auth", "check", "secure",
	// Ads
	"adfree", "adremov", "noads", "showad",
	// SafetyNet / Play Integrity
	"safetynet", "attestation", "playintegrity",
	// Installer / Store
	"installer", "playstore", "sideload",
	// Game-specific
	"health", "damage", "cooldown", "stamina", "mana",
	"godmode", "invincib", "cheat", "anticheat",
	"level", "stage", "realm", "marketplace",
	// Modern SDKs
	"revenuecat", "adapty", "qonversion",
	"remoteconfig", "featureflag",
	// Cryptography
	"encrypt", "decrypt", "cipher", "crypto", "hash",
	// DRM / License servers
	"drm", "activation", "validation", "guard", "protect",
	// Server / Auth / Token / DRM
	"token", "session", "jwt",
	"widevine",
	// Network / Rate limit / Quota
	"ratelimit", "quota", "offline",
	// Screen / Overlay
	"screenshot", "screenrecord", "overlay",
	// Update / Version
	"forceupdate", "killswitch",
}

// UILifecycleHints contains UI lifecycle method patterns (used for penalty detection).
var UILifecycleHints = []string{
	"oncreate", "onstart", "onresume", "onpause", "onlayout", "ondraw", "ontouch", "onclick", "show", "hide",
}

// UIPatternsForPenalty contains UI-related patterns that trigger name penalties.
var UIPatternsForPenalty = []string{
	"propagate", "shouldencode",
}

// DataClassMethodNames contains standard data class method names that are NOT security gates.
var DataClassMethodNames = []string{
	"equals", "hashcode", "tostring", "compareto", "clone",
}

// GetterPrefixes contains common getter prefixes that might indicate accessors rather than security gates.
var GetterPrefixes = []string{
	"get", "is", "has",
}

// NonSecurityGetterPatterns contains getter patterns that are clearly NOT security-related.
var NonSecurityGetterPatterns = []string{
	"enabled", "valid", "initialized", "ready",
	"empty", "null", "available", "supported", "compatible",
}

// UIDiffPatterns contains UI diff/payload method patterns (RecyclerView, DiffUtil).
var UIDiffPatterns = []string{
	"arecontentsthesame", "areitemsthesame", "diff",
	"payload", "viewholder", "adapter",
}

// IntrinsicPatterns contains Android Drawable intrinsic getter patterns.
var IntrinsicPatterns = []string{
	"intrinsic", "getintrinsic",
}
