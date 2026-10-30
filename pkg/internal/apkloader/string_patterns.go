package apkloader

import "strings"

// StringPattern represents a semantic pattern in a string constant.
type StringPattern struct {
	Pattern     string
	Category    string
	Confidence  int
	Description string
}

// StringPatternDatabase contains a collection of known string patterns.
type StringPatternDatabase struct {
	Patterns []StringPattern
}

// NewStringPatternDatabase creates a new database with default patterns.
func NewStringPatternDatabase() *StringPatternDatabase {
	db := &StringPatternDatabase{
		Patterns: []StringPattern{
			// Cryptography
			{"AES/CBC/PKCS5Padding", "crypto", 100, "AES encryption with CBC mode"},
			{"AES/ECB/PKCS5Padding", "crypto", 100, "AES encryption with ECB mode (insecure)"},
			{"DES/CBC/PKCS5Padding", "crypto", 95, "DES encryption"},
			{"RSA/ECB/PKCS1Padding", "crypto", 90, "RSA encryption"},
			{"SHA-256", "crypto", 80, "SHA-256 hashing"},
			{"MD5", "crypto", 70, "MD5 hashing (insecure)"},
			{"HmacSHA256", "crypto", 85, "HMAC with SHA-256"},

			// Network
			{"http://", "network", 60, "Unsecured HTTP URL"},
			{"https://", "network", 60, "Secured HTTPS URL"},
			{"content://", "network", 70, "Android Content Provider URI"},
			{"socket://", "network", 80, "Raw socket connection"},

			// Licensing & Anti-Tamper
			{"com.android.vending.BILLING", "license", 90, "Google Play Billing API"},
			{"com.android.vending.CHECK_LICENSE", "license", 90, "Google Play Licensing API"},
			{"com.google.android.c2dm.permission.RECEIVE", "push", 80, "GCM/FCM Push Notifications"},

			// Sensitive APIs
			{"android.intent.action.VIEW", "intent", 50, "Standard View Intent"},
			{"android.intent.action.SEND", "intent", 50, "Standard Send Intent"},
			{"android.permission.INTERNET", "permission", 50, "Internet Permission"},
			{"android.permission.READ_PHONE_STATE", "permission", 80, "Phone State Permission (Sensitive)"},

			// Obfuscation Markers
			{"dex2jar", "obfuscation", 100, "Dex2Jar artifact"},
			{"proguard", "obfuscation", 90, "ProGuard artifact"},
			{"dexguard", "obfuscation", 95, "DexGuard artifact"},
		},
	}
	return db
}

// Match returns the best matching pattern for a given string.
func (db *StringPatternDatabase) Match(s string) *StringPattern {
	var bestMatch *StringPattern
	for _, p := range db.Patterns {
		if strings.Contains(s, p.Pattern) {
			if bestMatch == nil || p.Confidence > bestMatch.Confidence {
				bestMatch = &p
			}
		}
	}
	return bestMatch
}

// GetCategory returns the category of a string if it matches any pattern.
func (db *StringPatternDatabase) GetCategory(s string) string {
	match := db.Match(s)
	if match != nil {
		return match.Category
	}
	return "unknown"
}
