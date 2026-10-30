package ml

// ═══════════════════════════════════════════════════════════════════════════════
// EXTRA VULNERABLE PATTERNS — современные защиты, которых не хватало ядру
// ═══════════════════════════════════════════════════════════════════════════════
//
// Регистрируются через GetAllPatterns (append ExtraVulnerablePatterns...). НЕ
// добавляются в VulnerablePatterns напрямую, чтобы не ломать TestPatternCounts
// (там жёсткая проверка len(VulnerablePatterns) == 74). GetAllPatterns проверяется
// через `>=`, поэтому расширение безопасно.
//
// Покрытие: Play Integrity API, HMAC-подпись запросов, RootBeer, OkHttp
// CertificatePinner, JWT-верификация, Firebase App Check.

var ExtraVulnerablePatterns = []VulnerablePattern{
	{
		ID:          "PLAY_INTEGRITY_VERDICT",
		Category:    PatchCatIntegrity,
		Description: "Google Play Integrity API verdict check (device/app/account integrity)",
		MethodNames: []string{
			"requestintegritytoken", "showdialog", "onintegrityresult",
			"isdeviceintegrityvalid", "checkintegrity", "verifyintegrity",
		},
		ClassPatterns: []string{
			"play/core/integrity", "integritymanager", "integritytokenresponse",
			"standardintegrity",
		},
		RequiredCalls: []string{
			"integritymanager;->requestintegritytoken",
			"integritytokenresponse;->token",
			"standardintegritytoken",
		},
		StringPatterns: []string{
			"meets_device_integrity", "meets_basic_integrity",
			"meets_strong_integrity", "play_recognized",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnTrue,
		Weight:        1.7,
		MinMatchScore: 12,
	},
	{
		ID:          "HMAC_REQUEST_SIGNATURE",
		Category:    PatchCatServerAuth,
		Description: "HMAC request signing / signature verification for API tamper protection",
		MethodNames: []string{
			"verifysignature", "checkhmac", "validatesignature",
			"issignaturevalid", "computehmac", "signrequest",
		},
		ClassPatterns: []string{
			"hmac", "signaturevalidator", "requestsigner", "crypto/mac",
		},
		RequiredCalls: []string{
			"javax/crypto/mac;->getinstance", "javax/crypto/mac;->dofinal",
			"hmacsha256", "messagedigest;->isequal",
		},
		StringPatterns: []string{
			"hmacsha256", "hmacsha1", "x-signature", "x-api-signature",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnTrue,
		Weight:        1.5,
		MinMatchScore: 12,
	},
	{
		ID:          "ROOTBEER_ROOT_CHECK",
		Category:    PatchCatRootDetect,
		Description: "RootBeer library root detection (isRooted / checkRootMethods)",
		MethodNames: []string{
			"isrooted", "isrootedwithoutbusyboxcheck", "checkrootmethods",
			"detectrootmanagementapps", "checkforbinary", "checkforsubinary",
		},
		ClassPatterns: []string{
			"scottyab/rootbeer", "rootbeer", "rootbeernative",
		},
		RequiredCalls: []string{
			"rootbeer;->isrooted", "rootbeernative;->checkforroot",
		},
		StringPatterns: []string{
			"su", "busybox", "magisk", "superuser.apk", "/system/xbin/su",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnFalse,
		Weight:        1.6,
		MinMatchScore: 10,
	},
	{
		ID:          "OKHTTP_CERT_PINNER",
		Category:    PatchCatSSLPinning,
		Description: "OkHttp CertificatePinner.check() SSL pinning enforcement",
		MethodNames: []string{
			"check", "checkservertrusted", "findmatchingpins", "verify",
		},
		ClassPatterns: []string{
			"okhttp3/certificatepinner", "certificatepinner", "okhttp3/internal/tls",
		},
		RequiredCalls: []string{
			"certificatepinner;->check", "certificatepinner$builder;->add",
		},
		StringPatterns: []string{
			"sha256/", "certificate pinning failure", "pin-sha256",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        1.6,
		MinMatchScore: 10,
	},
	{
		ID:          "JWT_SIGNATURE_VERIFY",
		Category:    PatchCatServerAuth,
		Description: "JWT signature verification bypass (jjwt / java-jwt / nimbus)",
		MethodNames: []string{
			"verify", "parseclaimsjws", "verifysignature", "isvalidtoken",
			"validatetoken", "requiresignature",
		},
		ClassPatterns: []string{
			"io/jsonwebtoken", "auth0/jwt", "nimbusds/jwt", "jwtverifier",
		},
		RequiredCalls: []string{
			"jwtparser;->parseclaimsjws", "jwtverifier;->verify",
			"signaturealgorithm", "macverifier;->verify",
		},
		StringPatterns: []string{
			"jwt", "signature verification failed", "invalid token", "alg",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnTrue,
		Weight:        1.5,
		MinMatchScore: 11,
	},
	{
		ID:          "FIREBASE_APP_CHECK",
		Category:    PatchCatIntegrity,
		Description: "Firebase App Check token attestation (Play Integrity/SafetyNet provider)",
		MethodNames: []string{
			"getapptoken", "gettoken", "getlimiteduseapptoken",
			"onappcheckresult", "installapptcheckprovider",
		},
		ClassPatterns: []string{
			"firebase/appcheck", "appchecktoken", "appcheckprovider",
			"playintegrityappcheck",
		},
		RequiredCalls: []string{
			"firebaseappcheck;->gettoken", "appchecktoken;->gettoken",
		},
		StringPatterns: []string{
			"appcheck", "attestation", "x-firebase-appcheck",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnTrue,
		Weight:        1.6,
		MinMatchScore: 11,
	},
}
