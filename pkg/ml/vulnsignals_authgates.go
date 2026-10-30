package ml

import (
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// Phase 7 — Client-side trust boundary detectors
//
// Это РЕАЛЬНЫЕ мобильные уязвимости: проверки авторизации, возраста, подписки,
// лицензии, триала и оплаты, которые приложение делает ТОЛЬКО локально — без
// серверной верификации. Реверсер патчит один boolean/return и обходит защиту.
// Никаких SQLi/XSS — база на сервере, тут только client-side trust.
// ═══════════════════════════════════════════════════════════════════════════════

// hasServerVerificationCall — есть ли в методе сетевой/крипто вызов, который
// мог бы быть серверной верификацией. Если есть — сигнал ослабляется.
func hasServerVerificationCall(mi *MethodInfo) bool {
	for _, c := range mi.Calls {
		full := strings.ToLower(c.FullCall)
		if containsAny(full, []string{
			"okhttp", "retrofit", "httpurlconnection", "volley", "firebase/auth",
			"/verify", "/validate", "/check", "signature;->verify",
			"mac;->dofinal", "messagedigest;->digest", "httpsurlconnection",
			"sslcontext", "trustmanager", "playintegrity", "safetynet",
		}) {
			return true
		}
	}
	// The network call may live in a helper in the same app-owned flow. Keep
	// endpoint constants as evidence of a server-backed gate, rather than
	// treating a method as local-only merely because URL construction is split
	// across helpers.
	for _, value := range mi.StringConsts {
		l := strings.ToLower(value)
		if strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://") ||
			strings.Contains(l, "/verify") || strings.Contains(l, "/validate") ||
			strings.Contains(l, "/subscription/") || strings.Contains(l, "/age/") {
			return true
		}
	}
	return false
}

// hasLocalStateWrite — метод пишет флаг состояния в SharedPreferences / поле.
func hasLocalStateWrite(mi *MethodInfo, evidence *[]string) bool {
	found := false
	for _, c := range mi.Calls {
		full := strings.ToLower(c.FullCall)
		if containsAny(full, []string{
			"sharedpreferences$editor;->putboolean",
			"sharedpreferences$editor;->putstring",
			"sharedpreferences$editor;->putint",
			"sharedpreferences$editor;->putlong",
			"preferences$editor;->putboolean",
			"preferences$editor;->putstring",
		}) {
			found = true
			*evidence = append(*evidence, c.FullCall)
		}
	}
	return found
}

// detectAuthCheckBypass: метод isLoggedIn/isAuthenticated/validateSession
// возвращает boolean, читает локальный флаг и НЕ делает серверного вызова.
func detectAuthCheckBypass(mi *MethodInfo) *VulnSignal {
	ctx := getMethodMetaContext(mi)
	if !containsAny(ctx, []string{
		"isloggedin", "is_logged_in", "isauthenticated", "is_authenticated",
		"validatesession", "validate_session", "checksession", "check_session",
		"hassession", "has_session", "isauthorized", "is_authorized",
		"checkauth", "check_auth", "verifylogin", "verify_login", "istokenvalid",
	}) {
		return nil
	}
	if !mi.ReturnsBoolean {
		return nil
	}

	evidence := []string{}
	readsLocal := false
	for _, c := range mi.Calls {
		full := strings.ToLower(c.FullCall)
		if containsAny(full, []string{
			"sharedpreferences;->getboolean", "sharedpreferences;->getstring",
			"preferences;->getboolean", "preferences;->getstring",
			"gettoken", "getsession", "getaccesstoken",
		}) {
			readsLocal = true
			evidence = append(evidence, c.FullCall)
		}
	}
	for _, s := range mi.StringConsts {
		l := strings.ToLower(s)
		if containsAny(l, []string{
			"is_logged_in", "logged_in", "access_token", "session_token",
			"auth_token", "is_authenticated", "login_state",
		}) {
			readsLocal = true
			evidence = append(evidence, s)
		}
	}

	if !readsLocal {
		return nil
	}
	if hasServerVerificationCall(mi) {
		return nil // сервер проверяет — не bypass
	}

	return &VulnSignal{
		Kind:        VulnAuthCheckBypass,
		Severity:    VulnSeverityHigh,
		Confidence:  0.80,
		Description: "Auth/session check returns boolean from local state only (no server verification) — patchable to always-true",
		Evidence:    capEvidence(evidence, 6),
	}
}

// detectAgeVerification: isAgeVerified/isAdult/checkAge — возрастной гейт
// на локальных данных (дата рождения из prefs, boolean флаг).
func detectAgeVerification(mi *MethodInfo) *VulnSignal {
	ctx := getMethodMetaContext(mi)
	if !containsAny(ctx, []string{
		"isageverified", "is_age_verified", "isadult", "is_adult",
		"checkage", "check_age", "verifyage", "verify_age", "agegate",
		"age_gate", "isoverage", "is_over_age", "is18", "is21", "agelock",
		"coppa", "isminor", "is_minor", "dateofbirth", "date_of_birth",
	}) {
		return nil
	}
	if !mi.ReturnsBoolean && !mi.ReturnsInt {
		return nil
	}

	evidence := []string{}
	local := false
	for _, c := range mi.Calls {
		full := strings.ToLower(c.FullCall)
		if containsAny(full, []string{
			"sharedpreferences;->getint", "sharedpreferences;->getboolean",
			"sharedpreferences;->getlong", "sharedpreferences;->getstring",
			"preferences;->getint", "preferences;->getboolean",
			"system;->currenttimemillis", "calendar;->getinstance",
			"date;-><init>", "simpledateformat",
		}) {
			local = true
			evidence = append(evidence, c.FullCall)
		}
	}
	for _, s := range mi.StringConsts {
		l := strings.ToLower(s)
		if containsAny(l, []string{
			"age_verified", "is_adult", "date_of_birth", "birth_year",
			"user_age", "age_gate_passed", "coppa_verified", "min_age",
		}) {
			local = true
			evidence = append(evidence, s)
		}
	}

	if !local {
		return nil
	}
	if hasServerVerificationCall(mi) {
		return nil
	}

	return &VulnSignal{
		Kind:        VulnAgeVerification,
		Severity:    VulnSeverityMedium,
		Confidence:  0.74,
		Description: "Age verification gate uses local data (prefs/clock) without server check — bypassable by patching return or stored value",
		Evidence:    capEvidence(evidence, 6),
	}
}

// detectPremiumFeatureGate: isPremium/isPro/isUnlocked/hasFeature — boolean
// гейт премиум-фичи, читающий локальный флаг.
func detectPremiumFeatureGate(mi *MethodInfo) *VulnSignal {
	ctx := getMethodMetaContext(mi)
	if !containsAny(ctx, []string{
		"ispremium", "is_premium", "ispro", "is_pro", "isunlocked", "is_unlocked",
		"haspremium", "has_premium", "isvip", "is_vip", "issubscribed",
		"is_subscribed", "hassubscription", "isplus", "is_plus", "isgold",
		"hasfeature", "has_feature", "isfeatureenabled", "isfeatureunlocked",
		"isupgraded", "is_upgraded", "isfullversion", "is_full_version",
	}) {
		return nil
	}
	if !mi.ReturnsBoolean {
		return nil
	}

	evidence := []string{}
	local := false
	for _, c := range mi.Calls {
		full := strings.ToLower(c.FullCall)
		if containsAny(full, []string{
			"sharedpreferences;->getboolean", "preferences;->getboolean",
			"sharedpreferences;->getstring", "getpremium", "getsubscription",
		}) {
			local = true
			evidence = append(evidence, c.FullCall)
		}
	}
	for _, s := range mi.StringConsts {
		l := strings.ToLower(s)
		if containsAny(l, []string{
			"is_premium", "premium", "pro_version", "is_pro", "unlocked",
			"subscription_active", "is_vip", "premium_user", "feature_unlocked",
		}) {
			local = true
			evidence = append(evidence, s)
		}
	}

	if !local {
		return nil
	}
	// Billing client — это легитимная проверка через Play, не считаем bypass-ом
	for _, c := range mi.Calls {
		full := strings.ToLower(c.FullCall)
		if containsAny(full, []string{
			"billingclient", "purchasesupdatedlistener", "querypurchases",
			"skuDetails", "inappbilling", "iabhelper",
		}) {
			return nil
		}
	}

	return &VulnSignal{
		Kind:        VulnPremiumFeatureGate,
		Severity:    VulnSeverityHigh,
		Confidence:  0.78,
		Description: "Premium/pro feature gate reads local flag without billing/server verification — patchable to unlock paid features",
		Evidence:    capEvidence(evidence, 6),
	}
}

// detectTrialPeriodCheck: isTrialActive/isTrialExpired/daysLeft — триал
// проверяется по локальным часам без серверного времени.
func detectTrialPeriodCheck(mi *MethodInfo) *VulnSignal {
	ctx := getMethodMetaContext(mi)
	if !containsAny(ctx, []string{
		"istrialactive", "is_trial_active", "istrialexpired", "is_trial_expired",
		"checktrial", "check_trial", "trialdaysleft", "trial_days_left",
		"istrialvalid", "is_trial_valid", "hastrialexpired", "gettrialstatus",
		"isexpired", "is_expired", "checkexpiry", "check_expiry", "dayssince",
	}) {
		return nil
	}
	if !mi.ReturnsBoolean && !mi.ReturnsInt {
		return nil
	}

	evidence := []string{}
	usesLocalClock := false
	for _, c := range mi.Calls {
		full := strings.ToLower(c.FullCall)
		if containsAny(full, []string{
			"system;->currenttimemillis", "system;->nanotime",
			"calendar;->getinstance", "date;-><init>", "date;->gettime",
			"sharedpreferences;->getlong", "preferences;->getlong",
		}) {
			usesLocalClock = true
			evidence = append(evidence, c.FullCall)
		}
	}
	for _, s := range mi.StringConsts {
		l := strings.ToLower(s)
		if containsAny(l, []string{
			"trial_start", "trial_end", "first_run", "install_date",
			"trial_period", "expiry_date", "trial_timestamp",
		}) {
			usesLocalClock = true
			evidence = append(evidence, s)
		}
	}

	if !usesLocalClock {
		return nil
	}
	if hasServerVerificationCall(mi) {
		return nil
	}

	return &VulnSignal{
		Kind:        VulnTrialPeriodCheck,
		Severity:    VulnSeverityMedium,
		Confidence:  0.76,
		Description: "Trial/expiry check relies on local clock or stored timestamp — bypassable by freezing date or patching return",
		Evidence:    capEvidence(evidence, 6),
	}
}

// detectLicenseLocalOnly: isLicensed/checkLicense/verifyLicense — лицензия
// проверяется локально (LVL без сервера, или свой кэш).
func detectLicenseLocalOnly(mi *MethodInfo) *VulnSignal {
	ctx := getMethodMetaContext(mi)
	if !containsAny(ctx, []string{
		"islicensed", "is_licensed", "checklicense", "check_license",
		"verifylicense", "verify_license", "validatelicense", "validate_license",
		"licensecheck", "license_check", "islicensevalid", "hasvalidlicense",
	}) {
		return nil
	}
	if !mi.ReturnsBoolean {
		return nil
	}

	evidence := []string{}
	local := false
	for _, c := range mi.Calls {
		full := strings.ToLower(c.FullCall)
		if containsAny(full, []string{
			"sharedpreferences;->getboolean", "sharedpreferences;->getstring",
			"preferences;->getboolean", "getlicense", "getcachedlicense",
		}) {
			local = true
			evidence = append(evidence, c.FullCall)
		}
	}
	for _, s := range mi.StringConsts {
		l := strings.ToLower(s)
		if containsAny(l, []string{
			"license_key", "license_valid", "licensed", "license_status",
			"license_cache", "last_license_check",
		}) {
			local = true
			evidence = append(evidence, s)
		}
	}

	if !local {
		return nil
	}
	// Play LVL / licensing.Validator — легитимный путь
	for _, c := range mi.Calls {
		full := strings.ToLower(c.FullCall)
		if containsAny(full, []string{
			"licensing/licensechecker", "licensevalidator", "play/licensing",
			"verifylicense", "licenseservice",
		}) {
			return nil
		}
	}
	if hasServerVerificationCall(mi) {
		return nil
	}

	return &VulnSignal{
		Kind:        VulnLicenseLocalOnly,
		Severity:    VulnSeverityHigh,
		Confidence:  0.77,
		Description: "License check satisfied from local cache/flag without Play LVL or server round-trip — patchable to always-licensed",
		Evidence:    capEvidence(evidence, 6),
	}
}

// detectBiometricLocalOnly: onAuthenticationSucceeded / isBiometricValid —
// результат биометрии трастится без CryptoObject binding.
func detectBiometricLocalOnly(mi *MethodInfo) *VulnSignal {
	ctx := getMethodMetaContext(mi)
	if !containsAny(ctx, []string{
		"biometric", "fingerprint", "faceunlock", "face_unlock",
		"onauthenticationsucceeded", "onauthenticationerror",
	}) {
		return nil
	}

	evidence := []string{}
	hasBiometric := false
	hasCryptoBinding := false
	for _, c := range mi.Calls {
		full := strings.ToLower(c.FullCall)
		if containsAny(full, []string{
			"biometricprompt;->authenticate", "biometricprompt$authenticationcallback",
			"fingerprintmanager;->authenticate", "biometricmanager;->canauthenticate",
		}) {
			hasBiometric = true
			evidence = append(evidence, c.FullCall)
		}
		if containsAny(full, []string{
			"cryptoobject", "cipher;->init", "signature;->initsign",
			"mac;->init", "keystore;->getkey", "keyguardmanager",
		}) {
			hasCryptoBinding = true
		}
	}
	for _, s := range mi.StringConsts {
		l := strings.ToLower(s)
		if containsAny(l, []string{"biometric_enabled", "fingerprint_enabled", "biometric_unlock"}) {
			hasBiometric = true
			evidence = append(evidence, s)
		}
	}

	if !hasBiometric || hasCryptoBinding {
		return nil
	}

	return &VulnSignal{
		Kind:        VulnBiometricLocalOnly,
		Severity:    VulnSeverityMedium,
		Confidence:  0.70,
		Description: "Biometric result trusted without CryptoObject/keystore binding — callback can be hooked or result spoofed",
		Evidence:    capEvidence(evidence, 6),
	}
}

// detectSessionTokenWeak: токен генерируется предсказуемо (timestamp, random
// без secure, UUID без сервера) или не проверяет expiry.
func detectSessionTokenWeak(mi *MethodInfo) *VulnSignal {
	ctx := getMethodMetaContext(mi)
	if !containsAny(ctx, []string{
		"generatetoken", "generate_token", "createtoken", "create_token",
		"generatesession", "generate_session", "createsession", "makeToken",
		"buildtoken", "build_token", "issuetoken", "issue_token",
	}) {
		return nil
	}

	evidence := []string{}
	weak := false
	secure := false
	for _, c := range mi.Calls {
		full := strings.ToLower(c.FullCall)
		if containsAny(full, []string{
			"java/util/random;-><init>", "math;->random",
			"system;->currenttimemillis", "uuid;->randomuuid",
			"integer;->tohexstring", "stringbuilder;->append",
		}) {
			weak = true
			evidence = append(evidence, c.FullCall)
		}
		if containsAny(full, []string{
			"securerandom", "keygenerator", "secretkeyspec",
			"messagedigest;->digest", "mac;->dofinal",
		}) {
			secure = true
		}
	}

	if !weak || secure {
		return nil
	}

	return &VulnSignal{
		Kind:        VulnSessionTokenWeak,
		Severity:    VulnSeverityMedium,
		Confidence:  0.68,
		Description: "Session/auth token generated from predictable source (timestamp/util.Random/UUID) without SecureRandom or server signing",
		Evidence:    capEvidence(evidence, 6),
	}
}

// detectPaymentClientSide: onPaymentSuccess/isPurchaseComplete — успех оплаты
// выводится из локального состояния, а не из verified purchase token.
func detectPaymentClientSide(mi *MethodInfo) *VulnSignal {
	ctx := getMethodMetaContext(mi)
	if !containsAny(ctx, []string{
		"onpaymentsuccess", "on_payment_success", "ispurchasecomplete",
		"is_purchase_complete", "paymentcomplete", "payment_complete",
		"confirmpurchase", "confirm_purchase", "isordersuccessful",
		"onpurchasecomplete", "handlepaymentsuccess", "processpayment",
	}) {
		return nil
	}

	evidence := []string{}
	local := false
	verified := false
	for _, c := range mi.Calls {
		full := strings.ToLower(c.FullCall)
		if containsAny(full, []string{
			"sharedpreferences$editor;->putboolean", "sharedpreferences$editor;->putstring",
			"setpaid", "setpurchased", "unlockpremium", "grantaccess",
		}) {
			local = true
			evidence = append(evidence, c.FullCall)
		}
		if containsAny(full, []string{
			"signature;->verify", "security;->verifypurchase", "billingclient",
			"querypurchases", "acknowledgepurchase", "getpurchasetoken",
			"getoriginaljson", "getsignature",
		}) {
			verified = true
		}
	}
	for _, s := range mi.StringConsts {
		l := strings.ToLower(s)
		if containsAny(l, []string{"purchase_complete", "payment_success", "order_id", "is_paid"}) {
			local = true
			evidence = append(evidence, s)
		}
	}

	if !local || verified {
		return nil
	}

	return &VulnSignal{
		Kind:        VulnPaymentClientSide,
		Severity:    VulnSeverityHigh,
		Confidence:  0.75,
		Description: "Payment success inferred from local state without verifying purchase token/signature — patchable to fake successful payment",
		Evidence:    capEvidence(evidence, 6),
	}
}

// detectRootDetectionBypass identifies a local boolean root gate. This is
// patchable because the final authorization decision is made in the APK.
func detectRootDetectionBypass(mi *MethodInfo) *VulnSignal {
	ctx := getMethodMetaContext(mi)
	if !mi.ReturnsBoolean || !containsAny(ctx, []string{
		"isrooted", "is_rooted", "checkroot", "check_root", "detectroot",
		"detect_root", "hasroot", "has_root", "rootcheck", "root_check",
		"isdevicecompromised", "is_device_compromised",
	}) {
		return nil
	}
	evidence := []string{}
	localCheck := false
	for _, c := range mi.Calls {
		full := strings.ToLower(c.FullCall)
		if containsAny(full, []string{
			"java/io/file;->exists", "runtime;->exec", "processbuilder",
			"packagemanager;->getpackageinfo", "build;->tags", "systemproperties",
			"rootbeer", "mount", "which", "su",
		}) {
			localCheck = true
			evidence = append(evidence, c.FullCall)
		}
	}
	for _, value := range mi.StringConsts {
		lower := strings.ToLower(value)
		if containsAny(lower, []string{
			"/system/bin/su", "/system/xbin/su", "/sbin/su", "magisk",
			"supersu", "busybox", "test-keys", "zygisk", "kernelsu",
		}) {
			localCheck = true
			evidence = append(evidence, value)
		}
	}
	if !localCheck {
		return nil
	}
	return &VulnSignal{
		Kind:        VulnRootDetectionBypass,
		Severity:    VulnSeverityHigh,
		Confidence:  0.86,
		Description: "Root status is decided by a local boolean gate - the result can be forced false in smali",
		Evidence:    capEvidence(evidence, 6),
	}
}

func detectEmulatorCheckBypass(mi *MethodInfo) *VulnSignal {
	ctx := getMethodMetaContext(mi)
	if !mi.ReturnsBoolean || !containsAny(ctx, []string{
		"isemulator", "is_emulator", "checkemulator", "check_emulator",
		"detectemulator", "detect_emulator", "isvirtualdevice", "is_virtual_device",
		"isdevicefarm", "is_device_farm", "isautomation", "is_automation",
	}) {
		return nil
	}
	evidence := []string{}
	localCheck := false
	for _, c := range mi.Calls {
		full := strings.ToLower(c.FullCall)
		if containsAny(full, []string{
			"android/os/build;->", "systemproperties", "telephonymanager;->getdeviceid",
			"sensorManager", "packageManager", "settings$secure",
		}) {
			localCheck = true
			evidence = append(evidence, c.FullCall)
		}
	}
	for _, value := range mi.StringConsts {
		lower := strings.ToLower(value)
		if containsAny(lower, []string{
			"generic", "goldfish", "ranchu", "google_sdk", "sdk_gphone",
			"genymotion", "vbox", "qemu", "bluestacks", "nox",
		}) {
			localCheck = true
			evidence = append(evidence, value)
		}
	}
	if !localCheck {
		return nil
	}
	return &VulnSignal{
		Kind:        VulnEmulatorCheckBypass,
		Severity:    VulnSeverityHigh,
		Confidence:  0.84,
		Description: "Emulator/device-farm status is decided by a local boolean gate - the result can be forced false",
		Evidence:    capEvidence(evidence, 6),
	}
}

func detectDebugCheckBypass(mi *MethodInfo) *VulnSignal {
	ctx := getMethodMetaContext(mi)
	if !mi.ReturnsBoolean || !containsAny(ctx, []string{
		"isdebugger", "is_debugger", "isdebugged", "is_debugged", "checkdebug",
		"check_debug", "detectdebugger", "detect_debugger", "isdebuggerattached",
		"is_debugger_attached", "isdebugbuild", "is_debug_build", "antidebug",
	}) {
		return nil
	}
	evidence := []string{}
	localCheck := false
	for _, c := range mi.Calls {
		full := strings.ToLower(c.FullCall)
		if containsAny(full, []string{
			"debug;->isdebuggerconnected", "debug;->waitingfordebugger",
			"applicationinfo;->flags", "tracerpid", "system;->getproperty",
		}) {
			localCheck = true
			evidence = append(evidence, c.FullCall)
		}
	}
	for _, value := range mi.StringConsts {
		lower := strings.ToLower(value)
		if containsAny(lower, []string{"tracerpid", "ro.debuggable", "debugger", "jdwp"}) {
			localCheck = true
			evidence = append(evidence, value)
		}
	}
	if !localCheck {
		return nil
	}
	return &VulnSignal{
		Kind:        VulnDebugCheckBypass,
		Severity:    VulnSeverityHigh,
		Confidence:  0.88,
		Description: "Debugger status is decided by a local boolean gate - the result can be forced false",
		Evidence:    capEvidence(evidence, 6),
	}
}

func detectTamperCheckBypass(mi *MethodInfo) *VulnSignal {
	ctx := getMethodMetaContext(mi)
	if !mi.ReturnsBoolean || !containsAny(ctx, []string{
		"istampered", "is_tampered", "checktamper", "check_tamper", "verifyintegrity",
		"verify_integrity", "checkintegrity", "check_integrity", "issignaturevalid",
		"is_signature_valid", "verifyapk", "verify_apk", "checksignature", "check_signature",
	}) {
		return nil
	}
	evidence := []string{}
	localCheck := false
	for _, c := range mi.Calls {
		full := strings.ToLower(c.FullCall)
		if containsAny(full, []string{
			"packagemanager;->getpackageinfo", "signinginfo", "signature;->tobytearray",
			"messagedigest;->digest", "certificatefactory", "jarfile", "zipfile",
			"applicationinfo;->sourcedir", "fileinputstream",
		}) {
			localCheck = true
			evidence = append(evidence, c.FullCall)
		}
	}
	for _, value := range mi.StringConsts {
		lower := strings.ToLower(value)
		if containsAny(lower, []string{"sha-256", "sha256", "signature", "checksum", "apk_hash", "cert_digest"}) {
			localCheck = true
			evidence = append(evidence, value)
		}
	}
	if !localCheck {
		return nil
	}
	return &VulnSignal{
		Kind:        VulnTamperCheckBypass,
		Severity:    VulnSeverityHigh,
		Confidence:  0.85,
		Description: "APK signature/integrity is reduced to a local boolean gate - the result can be forced to the accepted value",
		Evidence:    capEvidence(evidence, 6),
	}
}

// getMethodMetaContext возвращает строковый контекст имени метода/класса/файла в нижнем регистре с кешированием.
func getMethodMetaContext(mi *MethodInfo) string {
	if mi.cachedMetaContext == "" {
		mi.cachedMetaContext = strings.ToLower(mi.Name + " " + mi.ClassName + " " + mi.FilePath)
	}
	return mi.cachedMetaContext
}
