package ml

import "strings"

// ═══════════════════════════════════════════════════════════════════════════════
// EXTENDED VULNERABILITY SIGNALS — новые детекторы (сверх Phase 1-7)
//
// Отдельный модуль с дополнительными сигналами, которые реверсер часто ищет
// руками при аудите Android-приложений:
//
//   • Frida / instrumentation artifacts (anti-instrumentation → патч-точка)
//   • Hardcoded crypto material (SecretKeySpec / IvParameterSpec из констант)
//   • WebView file access (setAllowFileAccess* / universal access from file URLs)
//   • Sensitive data in SharedPreferences (пароли/токены в открытом виде)
//   • Sensitive data written to logcat (android.util.Log с секретами)
//   • Clipboard read of sensitive data (getPrimaryClip рядом с credential-контекстом)
//
// Все детекторы регистрируются через detectExtendedSignals(), который
// вызывается из AnalyzeVulnerabilitySignals (vulnsignals_core.go).
// ═══════════════════════════════════════════════════════════════════════════════

const (
	// VulnFridaArtifacts — приложение детектит Frida/инструментацию (порт 27042,
	// gum-js-loop, re.frida.server). Это анти-реверс проверка → кандидат на bypass.
	VulnFridaArtifacts VulnKind = "frida_artifacts"
	// VulnHardcodedCryptoKey — ключ/IV собран из строковой или байтовой константы.
	VulnHardcodedCryptoKey VulnKind = "hardcoded_crypto_key"
	// VulnWebViewFileAccess — WebView с доступом к файловой системе / universal access.
	VulnWebViewFileAccess VulnKind = "webview_file_access"
	// VulnSharedPrefsSecret — секрет (пароль/токен/ключ) пишется в SharedPreferences plaintext.
	VulnSharedPrefsSecret VulnKind = "shared_prefs_secret"
	// VulnLogSensitive — чувствительные данные попадают в logcat.
	VulnLogSensitive VulnKind = "log_sensitive"
	// VulnClipboardReadSensitive — приложение читает буфер обмена в credential-контексте.
	VulnClipboardReadSensitive VulnKind = "clipboard_read_sensitive"
)

// detectExtendedSignals прогоняет все дополнительные детекторы этого модуля.
// Возвращает найденные сигналы (может быть пустым слайсом).
func detectExtendedSignals(mi *MethodInfo) []VulnSignal {
	if mi == nil {
		return nil
	}
	detectors := []func(*MethodInfo) *VulnSignal{
		detectFridaArtifacts,
		detectHardcodedCryptoKey,
		detectWebViewFileAccess,
		detectSharedPrefsSecret,
		detectLogSensitive,
		detectClipboardReadSensitive,
	}
	out := make([]VulnSignal, 0, len(detectors))
	for _, d := range detectors {
		if s := d(mi); s != nil {
			out = append(out, *s)
		}
	}
	return out
}

// detectFridaArtifacts: строки/порты, характерные для обнаружения Frida и
// прочей динамической инструментации. Это проверка, которую делает приложение,
// поэтому она интересна как точка обхода (вернуть false / no-op).
func detectFridaArtifacts(mi *MethodInfo) *VulnSignal {
	needles := []string{
		"frida", "gum-js-loop", "gmain", "re.frida.server", "frida-server",
		"libfrida", "linjector", "xposed", "27042", "27043",
	}
	evidence := []string{}
	for _, s := range mi.StringConsts {
		l := strings.ToLower(s)
		if containsAny(l, needles) {
			evidence = append(evidence, s)
		}
	}
	if len(evidence) == 0 {
		return nil
	}
	return &VulnSignal{
		Kind:        VulnFridaArtifacts,
		Severity:    VulnSeverityHigh,
		Confidence:  0.85,
		Description: "Frida/instrumentation detection strings — anti-reversing check, candidate for bypass",
		Evidence:    capEvidence(evidence, 6),
	}
}

// detectHardcodedCryptoKey: SecretKeySpec / IvParameterSpec, инициализированные
// из строковой или короткой байтовой константы — классический hardcoded key/IV.
func detectHardcodedCryptoKey(mi *MethodInfo) *VulnSignal {
	usesKeySpec := false
	for _, c := range mi.Calls {
		full := strings.ToLower(c.FullCall)
		if strings.Contains(full, "javax/crypto/spec/secretkeyspec;-><init>") ||
			strings.Contains(full, "javax/crypto/spec/ivparameterspec;-><init>") {
			usesKeySpec = true
			break
		}
	}
	if !usesKeySpec {
		return nil
	}
	evidence := []string{}
	for _, s := range mi.StringConsts {
		trimmed := strings.TrimSpace(s)
		// Короткие "ключеподобные" константы: 8/16/24/32 симв., без пробелов, не URL.
		if n := len(trimmed); (n == 8 || n == 16 || n == 24 || n == 32) &&
			!strings.ContainsAny(trimmed, " \t\r\n") &&
			!strings.HasPrefix(strings.ToLower(trimmed), "http") {
			evidence = append(evidence, maskSensitive(trimmed))
		}
	}
	if len(evidence) == 0 {
		return nil
	}
	return &VulnSignal{
		Kind:        VulnHardcodedCryptoKey,
		Severity:    VulnSeverityHigh,
		Confidence:  0.8,
		Description: "SecretKeySpec/IvParameterSpec built from a hardcoded constant — recoverable crypto key/IV",
		Evidence:    capEvidence(evidence, 4),
	}
}

// detectWebViewFileAccess: WebSettings с включённым доступом к файловой системе
// или universal access from file URLs — типовая XSS/LFI поверхность в WebView.
func detectWebViewFileAccess(mi *MethodInfo) *VulnSignal {
	evidence := []string{}
	for _, c := range mi.Calls {
		full := strings.ToLower(c.FullCall)
		if strings.Contains(full, "setallowfileaccessfromfileurls") ||
			strings.Contains(full, "setallowuniversalaccessfromfileurls") ||
			strings.Contains(full, "setallowfileaccess") ||
			strings.Contains(full, "setallowcontentaccess") {
			evidence = append(evidence, c.FullCall)
		}
	}
	if len(evidence) == 0 {
		return nil
	}
	return &VulnSignal{
		Kind:        VulnWebViewFileAccess,
		Severity:    VulnSeverityMedium,
		Confidence:  0.7,
		Description: "WebView file/universal access enabled — local file read / XSS exposure",
		Evidence:    capEvidence(evidence, 5),
	}
}

// detectSharedPrefsSecret: SharedPreferences.putString с ключом, похожим на
// credential (password/token/secret/apikey), — секрет хранится в открытом виде.
func detectSharedPrefsSecret(mi *MethodInfo) *VulnSignal {
	usesPrefs := false
	for _, c := range mi.Calls {
		full := strings.ToLower(c.FullCall)
		if strings.Contains(full, "sharedpreferences") ||
			strings.Contains(full, "sharedpreferences$editor;->putstring") ||
			strings.Contains(full, "editor;->putstring") {
			usesPrefs = true
			break
		}
	}
	if !usesPrefs {
		return nil
	}
	secretKeys := []string{"password", "passwd", "pwd", "token", "secret", "apikey", "api_key", "credential", "auth", "session", "privatekey", "refresh_token"}
	evidence := []string{}
	for _, s := range mi.StringConsts {
		if containsAny(strings.ToLower(s), secretKeys) {
			evidence = append(evidence, s)
		}
	}
	if len(evidence) == 0 {
		return nil
	}
	return &VulnSignal{
		Kind:        VulnSharedPrefsSecret,
		Severity:    VulnSeverityMedium,
		Confidence:  0.65,
		Description: "Credential-like value stored in SharedPreferences (plaintext at rest)",
		Evidence:    capEvidence(evidence, 5),
	}
}

// detectLogSensitive: android.util.Log вызывается в методе, где присутствуют
// credential-подобные строки — утечка чувствительных данных в logcat.
func detectLogSensitive(mi *MethodInfo) *VulnSignal {
	hasLog := false
	for _, c := range mi.Calls {
		full := strings.ToLower(c.FullCall)
		if strings.Contains(full, "android/util/log;->") {
			hasLog = true
			break
		}
	}
	if !hasLog {
		return nil
	}
	secretHints := []string{"password", "passwd", "secret", "apikey", "api_key", "authorization", "bearer", "session", "credit", "card", "cvv", "pin"}
	evidence := []string{}
	ctx := strings.ToLower(mi.ClassName + " " + mi.FilePath + " " + mi.Name)
	if strings.Contains(ctx, "pairip/") {
		return nil
	}
	for _, s := range mi.StringConsts {
		ls := strings.ToLower(s)
		statusOnly := strings.Contains(ls, "already scheduled") || strings.Contains(ls, "skipping") ||
			strings.Contains(ls, "user cancelled") || strings.Contains(ls, "item already owned") ||
			strings.Contains(ls, "signature is bad")
		// Avoid false positives from static status messages such as
		// "token already scheduled" unless an actual credential-like value is present.
		if statusOnly {
			continue
		}
		if looksLikeSecretLiteral(s) || containsAny(ls, secretHints) {
			evidence = append(evidence, s)
		}
	}
	for _, c := range mi.Calls {
		full := strings.ToLower(c.FullCall)
		if strings.Contains(full, "getpurchasetoken") || strings.Contains(full, "getsignature") || strings.Contains(full, "getoriginaljson") {
			evidence = append(evidence, c.FullCall)
		}
	}
	if len(evidence) == 0 {
		return nil
	}
	return &VulnSignal{
		Kind:        VulnLogSensitive,
		Severity:    VulnSeverityMedium,
		Confidence:  0.6,
		Description: "Sensitive/credential strings logged via android.util.Log (logcat leak)",
		Evidence:    capEvidence(evidence, 5),
	}
}

// detectClipboardReadSensitive: чтение буфера обмена (getPrimaryClip) в методе с
// credential-контекстом — потенциальный сбор данных из clipboard.
func detectClipboardReadSensitive(mi *MethodInfo) *VulnSignal {
	hasClipRead := false
	for _, c := range mi.Calls {
		full := strings.ToLower(c.FullCall)
		if strings.Contains(full, "clipboardmanager;->getprimaryclip") ||
			strings.Contains(full, "clipboardmanager;->gettext") ||
			strings.Contains(full, "clipboardmanager;->hasprimaryclip") {
			hasClipRead = true
			break
		}
	}
	if !hasClipRead {
		return nil
	}
	meta := getMethodMetaContext(mi)
	hints := []string{"password", "token", "otp", "code", "2fa", "auth", "secret", "wallet", "seed", "mnemonic"}
	if !containsAny(meta, hints) {
		// Дополнительно проверяем строковые константы метода.
		found := false
		for _, s := range mi.StringConsts {
			if containsAny(strings.ToLower(s), hints) {
				found = true
				break
			}
		}
		if !found {
			return nil
		}
	}
	return &VulnSignal{
		Kind:        VulnClipboardReadSensitive,
		Severity:    VulnSeverityMedium,
		Confidence:  0.6,
		Description: "Clipboard read in a credential/OTP context — potential clipboard harvesting",
		Evidence:    []string{"clipboard read + sensitive context: " + meta},
	}
}
