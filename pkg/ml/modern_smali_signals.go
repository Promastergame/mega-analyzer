package ml

import "strings"

// Modern smali detectors deliberately report evidence instead of emitting a
// patch. These findings are intended for authorized audits and manual review;
// they avoid treating every security API call as an automatic bypass target.

func detectWeakCrypto(mi *MethodInfo) *VulnSignal {
	if mi == nil {
		return nil
	}
	evidence := make([]string, 0, 4)
	severe := false
	for _, c := range mi.Calls {
		full := strings.ToLower(c.FullCall)
		if strings.Contains(full, "cipher;->getinstance") || strings.Contains(full, "messagedigest;->getinstance") {
			evidence = append(evidence, c.FullCall)
		}
	}
	for _, literal := range mi.StringConsts {
		v := strings.ToUpper(literal)
		// Algorithm names match as standalone tokens, not substrings:
		// bare Contains("DES") misfires on DESCRIPTION/DESTROY/DESKTOP,
		// Contains("SHA1") on SHA1PRNG (the standard SecureRandom name).
		if strings.Contains(v, "/ECB/") || containsAlgorithmToken(v, "RC4") ||
			containsAlgorithmToken(v, "DES") || containsAlgorithmToken(v, "DESEDE") ||
			containsAlgorithmToken(v, "3DES") || strings.Contains(v, "NO PADDING") {
			evidence = append(evidence, "crypto_literal:"+literal)
			severe = true
		}
		if containsAlgorithmToken(v, "MD5") || containsAlgorithmToken(v, "SHA-1") ||
			containsAlgorithmToken(v, "SHA1") {
			evidence = append(evidence, "digest_literal:"+literal)
		}
	}
	if len(evidence) == 0 || (!severe && !hasWeakDigestLiteral(mi)) {
		return nil
	}
	severity := VulnSeverityMedium
	confidence := 0.72
	if severe {
		severity = VulnSeverityHigh
		confidence = 0.86
	}
	return &VulnSignal{
		Kind:        VulnWeakCrypto,
		Severity:    severity,
		Confidence:  confidence,
		Description: "Weak or misuse-prone cryptography detected; verify mode, padding, key management, and digest choice",
		Evidence:    evidence,
	}
}

func hasWeakDigestLiteral(mi *MethodInfo) bool {
	for _, literal := range mi.StringConsts {
		v := strings.ToUpper(literal)
		if containsAlgorithmToken(v, "MD5") || containsAlgorithmToken(v, "SHA-1") || containsAlgorithmToken(v, "SHA1") {
			return true
		}
	}
	return false
}

// containsAlgorithmToken reports whether upper-cased text mentions token as a
// standalone algorithm name rather than as a substring of another word.
// "AES/DES/PKCS5Padding", "DES", "DESede" and "3DES" match; "DESCRIPTION",
// "DESTROY" and "DESKTOP" do not. Neighbours must not be ASCII letters or
// digits (so "SHA1PRNG" does not match "SHA1").
func containsAlgorithmToken(text, token string) bool {
	if token == "" {
		return false
	}
	for i := 0; i+len(token) <= len(text); i++ {
		if text[i:i+len(token)] != token {
			continue
		}
		if i > 0 && isASCIILetterOrDigit(text[i-1]) {
			continue
		}
		if j := i + len(token); j < len(text) && isASCIILetterOrDigit(text[j]) {
			continue
		}
		return true
	}
	return false
}

func isASCIILetterOrDigit(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}

func detectUnsafeDeserialization(mi *MethodInfo) *VulnSignal {
	if mi == nil {
		return nil
	}
	evidence := make([]string, 0, 3)
	for _, c := range mi.Calls {
		full := strings.ToLower(c.FullCall)
		if strings.Contains(full, "objectinputstream;->readobject") ||
			strings.Contains(full, "parcel;->unmarshall") ||
			strings.Contains(full, "java/io/objectinputstream") {
			evidence = append(evidence, c.FullCall)
		}
	}
	if len(evidence) == 0 {
		return nil
	}
	return &VulnSignal{
		Kind:        VulnUnsafeDeserialization,
		Severity:    VulnSeverityHigh,
		Confidence:  0.84,
		Description: "Deserialization of a potentially untrusted object or Parcel payload; enforce a trusted source and strict type checks",
		Evidence:    evidence,
	}
}

func detectUnsafeWebViewConfig(mi *MethodInfo) *VulnSignal {
	if mi == nil {
		return nil
	}
	evidence := make([]string, 0, 5)
	hasBridge := false
	hasFileAccess := false
	for _, c := range mi.Calls {
		full := strings.ToLower(c.FullCall)
		switch {
		case strings.Contains(full, "websettings;->setjavascriptenabled") || strings.Contains(full, "webview;->addjavascriptinterface"):
			hasBridge = true
			evidence = append(evidence, c.FullCall)
		case strings.Contains(full, "setallowfileaccess") || strings.Contains(full, "setallowuniversalaccessfromfileurls") || strings.Contains(full, "setallowfileaccessfromfileurls"):
			hasFileAccess = true
			evidence = append(evidence, c.FullCall)
		}
	}
	if !hasBridge && !hasFileAccess {
		return nil
	}
	severity := VulnSeverityMedium
	confidence := 0.70
	if hasBridge && hasFileAccess {
		severity = VulnSeverityHigh
		confidence = 0.90
	}
	return &VulnSignal{
		Kind:        VulnWebViewConfig,
		Severity:    severity,
		Confidence:  confidence,
		Description: "WebView exposes JavaScript or local-file capabilities; restrict origins, bridge methods, and file access",
		Evidence:    evidence,
	}
}

func detectMutablePendingIntent(mi *MethodInfo) *VulnSignal {
	if mi == nil {
		return nil
	}
	ctx := strings.ToLower(mi.ClassName + " " + mi.FilePath + " " + mi.Name)
	if strings.Contains(ctx, "jobscheduling") || strings.Contains(ctx, "dorestart") {
		return nil
	}
	evidence := make([]string, 0, 3)
	for _, c := range mi.Calls {
		full := strings.ToLower(c.FullCall)
		if strings.Contains(full, "pendingintent;->getactivity") ||
			strings.Contains(full, "pendingintent;->getbroadcast") ||
			strings.Contains(full, "pendingintent;->getservice") {
			evidence = append(evidence, c.FullCall)
		}
	}
	for _, literal := range mi.StringConsts {
		if strings.Contains(strings.ToUpper(literal), "FLAG_MUTABLE") {
			evidence = append(evidence, "flag_literal:"+literal)
		}
	}
	if len(evidence) == 0 {
		return nil
	}
	return &VulnSignal{
		Kind:        VulnMutablePendingIntent,
		Severity:    VulnSeverityMedium,
		Confidence:  0.76,
		Description: "PendingIntent construction needs an explicit mutability decision and immutable-by-default review",
		Evidence:    evidence,
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CLIENT-SIDE TRUST DETECTORS (authorized-audit findings)
//
// Каждый детектор описывает УЯЗВИМЫЙ КОД и в поле Description — как этот код
// обходится при аудите (bypass note). Это evidence-first находки для ручного
// ревью, а не автоматические патчи.
// ═══════════════════════════════════════════════════════════════════════════════

// detectClientSideCurrency — игра/приложение хранит и изменяет валюту
// (coins/gems/lives/score) полностью на клиенте: геттеры getCoins()I,
// SharedPreferences.putInt("coins", ...), addCoins/spendCoins без серверной
// верификации.
//
// УЯЗВИМЫЙ КОД:  public int getCoins() { return prefs.getInt("coins", 0); }
// ОБХОД (аудит): патч геттера на const v0, 0x7FFFFFFF (или большое значение) →
// return v0; либо NOP тела spendCoins/deductCurrency. См. BuildCurrencyReturnPatch.
func detectClientSideCurrency(mi *MethodInfo) *VulnSignal {
	if mi == nil {
		return nil
	}
	evidence := make([]string, 0, 4)
	name := strings.ToLower(mi.Name)
	classCtx := strings.ToLower(mi.ClassName + " " + mi.FilePath)
	if strings.Contains(classCtx, "billingclient/") || strings.Contains(classCtx, "datatransport/") || strings.Contains(classCtx, "firebase/transport") || strings.Contains(classCtx, "permissionshelper") || strings.Contains(name, "currencycode") || strings.Contains(name, "productdetailscurrency") || strings.Contains(name, "pricecurrency") || strings.Contains(name, "storagemetrics") || strings.Contains(name, "externalstoragemanager") {
		return nil
	}
	currencyName := strings.Contains(name, "coin") || strings.Contains(name, "gem") ||
		strings.Contains(name, "gold") || strings.Contains(name, "credit") ||
		strings.Contains(name, "currency") || strings.Contains(name, "lives") ||
		strings.Contains(name, "score") || strings.Contains(name, "money") ||
		strings.Contains(name, "balance") || strings.Contains(name, "energy")
	if currencyName && (mi.ReturnsInt || mi.ReturnsBoolean ||
		strings.HasPrefix(name, "get") || strings.HasPrefix(name, "add") ||
		strings.HasPrefix(name, "spend") || strings.HasPrefix(name, "deduct") ||
		strings.HasPrefix(name, "set") || strings.HasPrefix(name, "increase")) {
		evidence = append(evidence, "method:"+mi.Name)
	}
	for _, c := range mi.Calls {
		full := strings.ToLower(c.FullCall)
		if strings.Contains(full, "sharedpreferences;->getint") ||
			strings.Contains(full, "editor;->putint") ||
			strings.Contains(full, "sharedpreferences;->getlong") ||
			strings.Contains(full, "editor;->putlong") {
			for _, lit := range mi.StringConsts {
				l := strings.ToLower(lit)
				if strings.Contains(l, "coin") || strings.Contains(l, "gem") ||
					strings.Contains(l, "gold") || strings.Contains(l, "credit") ||
					strings.Contains(l, "lives") || strings.Contains(l, "score") ||
					strings.Contains(l, "balance") || strings.Contains(l, "energy") {
					evidence = append(evidence, "prefs_key:"+lit)
					break
				}
			}
		}
	}
	if len(evidence) == 0 {
		return nil
	}
	return &VulnSignal{
		Kind:       VulnClientSideCurrency,
		Severity:   VulnSeverityHigh,
		Confidence: 0.84,
		Description: "Client-side currency/score trust: value is read/written locally without server verification. " +
			"Bypass (audit): patch the getter to return a large constant (const v0, 0x7FFFFFFF; return v0) " +
			"or NOP the spend/deduct method body. Fix: move balance logic server-side.",
		Evidence: evidence,
	}
}

// detectPremiumClientGate — премиум/подписка проверяется boolean-геттером на
// клиенте: isPremium()Z, isVip()Z, hasSubscription()Z, isPro()Z.
//
// УЯЗВИМЫЙ КОД:  public boolean isPremium() { return this.premium; }
// ОБХОД (аудит): return-true патч (const/4 v0, 0x1; return v0). См. стратегию
// PatchReturnTrue и BuildPremiumUnlockPatch.
func detectPremiumClientGate(mi *MethodInfo) *VulnSignal {
	if mi == nil {
		return nil
	}
	if !mi.ReturnsBoolean {
		return nil
	}
	name := strings.ToLower(mi.Name)
	classCtx := strings.ToLower(mi.ClassName + " " + mi.FilePath)
	// Не считаем все callbacks Billing/IAP SDK уязвимыми gates: методы вида
	// cndOnPurchaseOk/cndOnSubscriptionFail — это обработчики событий, а не
	// локальный флаг доступа. Нужен явный getter/access-check и контекст доступа.
	getter := strings.HasPrefix(name, "is") || strings.HasPrefix(name, "has") ||
		strings.HasPrefix(name, "can") || strings.HasPrefix(name, "should") ||
		strings.Contains(name, "enabled") || strings.Contains(name, "unlocked")
	accessCtx := strings.Contains(classCtx, "license") || strings.Contains(classCtx, "entitlement") ||
		strings.Contains(classCtx, "premium") || strings.Contains(classCtx, "paywall") ||
		strings.Contains(classCtx, "access") || strings.Contains(classCtx, "unlock")
	gate := getter && (strings.Contains(name, "premium") || strings.Contains(name, "vip") ||
		(strings.Contains(name, "pro") && strings.HasPrefix(name, "is")) ||
		strings.Contains(name, "subscri") || strings.Contains(name, "unlock") ||
		strings.Contains(name, "paid") || strings.Contains(name, "purchase") ||
		strings.Contains(name, "adfree") || strings.Contains(name, "ad_free") ||
		strings.Contains(name, "fullversion") || strings.Contains(name, "full_version"))
	if !gate || (!accessCtx && !mi.IsShortMethod && !mi.HasDualReturn) {
		return nil
	}
	confidence := 0.8
	if mi.IsShortMethod || mi.HasDualReturn {
		confidence = 0.9
	}
	return &VulnSignal{
		Kind:       VulnPremiumClientGate,
		Severity:   VulnSeverityHigh,
		Confidence: confidence,
		Description: "Premium/subscription gate evaluated on the client via boolean getter. " +
			"Bypass (audit): return-true patch (const/4 v0, 0x1; return v0). " +
			"Fix: verify entitlements server-side (Play Billing verify on backend).",
		Evidence: []string{"method:" + mi.Name},
	}
}

// detectLicenseCheckClient — проверка лицензии Google Play LVL на клиенте.
//
// УЯЗВИМЫЙ КОД:  LicenseChecker.checkAccess(...)/allow() на клиенте.
// ОБХОД (аудит): NOP вызова checkAccess или return-void/allow в колбэке.
func detectLicenseCheckClient(mi *MethodInfo) *VulnSignal {
	if mi == nil {
		return nil
	}
	evidence := make([]string, 0, 3)
	for _, c := range mi.Calls {
		full := strings.ToLower(c.FullCall)
		if strings.Contains(full, "licensechecker") || strings.Contains(full, "licensevalidator") ||
			strings.Contains(full, "lvl") && strings.Contains(full, "check") ||
			strings.Contains(full, "->checkaccess") ||
			strings.Contains(full, "licensecheckcallback;->allow") ||
			strings.Contains(full, "licensecheckercallback;->allow") ||
			strings.Contains(full, "policy;->allowaccess") {
			evidence = append(evidence, c.FullCall)
		}
	}
	if len(evidence) == 0 {
		return nil
	}
	return &VulnSignal{
		Kind:       VulnLicenseCheckClient,
		Severity:   VulnSeverityMedium,
		Confidence: 0.78,
		Description: "Play LVL license check runs on the client. " +
			"Bypass (audit): NOP the checkAccess call site or stub the callback to allow(). " +
			"Fix: server-side license/Play Integrity verification.",
		Evidence: evidence,
	}
}

// detectWeakRandom — java/util/Random или Math.random для токенов/ключей/IV.
//
// УЯЗВИМЫЙ КОД:  new Random().nextInt() для session token.
// ОБХОД/ЭКСПЛУАТАЦИЯ (аудит): предсказуемый PRNG — токены восстанавливаются по
// seed (System.currentTimeMillis). Fix: java/security/SecureRandom.
func detectWeakRandom(mi *MethodInfo) *VulnSignal {
	if mi == nil {
		return nil
	}
	evidence := make([]string, 0, 3)
	secure := false
	for _, c := range mi.Calls {
		full := strings.ToLower(c.FullCall)
		if strings.Contains(full, "securerandom") {
			secure = true
		}
		if strings.Contains(full, "java/util/random;-><init>") ||
			strings.Contains(full, "java/util/random;->next") ||
			strings.Contains(full, "java/lang/math;->random") {
			evidence = append(evidence, c.FullCall)
		}
	}
	if len(evidence) == 0 || secure {
		return nil
	}
	ctx := strings.ToLower(mi.ClassName + " " + mi.FilePath + " " + mi.Name)
	// java.util.Random is common in game/runtime logic; report only when security context is explicit.
	securityCtx := strings.Contains(ctx, "token") || strings.Contains(ctx, "auth") || strings.Contains(ctx, "session") || strings.Contains(ctx, "crypto") || strings.Contains(ctx, "key") || strings.Contains(ctx, "password")
	// Контекстное усиление: рядом токен/ключ/пароль — severity выше.
	severe := false
	for _, lit := range mi.StringConsts {
		l := strings.ToLower(lit)
		if strings.Contains(l, "token") || strings.Contains(l, "key") ||
			strings.Contains(l, "secret") || strings.Contains(l, "password") ||
			strings.Contains(l, "session") || strings.Contains(l, "iv") {
			severe = true
			break
		}
	}
	if !securityCtx && !severe {
		return nil
	}
	severity := VulnSeverityMedium
	confidence := 0.7
	if severe {
		severity = VulnSeverityHigh
		confidence = 0.85
	}
	return &VulnSignal{
		Kind:        VulnWeakRandom,
		Severity:    severity,
		Confidence:  confidence,
		Description: "Predictable PRNG (java/util/Random or Math.random) used in a security-sensitive context; tokens are recoverable from the seed. Fix: use SecureRandom.",
		Evidence:    evidence,
	}
}

// detectSQLInjection — rawQuery/execSQL с конкатенацией строк.
//
// УЯЗВИМЫЙ КОД:  db.rawQuery("SELECT * FROM u WHERE name='" + input + "'", ...)
// ЭКСПЛУАТАЦИЯ (аудит): классический SQLi через пользовательский ввод.
// Fix: selectionArgs / параметризованные запросы.
func detectSQLInjection(mi *MethodInfo) *VulnSignal {
	if mi == nil {
		return nil
	}
	evidence := make([]string, 0, 3)
	for _, c := range mi.Calls {
		full := strings.ToLower(c.FullCall)
		if strings.Contains(full, "contentresolver;->query") {
			continue
		}
		if strings.Contains(full, "->rawquery") || strings.Contains(full, "->execsql") ||
			strings.Contains(full, "->compilestatement") {
			evidence = append(evidence, c.FullCall)
		}
	}
	if len(evidence) == 0 {
		return nil
	}
	// Конкатенация строк рядом с SQL — признак инъекции, а не параметризованного вызова.
	concat := false
	for _, c := range mi.Calls {
		if strings.Contains(strings.ToLower(c.FullCall), "stringbuilder;->append") {
			concat = true
			break
		}
	}
	severity := VulnSeverityMedium
	confidence := 0.68
	if concat {
		severity = VulnSeverityHigh
		confidence = 0.85
		evidence = append(evidence, "string_concat:StringBuilder.append")
	}
	return &VulnSignal{
		Kind:        VulnSQLInjection,
		Severity:    severity,
		Confidence:  confidence,
		Description: "Raw SQL executed with possible string concatenation — injectable if input is attacker-controlled. Fix: use selectionArgs / bound parameters.",
		Evidence:    evidence,
	}
}

// detectPathTraversal — пути к файлам строятся из внешних данных.
//
// УЯЗВИМЫЙ КОД:  new File(Environment.getExternalStorageDirectory(), name)
// ЭКСПЛУАТАЦИЯ (аудит): "../" в name → чтение/запись вне sandbox.
// Fix: canonical path + проверка префикса, внутреннее хранилище.
func detectPathTraversal(mi *MethodInfo) *VulnSignal {
	if mi == nil {
		return nil
	}
	ctx := strings.ToLower(mi.ClassName + " " + mi.FilePath + " " + mi.Name)
	if strings.Contains(ctx, "runtime/log") || strings.Contains(ctx, "play/core/assetpacks") ||
		strings.Contains(ctx, "vending/expansion/zipfile") || strings.Contains(ctx, "isexternalstorage") ||
		strings.Contains(ctx, "hasexternalstorage") || strings.Contains(ctx, "services/inifile") ||
		strings.Contains(ctx, "application/crunapp") || strings.Contains(ctx, "services/cservices") ||
		strings.Contains(ctx, "extensions/crunkclist") {
		return nil
	}
	evidence := make([]string, 0, 3)
	fileIO := false
	userControlled := false
	for _, c := range mi.Calls {
		full := strings.ToLower(c.FullCall)
		if strings.Contains(full, "getexternalstorage") ||
			strings.Contains(full, "java/io/file;-><init>") ||
			strings.Contains(full, "fileoutputstream;-><init>") ||
			strings.Contains(full, "fileinputstream;-><init>") {
			fileIO = true
			evidence = append(evidence, c.FullCall)
		}
		if strings.Contains(full, "stringbuilder;->append") || strings.Contains(full, "string;->concat") ||
			strings.Contains(full, "zipentry;->getname") || strings.Contains(full, "uri;->getpath") {
			userControlled = true
		}
	}
	for _, lit := range mi.StringConsts {
		ll := strings.ToLower(lit)
		if strings.Contains(ll, "../") || strings.Contains(ll, "..\\") || strings.Contains(ll, "%2e%2e") {
			userControlled = true
			evidence = append(evidence, "traversal_literal:"+lit)
		}
	}
	if !fileIO || !userControlled || len(evidence) < 2 { // нужен file-IO + controlled path/traversal
		return nil
	}
	return &VulnSignal{
		Kind:        VulnPathTraversal,
		Severity:    VulnSeverityMedium,
		Confidence:  0.72,
		Description: "File paths built from external storage or user-controlled names; verify canonical-path checks to prevent ../ traversal outside the app sandbox.",
		Evidence:    evidence,
	}
}

// detectCleartextHTTP — http:// эндпоинты / cleartext трафик.
//
// УЯЗВИМЫЙ КОД:  const-string v0, "http://api.example.com/..."
// ЭКСПЛУАТАЦИЯ (аудит): MITM — трафик читается/подменяется в открытом виде.
// Fix: https + networkSecurityConfig без cleartextTrafficPermitted.
func detectCleartextHTTP(mi *MethodInfo) *VulnSignal {
	if mi == nil {
		return nil
	}
	evidence := make([]string, 0, 3)
	for _, lit := range mi.StringConsts {
		l := strings.ToLower(lit)
		if strings.HasPrefix(l, "http://") &&
			!strings.Contains(l, "localhost") && !strings.Contains(l, "127.0.0.1") &&
			!strings.Contains(l, "schemas.android.com") && !strings.Contains(l, "w3.org") {
			evidence = append(evidence, "cleartext_url:"+lit)
		}
		if strings.Contains(l, "usescleartexttraffic") || strings.Contains(l, "cleartexttrafficpermitted") {
			evidence = append(evidence, "cleartext_flag:"+lit)
		}
	}
	if len(evidence) == 0 {
		return nil
	}
	return &VulnSignal{
		Kind:        VulnCleartextHTTP,
		Severity:    VulnSeverityMedium,
		Confidence:  0.8,
		Description: "Cleartext HTTP endpoint or cleartext-traffic flag: traffic is MITM-readable and modifiable. Fix: HTTPS everywhere + networkSecurityConfig.",
		Evidence:    evidence,
	}
}
