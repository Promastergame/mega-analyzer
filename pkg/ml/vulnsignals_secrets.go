package ml

import (
	"fmt"
	"strings"
)


func containsAny(s string, needles []string) bool {
	for _, needle := range needles {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}

func capEvidence(evidence []string, max int) []string {
	if max <= 0 || len(evidence) <= max {
		return evidence
	}
	return evidence[:max]
}

func maskSensitive(s string) string {
	if len(s) <= 12 {
		return "***"
	}
	return s[:6] + "…" + s[len(s)-4:]
}

func looksLikeSecretLiteral(s string) bool {
	if len(s) < 24 || strings.ContainsAny(s, " \t\r\n") || strings.HasPrefix(strings.ToLower(s), "http") {
		return false
	}
	if reBase64Like.MatchString(s) || reHexLong.MatchString(s) {
		return true
	}

	hasLower, hasUpper, hasDigit, hasSymbol := false, false, false, false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= '0' && r <= '9':
			hasDigit = true
		default:
			hasSymbol = true
		}
	}
	classes := 0
	for _, ok := range []bool{hasLower, hasUpper, hasDigit, hasSymbol} {
		if ok {
			classes++
		}
	}
	return classes >= 3 && len(s) >= 32
}

// ─── Phase 5 Detectors ────────────────────────────────────────────────────────

// detectKeylogger: AccessibilityEvent getText + network send in same method.
// Classic keylogger: reads all typed text via accessibility, sends via HTTP.
func detectKeylogger(mi *MethodInfo) *VulnSignal {
	hasTextEvent := false
	hasNetSend := false
	evidence := []string{}

	for _, c := range mi.Calls {
		full := strings.ToLower(c.FullCall)
		if strings.Contains(full, "accessibilityevent;->gettext") ||
			strings.Contains(full, "accessibilityevent;->getsource") {
			hasTextEvent = true
			evidence = append(evidence, c.FullCall)
		}
		if strings.Contains(full, "httpurlconnection") ||
			strings.Contains(full, "okhttp3") ||
			strings.Contains(full, "outputstream;->write") ||
			strings.Contains(full, "socket;->getoutputstream") {
			hasNetSend = true
			evidence = append(evidence, c.FullCall)
		}
	}
	for _, s := range mi.StringConsts {
		l := strings.ToLower(s)
		if strings.Contains(l, "type_view_text_changed") ||
			strings.Contains(l, "text_changed") {
			hasTextEvent = true
			evidence = append(evidence, s)
		}
	}
	if !hasTextEvent || !hasNetSend {
		return nil
	}
	return &VulnSignal{
		Kind:        VulnKeylogger,
		Severity:    VulnSeverityCritical,
		Confidence:  0.91,
		Description: "Accessibility text-change event + network send — keylogger pattern (captures all typed text)",
		Evidence:    evidence,
	}
}

// detectScreenCapture: MediaProjectionManager + VirtualDisplay + optional exfil.
// Spyware pattern: captures device screen silently.
func detectScreenCapture(mi *MethodInfo) *VulnSignal {
	hasProjection := false
	hasExfil := false
	evidence := []string{}

	for _, c := range mi.Calls {
		full := strings.ToLower(c.FullCall)
		if strings.Contains(full, "mediaprojectionmanager") ||
			strings.Contains(full, "mediaprojection;->createvirtualdisplay") ||
			strings.Contains(full, "imagereader;->acquirelatestimage") {
			hasProjection = true
			evidence = append(evidence, c.FullCall)
		}
		if strings.Contains(full, "httpurlconnection") ||
			strings.Contains(full, "outputstream") ||
			strings.Contains(full, "ftpclient") {
			hasExfil = true
			evidence = append(evidence, c.FullCall)
		}
	}
	if !hasProjection {
		return nil
	}
	severity := VulnSeverityHigh
	desc := "MediaProjectionManager / VirtualDisplay — screen capture capability"
	conf := 0.82
	if hasExfil {
		severity = VulnSeverityCritical
		desc = "MediaProjectionManager + network send — covert screen capture + exfiltration"
		conf = 0.91
	}
	return &VulnSignal{
		Kind:        VulnScreenCapture,
		Severity:    severity,
		Confidence:  conf,
		Description: desc,
		Evidence:    evidence,
	}
}

// detectTelephonyAbuse: TelephonyManager harvesting IMEI/IMSI/phone number.
// Privacy violation — common in stalkerware and aggressive adware.
func detectTelephonyAbuse(mi *MethodInfo) *VulnSignal {
	ctx := strings.ToLower(mi.ClassName + " " + mi.FilePath + " " + mi.Name)
	if strings.Contains(ctx, "crunandroid") || strings.Contains(ctx, "androidplus") {
		return nil
	}
	evidence := []string{}
	for _, c := range mi.Calls {
		full := strings.ToLower(c.FullCall)
		if strings.Contains(full, "telephonymanager;->getdeviceid") ||
			strings.Contains(full, "telephonymanager;->getimei") ||
			strings.Contains(full, "telephonymanager;->getmeid") ||
			strings.Contains(full, "telephonymanager;->getsubscriberid") ||
			strings.Contains(full, "telephonymanager;->getline1number") ||
			strings.Contains(full, "telephonymanager;->getsimserialnumber") ||
			strings.Contains(full, "telephonymanager;->getnetworkoperatorname") {
			evidence = append(evidence, c.FullCall)
		}
	}
	if len(evidence) < 2 {
		return nil
	}
	conf := 0.70
	if len(evidence) >= 3 {
		conf = 0.9 // harvesting multiple IDs = very suspicious
	}
	return &VulnSignal{
		Kind:        VulnTelephonyAbuse,
		Severity:    VulnSeverityHigh,
		Confidence:  conf,
		Description: fmt.Sprintf("TelephonyManager harvesting %d device identifier(s) (IMEI/IMSI/phone) — stalkerware/adware indicator", len(evidence)),
		Evidence:    evidence,
	}
}

// detectWebSocketC2: WebSocket connection to suspicious/obfuscated URL.
// Used by banking trojans for real-time C2.
func detectWebSocketC2(mi *MethodInfo) *VulnSignal {
	hasWebSocket := false
	hasSuspiciousURL := false
	evidence := []string{}

	for _, c := range mi.Calls {
		full := strings.ToLower(c.FullCall)
		if strings.Contains(full, "websocket") ||
			strings.Contains(full, "okhttp3/websocket") {
			hasWebSocket = true
			evidence = append(evidence, c.FullCall)
		}
	}
	for _, s := range mi.StringConsts {
		l := strings.ToLower(s)
		if strings.HasPrefix(l, "ws://") || strings.HasPrefix(l, "wss://") {
			hasWebSocket = true
			if reSusURL.MatchString(l) || reIPAddress.MatchString(s) || reTelegramURL.MatchString(l) {
				hasSuspiciousURL = true
				evidence = append(evidence, "ws_c2:"+s)
			} else {
				evidence = append(evidence, "ws:"+s)
			}
		}
	}
	if !hasWebSocket {
		return nil
	}
	if hasSuspiciousURL {
		return &VulnSignal{
			Kind:        VulnWebSocketC2,
			Severity:    VulnSeverityCritical,
			Confidence:  0.88,
			Description: "WebSocket connection to suspicious URL/IP — real-time C2 channel",
			Evidence:    evidence,
		}
	}
	return &VulnSignal{
		Kind:        VulnWebSocketC2,
		Severity:    VulnSeverityMedium,
		Confidence:  0.50,
		Description: "WebSocket usage detected — review for C2 potential",
		Evidence:    evidence,
	}
}

// detectLocationStealth: Background location access + immediate network send.
// Stalkerware pattern: silently tracks GPS location and exfils it.
func detectLocationStealth(mi *MethodInfo) *VulnSignal {
	hasLocation := false
	hasNetSend := false
	evidence := []string{}

	for _, c := range mi.Calls {
		full := strings.ToLower(c.FullCall)
		if strings.Contains(full, "fusedlocationproviderclient") ||
			strings.Contains(full, "locationmanager;->requestlocationupdates") ||
			strings.Contains(full, "locationmanager;->getlastknownlocation") ||
			strings.Contains(full, "location;->getlatitude") ||
			strings.Contains(full, "location;->getlongitude") {
			hasLocation = true
			evidence = append(evidence, c.FullCall)
		}
		if strings.Contains(full, "httpurlconnection") ||
			strings.Contains(full, "okhttp3") ||
			strings.Contains(full, "outputstream;->write") {
			hasNetSend = true
		}
	}
	if !hasLocation || !hasNetSend {
		return nil
	}
	classLower := strings.ToLower(mi.ClassName)
	isBackground := strings.Contains(classLower, "service") ||
		strings.Contains(classLower, "receiver") ||
		strings.Contains(classLower, "worker")
	severity := VulnSeverityHigh
	conf := 0.78
	desc := "Location access + network send — potential location exfiltration"
	if isBackground {
		severity = VulnSeverityCritical
		conf = 0.91
		desc = "Location access + network send in background Service — covert location tracking (stalkerware)"
	}
	return &VulnSignal{
		Kind:        VulnLocationStealth,
		Severity:    severity,
		Confidence:  conf,
		Description: desc,
		Evidence:    evidence,
	}
}

// detectContentInjection: ContentProvider/SQLite query with string concatenation.
// SQL injection risk — CWE-89.
func detectContentInjection(mi *MethodInfo) *VulnSignal {
	ctx := strings.ToLower(mi.ClassName + " " + mi.FilePath)
	if strings.Contains(ctx, "services/cservices") || strings.Contains(ctx, "contentresolver") {
		return nil
	}
	hasQuery := false
	hasConcat := false
	evidence := []string{}

	for _, c := range mi.Calls {
		full := strings.ToLower(c.FullCall)
		if strings.Contains(full, "contentresolver;->query") ||
			strings.Contains(full, "sqlitedatabase;->rawquery") ||
			strings.Contains(full, "sqlitedatabase;->execsql") {
			hasQuery = true
			evidence = append(evidence, c.FullCall)
		}
		if strings.Contains(full, "stringbuilder;->append") ||
			strings.Contains(full, "string;->concat") {
			hasConcat = true
		}
	}
	if !hasQuery || !hasConcat {
		return nil
	}
	return &VulnSignal{
		Kind:        VulnContentInjection,
		Severity:    VulnSeverityHigh,
		Confidence:  0.80,
		Description: "ContentProvider/SQLite query + string concatenation — potential SQL injection (CWE-89)",
		Evidence:    evidence,
	}
}

// detectObfuscatedDexDecrypt: XOR decrypt loop + DexClassLoader = encrypted payload dropper.
// Decrypts hidden DEX from encrypted bytes at runtime, then loads it dynamically.
func detectObfuscatedDexDecrypt(mi *MethodInfo) *VulnSignal {
	hasDecrypt := false
	hasLoader := false
	evidence := []string{}

	for _, line := range mi.RawBody {
		l := strings.ToLower(line)
		if strings.Contains(l, "xor-int/lit8") ||
			strings.Contains(l, "xor-int/lit16") ||
			strings.Contains(l, "xor-int/2addr") {
			hasDecrypt = true
			if len(evidence) < 3 {
				evidence = append(evidence, strings.TrimSpace(line))
			}
		}
	}
	for _, c := range mi.Calls {
		full := strings.ToLower(c.FullCall)
		if strings.Contains(full, "dexclassloader") ||
			strings.Contains(full, "inmemorydexclassloader") ||
			strings.Contains(full, "pathclassloader") {
			hasLoader = true
			evidence = append(evidence, c.FullCall)
		}
	}
	if !hasDecrypt || !hasLoader {
		return nil
	}
	return &VulnSignal{
		Kind:        VulnObfuscatedDexDecrypt,
		Severity:    VulnSeverityCritical,
		Confidence:  0.93,
		Description: "XOR decrypt loop + DexClassLoader — encrypted payload dropper (decrypts hidden DEX at runtime)",
		Evidence:    evidence,
	}
}

// detectJNIBridgeAbuse: Native RegisterNatives + suspicious symbol names.
// Malware hides logic in native code behind innocuous-looking JNI bridges.
func detectJNIBridgeAbuse(mi *MethodInfo) *VulnSignal {
	hasNativeReg := false
	hasSuspiciousNative := false
	evidence := []string{}

	for _, c := range mi.Calls {
		full := strings.ToLower(c.FullCall)
		if strings.Contains(full, "registernatives") ||
			strings.Contains(full, "jni_onload") {
			hasNativeReg = true
			evidence = append(evidence, c.FullCall)
		}
	}
	for _, s := range mi.StringConsts {
		l := strings.ToLower(s)
		if strings.Contains(l, "exec") || strings.Contains(l, "shell") ||
			strings.Contains(l, "payload") || strings.Contains(l, "inject") {
			if hasNativeReg {
				hasSuspiciousNative = true
				evidence = append(evidence, "native_sym:"+s)
			}
		}
	}
	if !hasNativeReg || !hasSuspiciousNative {
		return nil
	}
	return &VulnSignal{
		Kind:        VulnJNIBridgeAbuse,
		Severity:    VulnSeverityHigh,
		Confidence:  0.82,
		Description: "JNI RegisterNatives + suspicious native symbol names — potential native code obfuscation",
		Evidence:    evidence,
	}
}
