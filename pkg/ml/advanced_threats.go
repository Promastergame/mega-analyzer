package ml

// ═══════════════════════════════════════════════════════════════════════════════
// ADVANCED THREAT DETECTION (Task 20 - Requirements 17, 19, 21, 22)
//
// Detects sophisticated threats beyond basic patterns:
// - Anti-analysis techniques (emulator, debugger, root, hooking detection)
// - Stealthy malware behaviors
// - Reflection-based obfuscation
// ═══════════════════════════════════════════════════════════════════════════════

// ThreatCategory represents advanced threat types
type ThreatCategory string

const (
	ThreatAntiEmulator     ThreatCategory = "anti_emulator"
	ThreatAntiDebugger     ThreatCategory = "anti_debugger"
	ThreatAntiRoot         ThreatCategory = "anti_root"
	ThreatAntiHook         ThreatCategory = "anti_hook"
	ThreatReflection       ThreatCategory = "reflection_obfuscation"
	ThreatDynamicLoading   ThreatCategory = "dynamic_code_loading"
	ThreatNativeLoading    ThreatCategory = "native_library_loading"
	ThreatSuspiciousNet    ThreatCategory = "suspicious_network"
	ThreatSensitiveFile    ThreatCategory = "sensitive_file_access"
	ThreatPermissionAbuse  ThreatCategory = "dangerous_permissions"
	ThreatStealthyBehavior ThreatCategory = "stealthy_behavior"
	ThreatBiometricAbuse   ThreatCategory = "biometric_abuse"
	ThreatHWAttestation    ThreatCategory = "hw_attestation"
	ThreatDeviceBinding    ThreatCategory = "device_binding"
	ThreatKernelSURoot     ThreatCategory = "kernelsu_root"
	ThreatAppClone         ThreatCategory = "app_clone"
	ThreatSpeedHack        ThreatCategory = "speed_hack"
	ThreatGeoBlock         ThreatCategory = "geo_block"
)

// ThreatIndicator represents a detected threat
type ThreatIndicator struct {
	Category    ThreatCategory `json:"category"`
	Type        string         `json:"type"`
	Description string         `json:"description"`
	Severity    string         `json:"severity"` // critical, high, medium, low
	Confidence  float64        `json:"confidence"`
	Evidence    []string       `json:"evidence"`
}

// AdvancedThreatAnalysis contains detected threats
type AdvancedThreatAnalysis struct {
	Threats         []ThreatIndicator `json:"threats"`
	ThreatCount     int               `json:"threat_count"`
	HighestSeverity string            `json:"highest_severity"`
}

// DetectAdvancedThreats analyzes a method for advanced threat patterns
func DetectAdvancedThreats(mi *MethodInfo) *AdvancedThreatAnalysis {
	analysis := &AdvancedThreatAnalysis{
		Threats: make([]ThreatIndicator, 0, 5),
	}

	// Detect anti-emulator techniques (Requirement 22.1)
	analysis.detectAntiEmulator(mi)

	// Detect anti-debugger techniques (Requirement 22.2)
	analysis.detectAntiDebugger(mi)

	// Detect anti-root techniques (Requirement 22.3)
	analysis.detectAntiRoot(mi)

	// Detect anti-hooking techniques (Requirement 22.4)
	analysis.detectAntiHook(mi)

	// Detect reflection-based obfuscation (Requirement 21)
	analysis.detectReflectionObfuscation(mi)

	// Detect dynamic code loading (Requirement 17.1)
	analysis.detectDynamicLoading(mi)

	// Detect native library loading (Requirement 19.1)
	analysis.detectNativeLoading(mi)

	// Detect suspicious network operations (Requirement 19.2)
	analysis.detectSuspiciousNetwork(mi)

	// Detect sensitive file access (Requirement 19.3)
	analysis.detectSensitiveFileAccess(mi)

	// Detect stealthy behaviors (Requirement 19.5)
	analysis.detectStealthyBehavior(mi)

	// Phase 6 — modern bypass / environment techniques
	analysis.detectBiometricAbuse(mi)
	analysis.detectHardwareAttestation(mi)
	analysis.detectDeviceBinding(mi)
	analysis.detectKernelSURoot(mi)
	analysis.detectAppClone(mi)
	analysis.detectSpeedHack(mi)
	analysis.detectGeoBlock(mi)

	analysis.ThreatCount = len(analysis.Threats)
	analysis.calculateHighestSeverity()

	return analysis
}

// detectAntiEmulator detects emulator detection techniques
func (a *AdvancedThreatAnalysis) detectAntiEmulator(mi *MethodInfo) {
	evidence := make([]string, 0, 3)

	// Check for Build.* property checks
	buildChecks := []string{
		"build;->fingerprint", "build;->model", "build;->manufacturer",
		"build;->hardware", "build;->product", "build;->brand",
		"build;->device", "build;->board",
	}
	for _, call := range mi.Calls {
		for _, check := range buildChecks {
			if containsLower(call.FullCall, check) {
				evidence = append(evidence, "Build property check: "+check)
				break
			}
		}
	}

	// Check for emulator-specific strings
	emuStrings := []string{
		"generic", "unknown", "sdk", "google_sdk", "goldfish",
		"ranchu", "andy", "ttvm_hdragon", "genymotion",
		"vbox86", "nox", "bluestacks", "15555215554",
	}
	for _, str := range mi.StringConsts {
		strLower := toLowerFast(str)
		for _, emuStr := range emuStrings {
			if containsLower(strLower, emuStr) {
				evidence = append(evidence, "Emulator string: "+str)
				break
			}
		}
	}

	// Check for sensor/telephony checks
	sensorChecks := []string{
		"sensormanager", "telephonymanager;->getdeviceid",
		"telephonymanager;->getline1number",
	}
	for _, call := range mi.Calls {
		for _, check := range sensorChecks {
			if containsLower(call.FullCall, check) {
				evidence = append(evidence, "Sensor/telephony check: "+check)
				break
			}
		}
	}

	if len(evidence) >= 2 {
		a.Threats = append(a.Threats, ThreatIndicator{
			Category:    ThreatAntiEmulator,
			Type:        "emulator_detection",
			Description: "Detects Android emulator environment",
			Severity:    "high",
			Confidence:  0.8,
			Evidence:    evidence,
		})
	}
}

// detectAntiDebugger detects debugger detection techniques
func (a *AdvancedThreatAnalysis) detectAntiDebugger(mi *MethodInfo) {
	evidence := make([]string, 0, 3)

	// Check for Debug API calls
	debugCalls := []string{
		"debug;->isdebuggable", "debug;->isdebuggerconnected",
		"debug;->waitingfordebugger", "debug;->waitfordebugger",
	}
	for _, call := range mi.Calls {
		for _, debugCall := range debugCalls {
			if containsLower(call.FullCall, debugCall) {
				evidence = append(evidence, "Debug API: "+debugCall)
				break
			}
		}
	}

	// Check for ApplicationInfo flags check
	if containsCallPattern(mi, "applicationinfo;->flags") {
		evidence = append(evidence, "ApplicationInfo flags check (FLAG_DEBUGGABLE)")
	}

	// Check for timing-based detection
	timingCalls := []string{
		"system;->currenttimemillis", "system;->nanotime",
		"systemclock;->elapsedrealtimeo",
	}
	timingCount := 0
	for _, call := range mi.Calls {
		for _, timing := range timingCalls {
			if containsLower(call.FullCall, timing) {
				timingCount++
				break
			}
		}
	}
	if timingCount >= 2 {
		evidence = append(evidence, "Timing-based debugger detection")
	}

	// Check for ptrace (native anti-debug)
	for _, str := range mi.StringConsts {
		if containsLower(str, "ptrace") || containsLower(str, "tracerpid") {
			evidence = append(evidence, "Native anti-debug: "+str)
		}
	}

	if len(evidence) >= 1 {
		a.Threats = append(a.Threats, ThreatIndicator{
			Category:    ThreatAntiDebugger,
			Type:        "debugger_detection",
			Description: "Detects debugger attachment",
			Severity:    "high",
			Confidence:  0.85,
			Evidence:    evidence,
		})
	}
}

// detectAntiRoot detects root detection techniques
func (a *AdvancedThreatAnalysis) detectAntiRoot(mi *MethodInfo) {
	evidence := make([]string, 0, 3)

	// Check for su binary paths
	suPaths := []string{
		"/system/app/superuser.apk", "/system/xbin/su", "/sbin/su",
		"/system/bin/su", "/data/local/bin/su", "/data/local/xbin/su",
	}
	for _, str := range mi.StringConsts {
		for _, suPath := range suPaths {
			if containsLower(str, suPath) {
				evidence = append(evidence, "SU path check: "+str)
				break
			}
		}
	}

	// Check for root management apps
	rootApps := []string{
		"com.noshufou.android.su", "eu.chainfire.supersu",
		"com.topjohnwu.magisk", "com.koushikdutta.superuser",
	}
	for _, str := range mi.StringConsts {
		for _, app := range rootApps {
			if containsLower(str, app) {
				evidence = append(evidence, "Root app check: "+str)
				break
			}
		}
	}

	// Check for test-keys
	for _, str := range mi.StringConsts {
		if containsLower(str, "test-keys") {
			evidence = append(evidence, "Test-keys check (unofficial build)")
		}
	}

	// Check for busybox
	for _, str := range mi.StringConsts {
		if containsLower(str, "busybox") || containsLower(str, "which su") {
			evidence = append(evidence, "Busybox/su command check")
		}
	}

	// Check for Runtime.exec (command execution)
	if containsCallPattern(mi, "runtime;->exec") {
		evidence = append(evidence, "Runtime.exec (command execution)")
	}

	if len(evidence) >= 2 {
		a.Threats = append(a.Threats, ThreatIndicator{
			Category:    ThreatAntiRoot,
			Type:        "root_detection",
			Description: "Detects rooted device",
			Severity:    "high",
			Confidence:  0.9,
			Evidence:    evidence,
		})
	}
}

// detectAntiHook detects hooking framework detection
func (a *AdvancedThreatAnalysis) detectAntiHook(mi *MethodInfo) {
	evidence := make([]string, 0, 3)

	// Check for Xposed detection
	xposedIndicators := []string{
		"de.robv.android.xposed", "xposedbridge", "xposed_bridge",
		"xposedhelpers", "lspatch", "lsposed",
	}
	for _, str := range mi.StringConsts {
		for _, indicator := range xposedIndicators {
			if containsLower(str, indicator) {
				evidence = append(evidence, "Xposed indicator: "+str)
				break
			}
		}
	}

	// Check for Frida detection
	fridaIndicators := []string{
		"frida", "frida-server", "gmain", "linjector",
		"re.frida.server", "27042",
	}
	for _, str := range mi.StringConsts {
		for _, indicator := range fridaIndicators {
			if containsLower(str, indicator) {
				evidence = append(evidence, "Frida indicator: "+str)
				break
			}
		}
	}

	// Check for Substrate detection
	for _, str := range mi.StringConsts {
		if containsLower(str, "substrate") || containsLower(str, "cydia") {
			evidence = append(evidence, "Substrate indicator: "+str)
		}
	}

	// Check for stack trace inspection
	if containsCallPattern(mi, "stacktraceelement") || containsCallPattern(mi, "thread;->getstacktrace") {
		evidence = append(evidence, "Stack trace inspection (hook detection)")
	}

	// Check for Class.forName (loading hook framework classes)
	if containsCallPattern(mi, "class;->forname") {
		evidence = append(evidence, "Class.forName (dynamic class loading)")
	}

	if len(evidence) >= 2 {
		a.Threats = append(a.Threats, ThreatIndicator{
			Category:    ThreatAntiHook,
			Type:        "hook_framework_detection",
			Description: "Detects hooking frameworks (Xposed, Frida, Substrate)",
			Severity:    "high",
			Confidence:  0.85,
			Evidence:    evidence,
		})
	}
}

// detectReflectionObfuscation detects reflection-based obfuscation
func (a *AdvancedThreatAnalysis) detectReflectionObfuscation(mi *MethodInfo) {
	evidence := make([]string, 0, 3)

	// Check for Method.invoke
	if containsCallPattern(mi, "method;->invoke") {
		evidence = append(evidence, "Method.invoke (reflection-based invocation)")
	}

	// Check for Field.get/set
	if containsCallPattern(mi, "field;->get") || containsCallPattern(mi, "field;->set") {
		evidence = append(evidence, "Field.get/set (reflection-based field access)")
	}

	// Check for Class.forName
	if containsCallPattern(mi, "class;->forname") {
		evidence = append(evidence, "Class.forName (dynamic class loading)")
	}

	// Check for Proxy.newProxyInstance
	if containsCallPattern(mi, "proxy;->newproxyinstance") {
		evidence = append(evidence, "Proxy.newProxyInstance (dynamic proxy)")
	}

	// Check for setAccessible (bypassing access control)
	if containsCallPattern(mi, "setaccessible") {
		evidence = append(evidence, "setAccessible (bypassing access control)")
	}

	// Check for getDeclaredMethod/Field (accessing private members)
	if containsCallPattern(mi, "getdeclaredmethod") || containsCallPattern(mi, "getdeclaredfield") {
		evidence = append(evidence, "getDeclaredMethod/Field (private member access)")
	}

	if len(evidence) >= 2 {
		a.Threats = append(a.Threats, ThreatIndicator{
			Category:    ThreatReflection,
			Type:        "reflection_obfuscation",
			Description: "Uses reflection to obfuscate method/field access",
			Severity:    "medium",
			Confidence:  0.75,
			Evidence:    evidence,
		})
	}
}

// detectDynamicLoading detects dynamic code loading
func (a *AdvancedThreatAnalysis) detectDynamicLoading(mi *MethodInfo) {
	evidence := make([]string, 0, 3)

	// Check for DexClassLoader
	if containsCallPattern(mi, "dexclassloader") {
		evidence = append(evidence, "DexClassLoader (dynamic DEX loading)")
	}

	// Check for PathClassLoader
	if containsCallPattern(mi, "pathclassloader") {
		evidence = append(evidence, "PathClassLoader (dynamic class loading)")
	}

	// Check for InMemoryDexClassLoader
	if containsCallPattern(mi, "inmemorydexclassloader") {
		evidence = append(evidence, "InMemoryDexClassLoader (in-memory DEX loading)")
	}

	// Check for .dex/.jar strings
	for _, str := range mi.StringConsts {
		if containsLower(str, ".dex") || containsLower(str, ".jar") {
			evidence = append(evidence, "DEX/JAR file reference: "+str)
			break
		}
	}

	if len(evidence) >= 1 {
		a.Threats = append(a.Threats, ThreatIndicator{
			Category:    ThreatDynamicLoading,
			Type:        "dynamic_code_loading",
			Description: "Loads code dynamically at runtime",
			Severity:    "critical",
			Confidence:  0.9,
			Evidence:    evidence,
		})
	}
}

// detectNativeLoading detects native library loading
func (a *AdvancedThreatAnalysis) detectNativeLoading(mi *MethodInfo) {
	evidence := make([]string, 0, 3)

	// Check for System.loadLibrary/load
	if containsCallPattern(mi, "system;->loadlibrary") || containsCallPattern(mi, "system;->load") {
		evidence = append(evidence, "System.loadLibrary/load (native library loading)")
	}

	// Check for .so files
	for _, str := range mi.StringConsts {
		if containsLower(str, ".so") {
			evidence = append(evidence, "Native library reference: "+str)
			break
		}
	}

	// Check for obfuscated library names
	for _, str := range mi.StringConsts {
		if len(str) > 10 && containsLower(str, "lib") && !containsLower(str, "library") {
			// Potentially obfuscated library name
			if hasRandomPattern(str) {
				evidence = append(evidence, "Obfuscated library name: "+str)
				break
			}
		}
	}

	if len(evidence) >= 1 {
		a.Threats = append(a.Threats, ThreatIndicator{
			Category:    ThreatNativeLoading,
			Type:        "native_library_loading",
			Description: "Loads native libraries (potential code hiding)",
			Severity:    "medium",
			Confidence:  0.6,
			Evidence:    evidence,
		})
	}
}

// detectSuspiciousNetwork detects suspicious network operations
func (a *AdvancedThreatAnalysis) detectSuspiciousNetwork(mi *MethodInfo) {
	evidence := make([]string, 0, 3)

	// Check for non-standard ports
	suspiciousPorts := []string{
		"4444", "5555", "6666", "7777", "8888", "9999",
		"1337", "31337", "27042", // Frida default
	}
	for _, str := range mi.StringConsts {
		for _, port := range suspiciousPorts {
			if containsLower(str, port) {
				evidence = append(evidence, "Suspicious port: "+port)
				break
			}
		}
	}

	// Check for Socket/ServerSocket
	if containsCallPattern(mi, "socket;-><init>") || containsCallPattern(mi, "serversocket") {
		evidence = append(evidence, "Direct socket usage")
	}

	// Check for encrypted communication indicators
	cryptoIndicators := []string{
		"cipher", "encrypt", "decrypt", "aes", "des", "rsa",
	}
	for _, call := range mi.Calls {
		for _, indicator := range cryptoIndicators {
			if containsLower(call.FullCall, indicator) {
				evidence = append(evidence, "Encryption usage: "+indicator)
				break
			}
		}
	}

	// Check for base64 (often used for C2 communication)
	if containsCallPattern(mi, "base64") {
		evidence = append(evidence, "Base64 encoding/decoding")
	}

	if len(evidence) >= 2 {
		a.Threats = append(a.Threats, ThreatIndicator{
			Category:    ThreatSuspiciousNet,
			Type:        "suspicious_network",
			Description: "Suspicious network operations (potential C2 communication)",
			Severity:    "high",
			Confidence:  0.7,
			Evidence:    evidence,
		})
	}
}

// detectSensitiveFileAccess detects access to sensitive files
func (a *AdvancedThreatAnalysis) detectSensitiveFileAccess(mi *MethodInfo) {
	evidence := make([]string, 0, 3)

	// Check for sensitive file paths
	sensitivePaths := []string{
		"/data/data/", "/data/system/", "/system/etc/",
		"/proc/", "/sys/", "/dev/",
	}
	for _, str := range mi.StringConsts {
		for _, path := range sensitivePaths {
			if containsLower(str, path) {
				evidence = append(evidence, "Sensitive path access: "+str)
				break
			}
		}
	}

	// Check for file operations
	if containsCallPattern(mi, "file;->exists") || containsCallPattern(mi, "file;->listfiles") {
		evidence = append(evidence, "File system enumeration")
	}

	if len(evidence) >= 1 {
		a.Threats = append(a.Threats, ThreatIndicator{
			Category:    ThreatSensitiveFile,
			Type:        "sensitive_file_access",
			Description: "Accesses sensitive system files/directories",
			Severity:    "medium",
			Confidence:  0.65,
			Evidence:    evidence,
		})
	}
}

// detectStealthyBehavior detects stealthy malware behaviors
func (a *AdvancedThreatAnalysis) detectStealthyBehavior(mi *MethodInfo) {
	evidence := make([]string, 0, 3)

	// Check for background service abuse
	serviceIndicators := []string{
		"startservice", "bindservice", "jobscheduler",
		"workmanager", "alarmmanager",
	}
	for _, call := range mi.Calls {
		for _, indicator := range serviceIndicators {
			if containsLower(call.FullCall, indicator) {
				evidence = append(evidence, "Background service: "+indicator)
				break
			}
		}
	}

	// Check for broadcast receiver manipulation
	if containsCallPattern(mi, "registerreceiver") || containsCallPattern(mi, "sendbroadcast") {
		evidence = append(evidence, "Broadcast receiver manipulation")
	}

	// Check for accessibility service
	if containsCallPattern(mi, "accessibilityservice") {
		evidence = append(evidence, "Accessibility service usage (potential overlay attack)")
	}

	// Check for device admin
	if containsCallPattern(mi, "devicepolicyman") || containsCallPattern(mi, "deviceadmin") {
		evidence = append(evidence, "Device admin API usage")
	}

	if len(evidence) >= 2 {
		a.Threats = append(a.Threats, ThreatIndicator{
			Category:    ThreatStealthyBehavior,
			Type:        "stealthy_behavior",
			Description: "Exhibits stealthy malware-like behavior",
			Severity:    "high",
			Confidence:  0.75,
			Evidence:    evidence,
		})
	}
}

// calculateHighestSeverity determines the highest severity level
func (a *AdvancedThreatAnalysis) calculateHighestSeverity() {
	a.HighestSeverity = "none"

	for _, threat := range a.Threats {
		switch threat.Severity {
		case "critical":
			a.HighestSeverity = "critical"
			return
		case "high":
			if a.HighestSeverity != "critical" {
				a.HighestSeverity = "high"
			}
		case "medium":
			if a.HighestSeverity != "critical" && a.HighestSeverity != "high" {
				a.HighestSeverity = "medium"
			}
		case "low":
			if a.HighestSeverity == "none" {
				a.HighestSeverity = "low"
			}
		}
	}
}

// Helper functions

func containsCallPattern(mi *MethodInfo, pattern string) bool {
	patternLower := toLowerFast(pattern)
	for _, call := range mi.Calls {
		if containsLower(call.FullCall, patternLower) {
			return true
		}
	}
	return false
}

func containsLower(s, substr string) bool {
	return len(s) >= len(substr) && indexLower(s, substr) >= 0
}

func indexLower(s, substr string) int {
	sLower := toLowerFast(s)
	substrLower := toLowerFast(substr)

	if len(substrLower) == 0 {
		return 0
	}
	if len(substrLower) > len(sLower) {
		return -1
	}

	for i := 0; i <= len(sLower)-len(substrLower); i++ {
		match := true
		for j := 0; j < len(substrLower); j++ {
			if sLower[i+j] != substrLower[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func toLowerFast(s string) string {
	// Fast ASCII lowercase (already exists in filter.go, reusing logic)
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		b[i] = c
	}
	return string(b)
}

// detectBiometricAbuse detects BiometricPrompt / FingerprintManager authentication gate usage.
func (a *AdvancedThreatAnalysis) detectBiometricAbuse(mi *MethodInfo) {
	evidence := make([]string, 0, 3)

	bioCalls := []string{
		"biometricprompt;->authenticate", "biometricprompt;->cancelauthentication",
		"fingerprintmanager;->authenticate", "biometricmanager;->canadauthenticate",
	}
	for _, call := range mi.Calls {
		for _, bc := range bioCalls {
			if containsLower(call.FullCall, bc) {
				evidence = append(evidence, "Biometric API: "+bc)
				break
			}
		}
	}

	bioStrings := []string{"biometricprompt", "fingerprintmanager", "face_auth", "biometric_gate"}
	for _, str := range mi.StringConsts {
		for _, bs := range bioStrings {
			if containsLower(str, bs) {
				evidence = append(evidence, "Biometric string: "+str)
				break
			}
		}
	}

	if len(evidence) >= 1 {
		a.Threats = append(a.Threats, ThreatIndicator{
			Category:    ThreatBiometricAbuse,
			Type:        "biometric_auth_gate",
			Description: "Biometric authentication gate (fingerprint/face) — potential bypass target",
			Severity:    "high",
			Confidence:  0.80,
			Evidence:    evidence,
		})
	}
}

// detectHardwareAttestation detects TEE / StrongBox / Android Keystore attestation usage.
func (a *AdvancedThreatAnalysis) detectHardwareAttestation(mi *MethodInfo) {
	evidence := make([]string, 0, 3)

	attestCalls := []string{
		"keypairgenerator;->generatekeypair", "keystore;->getentry",
		"x509certificate;->getextensionvalue", "attestationrecord",
	}
	for _, call := range mi.Calls {
		for _, ac := range attestCalls {
			if containsLower(call.FullCall, ac) {
				evidence = append(evidence, "Attestation API: "+ac)
				break
			}
		}
	}

	attestStrings := []string{"attestation", "strongbox", "tee", "key_attestation", "hardware_backed", "trusted_execution"}
	for _, str := range mi.StringConsts {
		for _, as := range attestStrings {
			if containsLower(str, as) {
				evidence = append(evidence, "Attestation string: "+str)
				break
			}
		}
	}

	if len(evidence) >= 2 {
		a.Threats = append(a.Threats, ThreatIndicator{
			Category:    ThreatHWAttestation,
			Type:        "hardware_attestation",
			Description: "TEE/StrongBox hardware attestation — strong device integrity check",
			Severity:    "critical",
			Confidence:  0.85,
			Evidence:    evidence,
		})
	}
}

// detectDeviceBinding detects device ID / IMEI binding enforcement.
func (a *AdvancedThreatAnalysis) detectDeviceBinding(mi *MethodInfo) {
	evidence := make([]string, 0, 3)

	bindingCalls := []string{
		"telephonymanager;->getdeviceid", "telephonymanager;->getimei",
		"telephonymanager;->getimsi", "settings$secure;->getstring",
		"telephonymanager;->getsubscriberid",
	}
	for _, call := range mi.Calls {
		for _, bc := range bindingCalls {
			if containsLower(call.FullCall, bc) {
				evidence = append(evidence, "Device ID API: "+bc)
				break
			}
		}
	}

	for _, str := range mi.StringConsts {
		if containsLower(str, "android_id") || containsLower(str, "device_id") ||
			containsLower(str, "hardware_id") || containsLower(str, "bound_device") {
			evidence = append(evidence, "Device binding string: "+str)
		}
	}

	// Hardware-backed binding: equals() after device ID fetch
	if len(evidence) >= 1 && containsCallPattern(mi, "string;->equals") {
		evidence = append(evidence, "Device ID equality check")
	}

	if len(evidence) >= 2 {
		a.Threats = append(a.Threats, ThreatIndicator{
			Category:    ThreatDeviceBinding,
			Type:        "device_id_binding",
			Description: "Device ID/IMEI binding — app tied to specific hardware",
			Severity:    "high",
			Confidence:  0.75,
			Evidence:    evidence,
		})
	}
}

// detectKernelSURoot detects KernelSU / APatch / Zygisk Next root presence checks.
func (a *AdvancedThreatAnalysis) detectKernelSURoot(mi *MethodInfo) {
	evidence := make([]string, 0, 3)

	ksuPaths := []string{
		"/data/adb/ksud", "/data/adb/apd", "/data/adb/ksu",
		"kernelsu", "apatch", "zygisk_next", "ksu_version",
	}
	for _, str := range mi.StringConsts {
		for _, path := range ksuPaths {
			if containsLower(str, path) {
				evidence = append(evidence, "KernelSU/APatch path: "+str)
				break
			}
		}
	}

	// Also check for /proc/version kernel string matching
	for _, str := range mi.StringConsts {
		if containsLower(str, "/proc/version") || containsLower(str, "kernelversion") {
			evidence = append(evidence, "Kernel version check: "+str)
		}
	}

	if len(evidence) >= 1 {
		a.Threats = append(a.Threats, ThreatIndicator{
			Category:    ThreatKernelSURoot,
			Type:        "kernelsu_apatch_detection",
			Description: "KernelSU / APatch / Zygisk Next root method detection",
			Severity:    "high",
			Confidence:  0.85,
			Evidence:    evidence,
		})
	}
}

// detectAppClone detects dual-space / parallel-space / clone app presence checks.
func (a *AdvancedThreatAnalysis) detectAppClone(mi *MethodInfo) {
	evidence := make([]string, 0, 3)

	clonePackages := []string{
		"com.lbe.parallel", "com.ludashi.dualspace", "com.excelliance.dualaid",
		"com.iscope.iclone", "io.va.exposed", "com.bly.daulspace",
	}
	for _, str := range mi.StringConsts {
		for _, pkg := range clonePackages {
			if containsLower(str, pkg) {
				evidence = append(evidence, "Clone app package: "+str)
				break
			}
		}
	}

	if containsCallPattern(mi, "usermanager;->getusers") || containsCallPattern(mi, "usermanager;->getuserid") {
		evidence = append(evidence, "UserManager multi-user API call")
	}

	for _, str := range mi.StringConsts {
		if containsLower(str, "parallel_space") || containsLower(str, "virtualapp") ||
			containsLower(str, "work_profile") || containsLower(str, "clone_app") {
			evidence = append(evidence, "Clone/parallel string: "+str)
		}
	}

	if len(evidence) >= 2 {
		a.Threats = append(a.Threats, ThreatIndicator{
			Category:    ThreatAppClone,
			Type:        "clone_app_detection",
			Description: "Dual-space / clone app detection — may block multi-user / parallel space",
			Severity:    "medium",
			Confidence:  0.75,
			Evidence:    evidence,
		})
	}
}

// detectSpeedHack detects game speed-hack / frame-time manipulation detection.
func (a *AdvancedThreatAnalysis) detectSpeedHack(mi *MethodInfo) {
	evidence := make([]string, 0, 3)

	timingCalls := []string{
		"system;->nanotime", "systemclock;->elapsedrealtime",
		"systemclock;->uptimemillis", "choreographer;->getlastframetime",
	}
	timingCount := 0
	for _, call := range mi.Calls {
		for _, tc := range timingCalls {
			if containsLower(call.FullCall, tc) {
				timingCount++
				evidence = append(evidence, "Timing call: "+tc)
				break
			}
		}
	}

	for _, str := range mi.StringConsts {
		if containsLower(str, "speed_hack") || containsLower(str, "speedhack") ||
			containsLower(str, "timescale") || containsLower(str, "frame_drift") {
			evidence = append(evidence, "Speed-hack string: "+str)
		}
	}

	// Multiple timing calls = frame-time validation loop
	if timingCount >= 2 {
		evidence = append(evidence, "Multiple timing comparisons (frame-time validation)")
	}

	if len(evidence) >= 2 {
		a.Threats = append(a.Threats, ThreatIndicator{
			Category:    ThreatSpeedHack,
			Type:        "speed_hack_detection",
			Description: "Game speed-hack / frame-time validation — clock manipulation check",
			Severity:    "medium",
			Confidence:  0.70,
			Evidence:    evidence,
		})
	}
}

// detectGeoBlock detects geographic restriction / region-lock enforcement.
func (a *AdvancedThreatAnalysis) detectGeoBlock(mi *MethodInfo) {
	evidence := make([]string, 0, 3)

	geoCalls := []string{
		"locale;->getcountry", "locale;->getdefault",
		"telephonymanager;->getnetworkcountryiso",
		"telephonymanager;->getsimcountryiso",
	}
	for _, call := range mi.Calls {
		for _, gc := range geoCalls {
			if containsLower(call.FullCall, gc) {
				evidence = append(evidence, "Geo-detection API: "+gc)
				break
			}
		}
	}

	for _, str := range mi.StringConsts {
		if containsLower(str, "country_code") || containsLower(str, "region_lock") ||
			containsLower(str, "geo_block") || containsLower(str, "restricted_country") ||
			containsLower(str, "allowed_countries") || containsLower(str, "blocked_regions") {
			evidence = append(evidence, "Geo-restriction string: "+str)
		}
	}

	if len(evidence) >= 2 {
		a.Threats = append(a.Threats, ThreatIndicator{
			Category:    ThreatGeoBlock,
			Type:        "geographic_restriction",
			Description: "Geographic region-lock / country restriction enforcement",
			Severity:    "medium",
			Confidence:  0.72,
			Evidence:    evidence,
		})
	}
}

func hasRandomPattern(s string) bool {
	// Simple heuristic: check if string has mix of consonants/vowels
	// Random strings often lack vowel patterns
	vowels := 0
	consonants := 0
	for _, c := range s {
		if c >= 'a' && c <= 'z' {
			if c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u' {
				vowels++
			} else {
				consonants++
			}
		}
	}
	total := vowels + consonants
	if total == 0 {
		return false
	}
	// If less than 20% vowels, likely random/obfuscated
	return float64(vowels)/float64(total) < 0.2
}
