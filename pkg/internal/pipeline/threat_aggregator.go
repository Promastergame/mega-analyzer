package pipeline

import (
	"sort"

	"mega-analyzer/pkg/internal/types"
)

// ═══════════════════════════════════════════════════════════════════════════════
// THREAT AGGREGATOR - Cross-file correlation engine
// ═══════════════════════════════════════════════════════════════════════════════

// ThreatAggregator performs APK-wide signal correlation
type ThreatAggregator struct {
	signals *ApkSignals
}

func NewThreatAggregator() *ThreatAggregator {
	return &ThreatAggregator{
		signals: NewApkSignals(),
	}
}

func (ta *ThreatAggregator) GetSignals() *ApkSignals {
	return ta.signals
}

// AddFileSignals adds signals from a single file analysis
func (ta *ThreatAggregator) AddFileSignals(fs *FileSignals) {
	ta.signals.AddFileSignals(fs)
}

// RunCorrelations performs APK-wide correlation analysis
// This should be called AFTER all files have been analyzed
func (ta *ThreatAggregator) RunCorrelations() {
	ta.signals.mu.Lock()
	if len(ta.signals.Correlations) > 0 || ta.signals.FusionIntelligence != nil {
		ta.signals.mu.Unlock()
		return
	}
	ta.signals.mu.Unlock()

	ta.correlateNetworkDexLoad()
	ta.correlateWebViewAbuse()
	ta.correlateAccessibilityAbuse()
	ta.correlateStealerCombo()
	ta.correlateReflectionNetwork()
	ta.correlateBase64Network()
	ta.correlateAntiAnalysisPayload()
	ta.correlateGeoRootCombo()
	ta.correlateHardcodedIPCluster()
	ta.correlateRuntimeLoadChain()

	ta.signals.FusionIntelligence = runBehaviorFusionIntelligence(ta.signals)
}

// ═══════════════════════════════════════════════════════════════════════════════
// CORRELATION RULES
// ═══════════════════════════════════════════════════════════════════════════════

// DEX from Network: DexLoader + Network + FileWrite/DexSuffix
func (ta *ThreatAggregator) correlateNetworkDexLoad() {
	// Global presence is not a chain: an app can use networking in one library
	// and a legitimate loader in another. Require all evidence in one analysis
	// unit; source-to-sink dataflow is the stronger, cross-method proof.
	files := ta.filesWithSignalGroups(
		[]SignalType{SignalDexClassLoader, SignalInMemoryDexClassLoader, SignalDexFileLoad},
		[]SignalType{SignalNetworkHTTP, SignalNetworkHTTPS, SignalNetworkURLConnection, SignalNetworkOkHttp},
		[]SignalType{SignalDexSuffix, SignalFileWrite, SignalFileOutputStream},
	)
	if len(files) > 0 {

		ta.signals.Correlations = append(ta.signals.Correlations, Correlation{
			Name:        "DEX_FROM_NETWORK",
			Description: "Dynamic code loading from network detected (downloads DEX and loads it)",
			Signals: []SignalType{
				SignalDexClassLoader, SignalNetworkHTTP, SignalDexSuffix,
			},
			Files:    files,
			Score:    SignalWeight[SignalDexFromNetwork],
			Severity: SeverityCritical,
		})

		ta.signals.TotalScore += SignalWeight[SignalDexFromNetwork]
	}
}

// WebView Remote Code: WebView + JS Interface + Remote URL
func (ta *ThreatAggregator) correlateWebViewAbuse() {
	bridgeFiles := ta.filesWithSignalGroups(
		[]SignalType{SignalWebViewJSInterface},
		[]SignalType{SignalWebViewJSEnabled},
		[]SignalType{SignalWebViewLoadURL, SignalWebViewLoadData},
		[]SignalType{SignalNetworkHTTP, SignalNetworkHTTPS},
	)

	// High risk: JS bridge + JS + remote-loading indicators in one file. The
	// AST WebView detector remains authoritative for object-level proof.
	if len(bridgeFiles) > 0 {

		ta.signals.Correlations = append(ta.signals.Correlations, Correlation{
			Name:        "WEBVIEW_JS_BRIDGE_REMOTE",
			Description: "WebView with JavaScript bridge loading remote content (potential RCE vector)",
			Signals: []SignalType{
				SignalWebViewJSInterface, SignalWebViewLoadURL,
			},
			Files:    bridgeFiles,
			Score:    SignalWeight[SignalWebViewRemoteCode],
			Severity: SeverityCritical,
		})

		ta.signals.TotalScore += SignalWeight[SignalWebViewRemoteCode]
	} else if files := ta.filesWithSignalGroups(
		[]SignalType{SignalWebViewJSEnabled},
		[]SignalType{SignalWebViewLoadURL, SignalWebViewLoadData},
		[]SignalType{SignalNetworkHTTP, SignalNetworkHTTPS},
	); len(files) > 0 {
		// Medium risk: JS enabled + remote
		ta.signals.Correlations = append(ta.signals.Correlations, Correlation{
			Name:        "WEBVIEW_REMOTE_JS",
			Description: "WebView with JavaScript enabled loading remote content",
			Signals: []SignalType{
				SignalWebViewJSEnabled, SignalWebViewLoadURL,
			},
			Files:    files,
			Score:    8,
			Severity: SeverityHigh,
		})

		ta.signals.TotalScore += 8
	}
}

// filesWithSignalGroups returns files that contain at least one signal from
// every group. It is intentionally stricter than APK-wide aggregation.
func (ta *ThreatAggregator) filesWithSignalGroups(groups ...[]SignalType) []string {
	ta.signals.mu.RLock()
	defer ta.signals.mu.RUnlock()
	files := make([]string, 0)
	for path, file := range ta.signals.Files {
		matched := true
		for _, group := range groups {
			found := false
			for _, signal := range group {
				if file.Has(signal) {
					found = true
					break
				}
			}
			if !found {
				matched = false
				break
			}
		}
		if matched {
			files = append(files, path)
		}
	}
	sort.Strings(files)
	return files
}

// Accessibility Abuse: Permission + Service + Event handling + Root access
func (ta *ThreatAggregator) correlateAccessibilityAbuse() {
	hasPermission := ta.signals.HasGlobal(SignalAccessibilityPermission)
	hasService := ta.signals.HasGlobal(SignalAccessibilityService)
	hasEvent := ta.signals.HasGlobal(SignalAccessibilityEvent)
	hasRoot := ta.signals.HasGlobal(SignalAccessibilityRootWindow)
	hasAction := ta.signals.HasGlobal(SignalAccessibilityGlobalAction)

	// Critical: Full accessibility abuse chain
	if hasPermission && hasService && hasEvent && (hasRoot || hasAction) {
		files := ta.collectFilesForSignals(
			SignalAccessibilityPermission, SignalAccessibilityService,
			SignalAccessibilityEvent, SignalAccessibilityRootWindow,
			SignalAccessibilityGlobalAction,
		)

		ta.signals.Correlations = append(ta.signals.Correlations, Correlation{
			Name:        "ACCESSIBILITY_ABUSE_FULL",
			Description: "Full accessibility abuse chain: permission + service + event + root/actions (banking trojan pattern)",
			Signals: []SignalType{
				SignalAccessibilityPermission, SignalAccessibilityService,
				SignalAccessibilityRootWindow, SignalAccessibilityGlobalAction,
			},
			Files:    files,
			Score:    SignalWeight[SignalAccessibilityAbuse],
			Severity: SeverityHigh,
		})

		ta.signals.TotalScore += SignalWeight[SignalAccessibilityAbuse]
	} else if hasPermission && (hasService || hasEvent) {
		// High risk: Permission + Service/Event
		files := ta.collectFilesForSignals(
			SignalAccessibilityPermission, SignalAccessibilityService,
			SignalAccessibilityEvent,
		)

		ta.signals.Correlations = append(ta.signals.Correlations, Correlation{
			Name:        "ACCESSIBILITY_SERVICE_ACTIVE",
			Description: "Active accessibility service implementation (high risk for overlay attacks)",
			Signals: []SignalType{
				SignalAccessibilityPermission, SignalAccessibilityService,
			},
			Files:    files,
			Score:    4,
			Severity: SeverityMedium,
		})

		ta.signals.TotalScore += 4
	}
}

// Stealer Permission Combo: Multiple stealer-related permissions
func (ta *ThreatAggregator) correlateStealerCombo() {
	stealerPerms := []SignalType{
		SignalPermissionSMS,
		SignalPermissionContacts,
		SignalPermissionCallLog,
		SignalPermissionCamera,
		SignalPermissionMicrophone,
		SignalPermissionLocation,
	}

	count := 0
	var foundPerms []SignalType
	for _, perm := range stealerPerms {
		if ta.signals.HasGlobal(perm) {
			count++
			foundPerms = append(foundPerms, perm)
		}
	}

	// 3+ stealer permissions is highly suspicious
	if count >= 3 {
		files := ta.collectFilesForSignals(foundPerms...)

		severity := SeverityHigh
		score := 10
		if count >= 5 {
			severity = SeverityCritical
			score = SignalWeight[SignalStealerCombo]
		}

		ta.signals.Correlations = append(ta.signals.Correlations, Correlation{
			Name:        "STEALER_PERMISSION_COMBO",
			Description: "Multiple data-stealing permissions detected (SMS, contacts, calls, camera, mic, location)",
			Signals:     foundPerms,
			Files:       files,
			Score:       score,
			Severity:    severity,
		})

		ta.signals.TotalScore += score
	}
}

// Reflection + Network: Dynamic code execution with network access
func (ta *ThreatAggregator) correlateReflectionNetwork() {
	hasReflection := ta.signals.HasAnyGlobal(
		SignalReflectionForName,
		SignalReflectionInvoke,
		SignalReflectionLoadClass,
		SignalReflectionDefineClass,
	)

	hasNetwork := ta.signals.HasAnyGlobal(
		SignalNetworkHTTP, SignalNetworkHTTPS,
		SignalNetworkURLConnection, SignalNetworkOkHttp,
	)

	hasC2 := ta.signals.HasAnyGlobal(
		SignalDiscordWebhook,
		SignalPastebin, SignalHardcodedIPv4,
		SignalSuspiciousTLD,
	)

	if hasReflection && (hasNetwork || hasC2) {
		files := ta.collectFilesForSignals(
			SignalReflectionForName, SignalReflectionInvoke,
			SignalReflectionLoadClass, SignalNetworkHTTP,
			SignalHardcodedIPv4,
		)

		ta.signals.Correlations = append(ta.signals.Correlations, Correlation{
			Name:        "REFLECTION_NETWORK_COMBO",
			Description: "Reflection-based dynamic execution with network/C2 access",
			Signals: []SignalType{
				SignalReflectionInvoke, SignalNetworkHTTP,
			},
			Files:    files,
			Score:    10,
			Severity: SeverityHigh,
		})

		ta.signals.TotalScore += 10
	}
}

// Base64 + Network: Obfuscated network communication
func (ta *ThreatAggregator) correlateBase64Network() {
	hasBase64 := ta.signals.HasAnyGlobal(
		SignalBase64Decode,
		SignalBase64LongString,
	)

	hasNetwork := ta.signals.HasAnyGlobal(
		SignalNetworkHTTP, SignalNetworkHTTPS,
		SignalNetworkURLConnection,
	)

	hasC2 := ta.signals.HasAnyGlobal(
		SignalDiscordWebhook,
		SignalPastebin, SignalHardcodedIPv4,
	)

	if hasBase64 && (hasNetwork || hasC2) {
		files := ta.collectFilesForSignals(
			SignalBase64Decode, SignalBase64LongString,
			SignalNetworkHTTP,
		)

		ta.signals.Correlations = append(ta.signals.Correlations, Correlation{
			Name:        "BASE64_OBFUSCATED_NETWORK",
			Description: "Base64 encoding with network operations (obfuscated C2 communication pattern)",
			Signals: []SignalType{
				SignalBase64Decode, SignalNetworkHTTP,
			},
			Files:    files,
			Score:    8,
			Severity: SeverityHigh,
		})

		ta.signals.TotalScore += 8
	}
}

// Anti-Analysis + Payload: Evasion with suspicious payload
func (ta *ThreatAggregator) correlateAntiAnalysisPayload() {
	hasAntiAnalysis := ta.signals.HasAnyGlobal(
		SignalFrida, SignalXposed, SignalSubstrate,
		SignalPtrace, SignalDebuggerCheck, SignalEmulatorCheck,
		SignalRootCheck,
	)

	hasSuspiciousPayload := ta.signals.HasAnyGlobal(
		SignalNativeDexLoader, SignalNativeHTTP, SignalNativeC2,
		SignalDexClassLoader, SignalInMemoryDexClassLoader,
	)

	if hasAntiAnalysis && hasSuspiciousPayload {
		files := ta.collectFilesForSignals(
			SignalFrida, SignalXposed, SignalPtrace,
			SignalNativeDexLoader, SignalNativeC2,
		)

		ta.signals.Correlations = append(ta.signals.Correlations, Correlation{
			Name:        "ANTI_ANALYSIS_WITH_PAYLOAD",
			Description: "Anti-analysis techniques combined with suspicious payload (likely packed malware)",
			Signals: []SignalType{
				SignalFrida, SignalNativeDexLoader,
			},
			Files:    files,
			Score:    15,
			Severity: SeverityCritical,
		})

		ta.signals.TotalScore += 15
	}
}

// Geo-fencing + Root detection combo (banking/anti-analysis pattern)
func (ta *ThreatAggregator) correlateGeoRootCombo() {
	hasGeo := ta.signals.HasGlobal(SignalGeoFence)
	hasRoot := ta.signals.HasGlobal(SignalRootCheck)
	hasAnti := ta.signals.HasAnyGlobal(
		SignalFrida, SignalXposed, SignalSubstrate,
		SignalPtrace, SignalDebuggerCheck, SignalEmulatorCheck,
		SignalDlopen,
	)

	switch {
	case hasGeo && hasRoot && hasAnti:
		files := ta.collectFilesForSignals(SignalGeoFence, SignalRootCheck)
		ta.signals.Correlations = append(ta.signals.Correlations, Correlation{
			Name:        "GEOFENCE_ROOT_COMBO",
			Description: "Geo-fencing + root detection + anti-analysis (banking trojan pattern)",
			Signals:     []SignalType{SignalGeoFence, SignalRootCheck},
			Files:       files,
			Score:       12,
			Severity:    SeverityCritical,
		})
		ta.signals.TotalScore += 12
	case hasGeo && hasRoot:
		files := ta.collectFilesForSignals(SignalGeoFence, SignalRootCheck)
		ta.signals.Correlations = append(ta.signals.Correlations, Correlation{
			Name:        "GEOFENCE_ROOT_COMBO",
			Description: "Geo-fencing combined with root detection (regional activation)",
			Signals:     []SignalType{SignalGeoFence, SignalRootCheck},
			Files:       files,
			Score:       6,
			Severity:    SeverityHigh,
		})
		ta.signals.TotalScore += 6
	}
}

// Hardcoded IP cluster: many IP hits → likely C2 list
func (ta *ThreatAggregator) correlateHardcodedIPCluster() {
	count := ta.signals.SignalCounts[SignalHardcodedIPv4]
	if count > 10 {
		files := ta.collectFilesForSignals(SignalHardcodedIPv4)
		ta.signals.Correlations = append(ta.signals.Correlations, Correlation{
			Name:        "HARDCODED_IP_CLUSTER",
			Description: "Multiple hardcoded IP addresses detected (>10) — possible C2 list",
			Signals:     []SignalType{SignalHardcodedIPv4},
			Files:       files,
			Score:       10,
			Severity:    SeverityHigh,
		})
		ta.signals.TotalScore += 10
	}
}

// Runtime-Load Chain: System.loadLibrary + RegisterNatives + DexClassLoader
// This is the hallmark of commercial packers (Qihoo 360, Bangcle, etc.)
// and sophisticated malware that hides logic in native code → JNI bridge → DEX injection.
func (ta *ThreatAggregator) correlateRuntimeLoadChain() {
	hasNativeLoad := ta.signals.HasAnyGlobal(
		SignalSystemLoadLibrary,
		SignalNativeJNIOnLoad,
	)

	hasJNIBridge := ta.signals.HasAnyGlobal(
		SignalRegisterNatives,
		SignalDlopen,
	)

	hasDexInjection := ta.signals.HasAnyGlobal(
		SignalDexClassLoader,
		SignalInMemoryDexClassLoader,
		SignalDexFileLoad,
		SignalEncryptedAssetDex,
		SignalAttachBaseContext,
	)

	if hasNativeLoad && hasJNIBridge && hasDexInjection {
		files := ta.collectFilesForSignals(
			SignalSystemLoadLibrary, SignalNativeJNIOnLoad,
			SignalRegisterNatives, SignalDlopen,
			SignalDexClassLoader, SignalInMemoryDexClassLoader,
			SignalEncryptedAssetDex, SignalAttachBaseContext,
		)

		ta.signals.Correlations = append(ta.signals.Correlations, Correlation{
			Name:        "RUNTIME_LOAD_CHAIN",
			Description: "Full runtime loading chain: native lib → JNI bridge → dynamic DEX injection (packer/malware pattern)",
			Signals: []SignalType{
				SignalSystemLoadLibrary, SignalRegisterNatives, SignalDexClassLoader,
			},
			Files:    files,
			Score:    SignalWeight[SignalRuntimeLoadChain],
			Severity: SeverityCritical,
		})

		ta.signals.TotalScore += SignalWeight[SignalRuntimeLoadChain]
	} else if hasNativeLoad && hasDexInjection {
		// Partial chain: native load + DEX injection (still very suspicious)
		files := ta.collectFilesForSignals(
			SignalSystemLoadLibrary, SignalNativeJNIOnLoad,
			SignalDexClassLoader, SignalInMemoryDexClassLoader,
			SignalEncryptedAssetDex, SignalAttachBaseContext,
		)

		ta.signals.Correlations = append(ta.signals.Correlations, Correlation{
			Name:        "RUNTIME_LOAD_PARTIAL",
			Description: "Native library loading combined with DEX injection (partial packer chain)",
			Signals: []SignalType{
				SignalSystemLoadLibrary, SignalDexClassLoader,
			},
			Files:    files,
			Score:    10,
			Severity: SeverityHigh,
		})

		ta.signals.TotalScore += 10
	}
}

// Helper: collect all files that have any of the given signals
func (ta *ThreatAggregator) collectFilesForSignals(sigs ...SignalType) []string {
	fileSet := make(map[string]struct{})
	for _, sig := range sigs {
		if files, ok := ta.signals.GlobalSignals[sig]; ok {
			for _, f := range files {
				fileSet[f] = struct{}{}
			}
		}
	}

	result := make([]string, 0, len(fileSet))
	for f := range fileSet {
		result = append(result, f)
	}
	return result
}

// ═══════════════════════════════════════════════════════════════════════════════
// CORRELATION TO MATCHES CONVERTER
// ═══════════════════════════════════════════════════════════════════════════════

// GenerateMatches converts correlations and signals to Match objects
func (ta *ThreatAggregator) GenerateMatches() []types.Match {
	var matches []types.Match

	// Add correlation matches first (highest priority)
	for _, corr := range ta.signals.Correlations {
		cat := correlationToCategory(corr.Name)
		for _, file := range corr.Files {
			matches = append(matches, newMatch(
				cat,
				file,
				0,
				corr.Description,
				corr.Name,
				true,
			))
		}
	}

	return matches
}

func correlationToCategory(name string) types.Category {
	switch name {
	case "DEX_FROM_NETWORK":
		return types.CategoryDexNetworkLoad
	case "WEBVIEW_JS_BRIDGE_REMOTE", "WEBVIEW_REMOTE_JS":
		return types.CategoryWebViewRemoteJS
	case "ACCESSIBILITY_ABUSE_FULL", "ACCESSIBILITY_SERVICE_ACTIVE":
		return types.CategoryStealerIndicator
	case "STEALER_PERMISSION_COMBO":
		return types.CategoryStealerIndicator
	case "REFLECTION_NETWORK_COMBO":
		return types.CategoryDynamicCodeLoad
	case "BASE64_OBFUSCATED_NETWORK":
		return types.CategoryObfuscatedCode
	case "ANTI_ANALYSIS_WITH_PAYLOAD":
		return types.CategorySuspiciousNativePayload
	case "GEOFENCE_ROOT_COMBO":
		return types.CategoryDynamicCodeLoad
	case "HARDCODED_IP_CLUSTER":
		return types.CategoryNetworkEndpoint
	case "RUNTIME_LOAD_CHAIN", "RUNTIME_LOAD_PARTIAL":
		return types.CategoryDynamicCodeLoad
	default:
		return types.CategoryStealerIndicator
	}
}
