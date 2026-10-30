package cfg

import (
	"strings"

	"mega-analyzer/pkg/internal/dexir"
)

// irSearchText renders the typed reference content of an instruction
// (method/field refs, type descriptors, string literals) as searchable
// text. Pattern detectors scan this instead of the raw instruction line;
// it covers every signature a pattern table matches against.
func irSearchText(ref InstructionRef) string {
	ir := ref.IR
	if ir == nil {
		return ref.Raw
	}
	var b strings.Builder
	if ir.Method != nil {
		b.WriteString(ir.Method.String())
	}
	if ir.Field != nil {
		b.WriteString(ir.Field.String())
	}
	if ir.Type != "" {
		b.WriteString(ir.Type)
	}
	if ir.HasStr {
		b.WriteString(ir.Str)
	}
	if b.Len() == 0 && ref.Raw != "" {
		return ref.Raw
	}
	return b.String()
}

// instrDisplayText renders a human-readable one-liner for reports.
func instrDisplayText(ref InstructionRef) string {
	ir := ref.IR
	if ir == nil {
		return ref.Opcode
	}
	switch {
	case ir.Method != nil:
		return ref.Opcode + " " + ir.Method.String()
	case ir.Field != nil:
		return ref.Opcode + " " + ir.Field.String()
	case ir.HasStr:
		return ref.Opcode + " \"" + ir.Str + "\""
	case ir.Type != "":
		return ref.Opcode + " " + ir.Type
	default:
		return ref.Opcode
	}
}

// constStringValue returns the string literal of a const-string
// instruction from the typed IR, or ("", false).
func constStringValue(ref InstructionRef) (string, bool) {
	ir := ref.IR
	if ir == nil || !ir.HasStr {
		if strings.HasPrefix(ref.Opcode, "const-string") || strings.HasPrefix(ref.Raw, "const-string") {
			if quoteStart := strings.IndexByte(ref.Raw, '"'); quoteStart >= 0 {
				if quoteEnd := strings.LastIndexByte(ref.Raw, '"'); quoteEnd > quoteStart {
					return ref.Raw[quoteStart+1 : quoteEnd], true
				}
			}
		}
		return "", false
	}
	if ir.Op != dexir.OpConstString && ir.Op != dexir.OpConstStringJumbo {
		return "", false
	}
	return ir.Str, true
}

// ═══════════════════════════════════════════════════════════════════════════════
// PATTERN ANALYZER - ULTIMATE EDITION
// ═══════════════════════════════════════════════════════════════════════════════
// NEW FEATURES:
//   • Anti-debugging pattern detection
//   • Emulator/VM detection patterns
//   • Cryptographic operation patterns
//   • Native code interaction patterns
//   • Reflection usage patterns
//   • String encryption patterns
//   • Tamper detection patterns
//   • Network/C2 communication patterns
// ═══════════════════════════════════════════════════════════════════════════════

type PatternAnalyzer struct {
	cfg *ControlFlowGraph
	dom *DominatorAnalyzer
}

func NewPatternAnalyzer(cfg *ControlFlowGraph) *PatternAnalyzer {
	return &PatternAnalyzer{cfg: cfg}
}

// ═══════════════════════════════════════════════════════════════════════════════
// ANTI-DEBUGGING PATTERNS
// ═══════════════════════════════════════════════════════════════════════════════

type AntiDebugPattern struct {
	Type        AntiDebugType
	Location    *CFGNode
	MethodCalls []string
	Severity    int // 1-10
	Description string
}

type AntiDebugType int

const (
	AntiDebugUnknown AntiDebugType = iota
	AntiDebugIsDebuggable
	AntiDebugTracerPid
	AntiDebugTimingCheck
	AntiDebugSignatureCheck
	AntiDebugNativeDebugger
	AntiDebugBreakpointDetect
)

func (p *PatternAnalyzer) FindAntiDebugPatterns() []*AntiDebugPattern {
	var patterns []*AntiDebugPattern

	for _, node := range p.cfg.Nodes {
		for _, instrRef := range node.Instructions {
			if strings.HasPrefix(instrRef.Opcode, "invoke") {
				pattern := p.checkAntiDebugInvoke(node, instrRef)
				if pattern != nil {
					patterns = append(patterns, pattern)
				}
			}
		}
	}

	return patterns
}

func (p *PatternAnalyzer) checkAntiDebugInvoke(node *CFGNode, instr InstructionRef) *AntiDebugPattern {
	methodSignatures := []struct {
		pattern  string
		adType   AntiDebugType
		severity int
		desc     string
	}{
		{"ApplicationInfo;->flags", AntiDebugIsDebuggable, 5, "Check for FLAG_DEBUGGABLE"},
		{"/proc/self/status", AntiDebugTracerPid, 8, "TracerPid check (ptrace detection)"},
		{"System;->currentTimeMillis", AntiDebugTimingCheck, 6, "Timing-based detection"},
		{"PackageManager;->getPackageInfo", AntiDebugSignatureCheck, 7, "Signature verification"},
		{"Debug;->isDebuggerConnected", AntiDebugIsDebuggable, 9, "Direct debugger check"},
		{"Debug;->waitingForDebugger", AntiDebugIsDebuggable, 9, "Debugger wait check"},
	}

	for _, sig := range methodSignatures {
		if strings.Contains(irSearchText(instr), sig.pattern) {
			return &AntiDebugPattern{
				Type:        sig.adType,
				Location:    node,
				MethodCalls: []string{instrDisplayText(instr)},
				Severity:    sig.severity,
				Description: sig.desc,
			}
		}
	}

	return nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// EMULATOR/VM DETECTION PATTERNS
// ═══════════════════════════════════════════════════════════════════════════════

type EmulatorPattern struct {
	Type        EmulatorCheckType
	Location    *CFGNode
	Indicators  []string
	Confidence  float64 // 0-1
	Description string
}

type EmulatorCheckType int

const (
	EmulatorCheckBuild EmulatorCheckType = iota
	EmulatorCheckFiles
	EmulatorCheckProps
	EmulatorCheckSensors
	EmulatorCheckCPU
	EmulatorCheckTelephony
)

func (p *PatternAnalyzer) FindEmulatorPatterns() []*EmulatorPattern {
	var patterns []*EmulatorPattern

	// Known emulator indicators
	emulatorStrings := []string{
		"generic", "unknown", "google_sdk", "Genymotion", "Andy",
		"/dev/socket/qemud", "/dev/qemu_pipe", "/system/lib/libc_malloc_debug_qemu.so",
		"goldfish", "ranchu", "vbox",
	}

	for _, node := range p.cfg.Nodes {
		for _, instrRef := range node.Instructions {
			raw := strings.ToLower(irSearchText(instrRef))

			for _, indicator := range emulatorStrings {
				if strings.Contains(raw, strings.ToLower(indicator)) {
					pattern := &EmulatorPattern{
						Type:        p.inferEmulatorCheckType(indicator),
						Location:    node,
						Indicators:  []string{indicator},
						Confidence:  0.8,
						Description: "Emulator detection string: " + indicator,
					}
					patterns = append(patterns, pattern)
					break
				}
			}
		}
	}

	return patterns
}

func (p *PatternAnalyzer) inferEmulatorCheckType(indicator string) EmulatorCheckType {
	switch {
	case strings.Contains(indicator, "generic"), strings.Contains(indicator, "sdk"):
		return EmulatorCheckBuild
	case strings.Contains(indicator, "/dev"), strings.Contains(indicator, "/system"):
		return EmulatorCheckFiles
	case strings.Contains(indicator, "goldfish"), strings.Contains(indicator, "ranchu"):
		return EmulatorCheckCPU
	default:
		return EmulatorCheckBuild
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CRYPTOGRAPHIC OPERATION PATTERNS
// ═══════════════════════════════════════════════════════════════════════════════

type CryptoPattern struct {
	Type      CryptoType
	Location  *CFGNode
	Algorithm string
	KeySource string
	IVSource  string
	Purpose   string
	Weakness  []string
}

type CryptoType int

const (
	CryptoEncryption CryptoType = iota
	CryptoDecryption
	CryptoHashing
	CryptoSignature
	CryptoKeyDerivation
)

func (p *PatternAnalyzer) FindCryptoPatterns() []*CryptoPattern {
	var patterns []*CryptoPattern

	cryptoAPIs := []struct {
		pattern string
		cType   CryptoType
	}{
		{"Cipher;->getInstance", CryptoEncryption},
		{"MessageDigest;->getInstance", CryptoHashing},
		{"Signature;->getInstance", CryptoSignature},
		{"SecretKeyFactory;->getInstance", CryptoKeyDerivation},
		{"Mac;->getInstance", CryptoHashing},
	}

	for _, node := range p.cfg.Nodes {
		for _, instrRef := range node.Instructions {
			for _, api := range cryptoAPIs {
				if strings.Contains(irSearchText(instrRef), api.pattern) {
					pattern := &CryptoPattern{
						Type:      api.cType,
						Location:  node,
						Algorithm: p.extractCryptoAlgorithm(node),
					}

					// Check for weaknesses
					pattern.Weakness = p.checkCryptoWeaknesses(pattern.Algorithm)

					patterns = append(patterns, pattern)
				}
			}
		}
	}

	return patterns
}

func (p *PatternAnalyzer) extractCryptoAlgorithm(node *CFGNode) string {
	// Look backward for const-string with algorithm name
	for i := len(node.Instructions) - 1; i >= 0; i-- {
		if s, ok := constStringValue(node.Instructions[i]); ok {
			return s
		}
	}
	return "unknown"
}

func (p *PatternAnalyzer) checkCryptoWeaknesses(algorithm string) []string {
	var weaknesses []string

	weakAlgorithms := map[string]string{
		"DES":  "Broken - use AES",
		"3DES": "Deprecated - use AES",
		"RC4":  "Broken stream cipher",
		"MD5":  "Cryptographically broken",
		"SHA1": "Deprecated - use SHA-256+",
		"ECB":  "Insecure mode - use CBC/GCM",
	}

	algUpper := strings.ToUpper(algorithm)
	for weak, reason := range weakAlgorithms {
		if strings.Contains(algUpper, weak) {
			weaknesses = append(weaknesses, reason)
		}
	}

	return weaknesses
}

// ═══════════════════════════════════════════════════════════════════════════════
// NATIVE CODE INTERACTION PATTERNS
// ═══════════════════════════════════════════════════════════════════════════════

type NativePattern struct {
	Type         NativeType
	Location     *CFGNode
	LibraryName  string
	FunctionName string
	Purpose      string
	Risk         int // 1-10
}

type NativeType int

const (
	NativeSystemLoad NativeType = iota
	NativeJNICall
	NativeExec
	NativePtrace
)

func (p *PatternAnalyzer) FindNativePatterns() []*NativePattern {
	var patterns []*NativePattern

	nativeAPIs := []struct {
		pattern string
		nType   NativeType
		risk    int
	}{
		{"System;->loadLibrary", NativeSystemLoad, 5},
		{"System;->load", NativeSystemLoad, 6},
		{"Runtime;->exec", NativeExec, 9},
		{"ProcessBuilder", NativeExec, 9},
		{"/system/bin/su", NativeExec, 10},
		{"ptrace", NativePtrace, 10},
	}

	for _, node := range p.cfg.Nodes {
		for _, instrRef := range node.Instructions {
			for _, api := range nativeAPIs {
				if strings.Contains(irSearchText(instrRef), api.pattern) {
					pattern := &NativePattern{
						Type:     api.nType,
						Location: node,
						Risk:     api.risk,
					}

					if api.nType == NativeSystemLoad {
						pattern.LibraryName = p.extractLibraryName(node)
					}

					patterns = append(patterns, pattern)
				}
			}
		}
	}

	return patterns
}

func (p *PatternAnalyzer) extractLibraryName(node *CFGNode) string {
	for i := len(node.Instructions) - 1; i >= 0; i-- {
		if s, ok := constStringValue(node.Instructions[i]); ok {
			return s
		}
	}
	return "unknown"
}

// ═══════════════════════════════════════════════════════════════════════════════
// REFLECTION USAGE PATTERNS
// ═══════════════════════════════════════════════════════════════════════════════

type ReflectionPattern struct {
	Type         ReflectionType
	Location     *CFGNode
	TargetClass  string
	TargetMethod string
	Purpose      string
	Suspicious   bool
}

type ReflectionType int

const (
	ReflectionClassForName ReflectionType = iota
	ReflectionGetMethod
	ReflectionGetField
	ReflectionInvoke
	ReflectionNewInstance
)

func (p *PatternAnalyzer) FindReflectionPatterns() []*ReflectionPattern {
	var patterns []*ReflectionPattern

	reflectionAPIs := []struct {
		pattern string
		rType   ReflectionType
	}{
		{"Class;->forName", ReflectionClassForName},
		{"Class;->getMethod", ReflectionGetMethod},
		{"Class;->getDeclaredMethod", ReflectionGetMethod},
		{"Class;->getField", ReflectionGetField},
		{"Method;->invoke", ReflectionInvoke},
		{"Constructor;->newInstance", ReflectionNewInstance},
	}

	for _, node := range p.cfg.Nodes {
		for _, instrRef := range node.Instructions {
			for _, api := range reflectionAPIs {
				if strings.Contains(irSearchText(instrRef), api.pattern) {
					pattern := &ReflectionPattern{
						Type:     api.rType,
						Location: node,
					}

					// Check if suspicious (accessing hidden APIs, etc.)
					pattern.Suspicious = p.isReflectionSuspicious(node)

					patterns = append(patterns, pattern)
				}
			}
		}
	}

	return patterns
}

func (p *PatternAnalyzer) isReflectionSuspicious(node *CFGNode) bool {
	suspiciousPatterns := []string{
		"android.os.ServiceManager",
		"com.android.internal",
		"setAccessible",
		"getDeclaredField",
	}

	for _, instr := range node.Instructions {
		for _, suspicious := range suspiciousPatterns {
			if strings.Contains(irSearchText(instr), suspicious) {
				return true
			}
		}
	}

	return false
}

// ═══════════════════════════════════════════════════════════════════════════════
// STRING ENCRYPTION PATTERNS
// ═══════════════════════════════════════════════════════════════════════════════

type StringEncryptionPattern struct {
	Location         *CFGNode
	DecryptionMethod string
	EncryptedStrings int
	Algorithm        string
}

func (p *PatternAnalyzer) FindStringEncryption() []*StringEncryptionPattern {
	var patterns []*StringEncryptionPattern

	// Look for patterns like:
	// const-string v0, "<encrypted>"
	// invoke-static {v0}, Ldecryptor;->decrypt(Ljava/lang/String;)Ljava/lang/String;

	for _, node := range p.cfg.Nodes {
		hasConstString := false
		hasDecryptCall := false
		var decryptMethod string

		for _, instr := range node.Instructions {
			if strings.Contains(instr.Opcode, "const-string") {
				hasConstString = true
			}

			text := irSearchText(instr)
			if strings.Contains(text, "decrypt") || strings.Contains(text, "deobfuscate") {
				hasDecryptCall = true
				decryptMethod = instrDisplayText(instr)
			}
		}

		if hasConstString && hasDecryptCall {
			pattern := &StringEncryptionPattern{
				Location:         node,
				DecryptionMethod: decryptMethod,
				EncryptedStrings: 1, // simplified
			}
			patterns = append(patterns, pattern)
		}
	}

	return patterns
}

// ═══════════════════════════════════════════════════════════════════════════════
// NETWORK/C2 COMMUNICATION PATTERNS
// ═══════════════════════════════════════════════════════════════════════════════

type NetworkPattern struct {
	Type       NetworkType
	Location   *CFGNode
	Protocol   string
	URL        string
	Encryption bool
	Suspicious bool
}

type NetworkType int

const (
	NetworkHTTP NetworkType = iota
	NetworkSocket
	NetworkWebSocket
	NetworkCustom
)

func (p *PatternAnalyzer) FindNetworkPatterns() []*NetworkPattern {
	var patterns []*NetworkPattern

	networkAPIs := []struct {
		pattern string
		nType   NetworkType
	}{
		{"HttpURLConnection", NetworkHTTP},
		{"OkHttpClient", NetworkHTTP},
		{"Socket;-><init>", NetworkSocket},
		{"WebSocket", NetworkWebSocket},
	}

	for _, node := range p.cfg.Nodes {
		for _, instr := range node.Instructions {
			for _, api := range networkAPIs {
				if strings.Contains(irSearchText(instr), api.pattern) {
					pattern := &NetworkPattern{
						Type:     api.nType,
						Location: node,
					}

					// Check for encryption
					pattern.Encryption = p.hasSSLContext(node)

					// Check if suspicious (hardcoded IPs, non-standard ports)
					pattern.Suspicious = p.isNetworkSuspicious(node)

					patterns = append(patterns, pattern)
				}
			}
		}
	}

	return patterns
}

func (p *PatternAnalyzer) hasSSLContext(node *CFGNode) bool {
	for _, instr := range node.Instructions {
		text := irSearchText(instr)
		if strings.Contains(text, "SSLContext") || strings.Contains(text, "https") {
			return true
		}
	}
	return false
}

func (p *PatternAnalyzer) isNetworkSuspicious(node *CFGNode) bool {
	suspiciousPatterns := []string{
		// Hardcoded IPs
		"192.168", "10.0", "172.16",
		// Non-standard ports
		":8080", ":4444", ":31337",
		// Tor/proxy
		"socks", "proxy", ".onion",
	}

	for _, instr := range node.Instructions {
		raw := strings.ToLower(irSearchText(instr))
		for _, suspicious := range suspiciousPatterns {
			if strings.Contains(raw, suspicious) {
				return true
			}
		}
	}

	return false
}

// ═══════════════════════════════════════════════════════════════════════════════
// TAMPER DETECTION PATTERNS
// ═══════════════════════════════════════════════════════════════════════════════

type TamperPattern struct {
	Type        TamperType
	Location    *CFGNode
	Description string
	Severity    int
}

type TamperType int

const (
	TamperSignature TamperType = iota
	TamperChecksum
	TamperInstaller
	TamperNativeLib
)

func (p *PatternAnalyzer) FindTamperPatterns() []*TamperPattern {
	var patterns []*TamperPattern

	tamperAPIs := []struct {
		pattern  string
		tType    TamperType
		severity int
	}{
		{"getPackageInfo", TamperSignature, 7},
		{"GET_SIGNATURES", TamperSignature, 8},
		{"getInstallerPackageName", TamperInstaller, 6},
		{"CRC", TamperChecksum, 7},
		{"MessageDigest", TamperChecksum, 6},
	}

	for _, node := range p.cfg.Nodes {
		for _, instr := range node.Instructions {
			for _, api := range tamperAPIs {
				if strings.Contains(irSearchText(instr), api.pattern) {
					pattern := &TamperPattern{
						Type:        api.tType,
						Location:    node,
						Description: "Tamper detection: " + api.pattern,
						Severity:    api.severity,
					}
					patterns = append(patterns, pattern)
				}
			}
		}
	}

	return patterns
}

// ═══════════════════════════════════════════════════════════════════════════════
// ULTIMATE PATTERN SUMMARY
// ═══════════════════════════════════════════════════════════════════════════════

type UltimatePatternSummary struct {
	Guards           []*GuardInfo
	Funnels          []*FunnelInfo
	AntiDebug        []*AntiDebugPattern
	Emulator         []*EmulatorPattern
	Crypto           []*CryptoPattern
	Native           []*NativePattern
	Reflection       []*ReflectionPattern
	StringEncryption []*StringEncryptionPattern
	Network          []*NetworkPattern
	Tamper           []*TamperPattern

	TotalPatterns     int
	RiskScore         float64 // 0-100
	MalwareIndicators []string
}

func (p *PatternAnalyzer) FindAllPatterns() UltimatePatternSummary {
	summary := UltimatePatternSummary{
		Guards:           p.FindGuards(),
		Funnels:          p.FindFunnels(),
		AntiDebug:        p.FindAntiDebugPatterns(),
		Emulator:         p.FindEmulatorPatterns(),
		Crypto:           p.FindCryptoPatterns(),
		Native:           p.FindNativePatterns(),
		Reflection:       p.FindReflectionPatterns(),
		StringEncryption: p.FindStringEncryption(),
		Network:          p.FindNetworkPatterns(),
		Tamper:           p.FindTamperPatterns(),
	}

	summary.TotalPatterns = len(summary.Guards) + len(summary.Funnels) +
		len(summary.AntiDebug) + len(summary.Emulator) +
		len(summary.Crypto) + len(summary.Native) +
		len(summary.Reflection) + len(summary.StringEncryption) +
		len(summary.Network) + len(summary.Tamper)

	// Calculate risk score
	summary.RiskScore = p.calculateRiskScore(&summary)
	summary.MalwareIndicators = p.identifyMalwareIndicators(&summary)

	return summary
}

func (p *PatternAnalyzer) calculateRiskScore(summary *UltimatePatternSummary) float64 {
	score := 0.0

	// Anti-debug patterns (high risk)
	for _, ad := range summary.AntiDebug {
		score += float64(ad.Severity)
	}

	// Native code execution (medium-high risk)
	for _, nat := range summary.Native {
		score += float64(nat.Risk)
	}

	// Suspicious network activity
	for _, net := range summary.Network {
		if net.Suspicious {
			score += 15.0
		}
	}

	// String encryption (obfuscation indicator)
	score += float64(len(summary.StringEncryption)) * 5.0

	// Suspicious reflection
	for _, ref := range summary.Reflection {
		if ref.Suspicious {
			score += 8.0
		}
	}

	// Emulator detection (anti-analysis)
	score += float64(len(summary.Emulator)) * 10.0

	// Normalize to 0-100
	if score > 100 {
		score = 100
	}

	return score
}

func (p *PatternAnalyzer) identifyMalwareIndicators(summary *UltimatePatternSummary) []string {
	var indicators []string

	if len(summary.AntiDebug) > 2 {
		indicators = append(indicators, "Multiple anti-debug techniques")
	}

	if len(summary.Emulator) > 3 {
		indicators = append(indicators, "Extensive emulator detection")
	}

	for _, net := range summary.Network {
		if net.Suspicious {
			indicators = append(indicators, "Suspicious network communication")
			break
		}
	}

	for _, nat := range summary.Native {
		if nat.Risk >= 9 {
			indicators = append(indicators, "High-risk native code execution")
			break
		}
	}

	if len(summary.StringEncryption) > 5 {
		indicators = append(indicators, "Heavy string obfuscation")
	}

	return indicators
}

// ═══════════════════════════════════════════════════════════════════════════════
// PATH-SENSITIVE GUARD DETECTION (from original)
// ═══════════════════════════════════════════════════════════════════════════════

func (p *PatternAnalyzer) FindGuards() []*GuardInfo {
	if p.cfg == nil {
		return nil
	}

	if p.dom == nil {
		p.dom = NewDominatorAnalyzer(p.cfg)
		p.dom.ComputeDominators()
		p.dom.ComputePostDominators()
	}

	var guards []*GuardInfo

	for _, node := range p.cfg.Nodes {
		if node.Type != NodeTypeCondition {
			continue
		}

		guard := p.checkPathSensitiveGuard(node)
		if guard != nil {
			guards = append(guards, guard)
			node.IsGuard = true
			node.Type = NodeTypeGuard
			node.GuardInfo = guard
		}
	}

	p.cfg.Guards = guards
	return guards
}

func (p *PatternAnalyzer) checkPathSensitiveGuard(condNode *CFGNode) *GuardInfo {
	for _, succ := range condNode.Successors {
		exitNode := p.findReachableExit(succ, 5)
		if exitNode == nil {
			continue
		}

		dominates := p.dom.Dominates(condNode, exitNode)
		postDoms := p.dom.PostDominates(exitNode, condNode)

		if !dominates {
			continue
		}

		edge := p.cfg.FindEdge(condNode, succ)
		if edge == nil {
			continue
		}

		guard := &GuardInfo{
			Condition:     condNode.Condition,
			GuardEdge:     edge.Type,
			ActionNode:    exitNode,
			ActionType:    exitNode.Type,
			DominatesExit: dominates,
			ExitPostDoms:  postDoms,
		}

		guard.Meaning = p.inferConditionMeaning(condNode)
		guard.Description = p.buildGuardDescription(guard)

		return guard
	}

	return nil
}

func (p *PatternAnalyzer) findReachableExit(start *CFGNode, maxDepth int) *CFGNode {
	if start.Type.IsTerminator() {
		return start
	}

	if maxDepth <= 0 {
		return nil
	}

	visited := make(map[int]bool)
	queue := []*CFGNode{start}
	depth := 0

	for len(queue) > 0 && depth < maxDepth {
		nextQueue := make([]*CFGNode, 0)

		for _, node := range queue {
			if visited[node.ID] {
				continue
			}
			visited[node.ID] = true

			if node.Type.IsTerminator() {
				return node
			}

			nextQueue = append(nextQueue, node.Successors...)
		}

		queue = nextQueue
		depth++
	}

	return nil
}

func (p *PatternAnalyzer) inferConditionMeaning(node *CFGNode) ConditionMeaning {
	if node.Condition == nil {
		return MeaningUnknown
	}

	if node.Condition.LHS != nil {
		return p.inferValueMeaning(node.Condition.LHS)
	}

	return MeaningUnknown
}

func (p *PatternAnalyzer) inferValueMeaning(val *ValueRef) ConditionMeaning {
	if val == nil {
		return MeaningUnknown
	}

	keywords := map[string]ConditionMeaning{
		"license":    MeaningLicenseCheck,
		"licensed":   MeaningLicenseCheck,
		"premium":    MeaningPremiumCheck,
		"pro":        MeaningPremiumCheck,
		"purchase":   MeaningPurchaseCheck,
		"bought":     MeaningPurchaseCheck,
		"trial":      MeaningTrialCheck,
		"expired":    MeaningTrialCheck,
		"root":       MeaningRootCheck,
		"rooted":     MeaningRootCheck,
		"debug":      MeaningDebugCheck,
		"debuggable": MeaningDebugCheck,
	}

	if val.Kind == ValueInvoke {
		for kw, meaning := range keywords {
			if containsAny(val.InvokeMethod, kw) {
				return meaning
			}
		}
	}

	if val.Kind == ValueField {
		for kw, meaning := range keywords {
			if containsAny(val.FieldName, kw) {
				return meaning
			}
		}
	}

	return MeaningUnknown
}

func (p *PatternAnalyzer) buildGuardDescription(guard *GuardInfo) string {
	var desc string

	if guard.Condition.LHS != nil {
		desc = guard.Condition.LHS.String()
	} else {
		desc = guard.Condition.Register1
	}

	if guard.GuardEdge == EdgeTrue {
		desc = "!" + desc
	}

	desc += " → " + guard.ActionType.String()

	if guard.ExitPostDoms {
		desc += " (guaranteed)"
	}

	return desc
}

// FindFunnels (from original)
func (p *PatternAnalyzer) FindFunnels() []*FunnelInfo {
	if p.cfg == nil {
		return nil
	}

	var funnels []*FunnelInfo

	for _, exit := range p.cfg.Exits {
		if exit.Type != NodeTypeReturn {
			continue
		}

		funnel := p.checkFunnel(exit)
		if funnel != nil {
			funnels = append(funnels, funnel)
			exit.IsFunnel = true
			exit.FunnelInfo = funnel
		}
	}

	p.cfg.Funnels = funnels
	return funnels
}

func (p *PatternAnalyzer) checkFunnel(returnNode *CFGNode) *FunnelInfo {
	conditions := p.collectConditionPredecessors(returnNode, 10)

	if len(conditions) < 2 {
		return nil
	}

	funnel := &FunnelInfo{
		SourceNodes: conditions,
		Conditions:  make([]*ConditionInfo, 0),
		ReturnValue: returnNode.ReturnValue,
	}

	for _, node := range conditions {
		if node.Condition != nil {
			funnel.Conditions = append(funnel.Conditions, node.Condition)
		}
	}

	p.analyzeFunnelType(funnel, returnNode)
	funnel.Purpose = p.inferFunnelPurpose(funnel)

	return funnel
}

func (p *PatternAnalyzer) collectConditionPredecessors(node *CFGNode, maxDepth int) []*CFGNode {
	var conditions []*CFGNode
	visited := make(map[int]bool)

	var dfs func(n *CFGNode, depth int)
	dfs = func(n *CFGNode, depth int) {
		if depth <= 0 || visited[n.ID] {
			return
		}
		visited[n.ID] = true

		if n.Type == NodeTypeCondition || n.Type == NodeTypeGuard {
			conditions = append(conditions, n)
		}

		for _, pred := range n.Predecessors {
			dfs(pred, depth-1)
		}
	}

	for _, pred := range node.Predecessors {
		dfs(pred, maxDepth)
	}

	return conditions
}

func (p *PatternAnalyzer) analyzeFunnelType(funnel *FunnelInfo, returnNode *CFGNode) {
	if funnel == nil || returnNode == nil {
		return
	}

	trueCount := 0
	falseCount := 0

	for _, condNode := range funnel.SourceNodes {
		edgeType := p.findEdgeToReturn(condNode, returnNode, 8)
		switch edgeType {
		case EdgeTrue:
			trueCount++
		case EdgeFalse:
			falseCount++
		}
	}

	switch {
	case trueCount > 0 && falseCount == 0:
		funnel.RequiresAllTrue = true
	case falseCount > 0 && trueCount == 0:
		funnel.RequiresAnyFalse = true
	case trueCount >= falseCount:
		funnel.RequiresAllTrue = true
	default:
		funnel.RequiresAnyFalse = true
	}
}

func (p *PatternAnalyzer) findEdgeToReturn(condNode *CFGNode, returnNode *CFGNode, maxDepth int) EdgeType {
	if condNode == nil || returnNode == nil || p.cfg == nil {
		return EdgeFallthrough
	}
	for _, succ := range condNode.Successors {
		if succ == nil {
			continue
		}
		if succ == returnNode || p.canReachNode(succ, returnNode, maxDepth) {
			if edge := p.cfg.FindEdge(condNode, succ); edge != nil {
				return edge.Type
			}
		}
	}
	return EdgeFallthrough
}

func (p *PatternAnalyzer) canReachNode(start *CFGNode, target *CFGNode, maxDepth int) bool {
	if start == nil || target == nil {
		return false
	}
	if start == target {
		return true
	}
	if maxDepth <= 0 {
		return false
	}

	visited := make(map[int]bool)
	queue := []*CFGNode{start}
	depth := 0

	for len(queue) > 0 && depth < maxDepth {
		nextQueue := make([]*CFGNode, 0)
		for _, node := range queue {
			if node == nil || visited[node.ID] {
				continue
			}
			visited[node.ID] = true
			if node == target {
				return true
			}
			nextQueue = append(nextQueue, node.Successors...)
		}
		queue = nextQueue
		depth++
	}

	return false
}

func (p *PatternAnalyzer) inferFunnelPurpose(funnel *FunnelInfo) string {
	if funnel == nil || len(funnel.Conditions) == 0 {
		return "unknown"
	}

	counts := make(map[ConditionMeaning]int)
	for _, cond := range funnel.Conditions {
		if cond == nil {
			continue
		}
		meaning := cond.Meaning
		if meaning == MeaningUnknown && cond.LHS != nil {
			meaning = p.inferValueMeaning(cond.LHS)
		}
		if meaning != MeaningUnknown {
			counts[meaning]++
		}
	}

	if len(counts) == 0 {
		return "unknown"
	}

	var topMeaning ConditionMeaning
	topCount := 0
	for m, c := range counts {
		if c > topCount {
			topMeaning = m
			topCount = c
		}
	}

	switch topMeaning {
	case MeaningLicenseCheck:
		return "license check"
	case MeaningPremiumCheck:
		return "premium check"
	case MeaningPurchaseCheck:
		return "purchase check"
	case MeaningTrialCheck:
		return "trial/expiry check"
	case MeaningRootCheck:
		return "root check"
	case MeaningDebugCheck:
		return "debug check"
	case MeaningNullCheck:
		return "null check"
	default:
		return "unknown"
	}
}

func containsAny(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}
