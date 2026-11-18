package pipeline

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"mega-analyzer/pkg/internal/finding"
	"mega-analyzer/pkg/internal/matcher"
	"mega-analyzer/pkg/internal/networkrefs"
	"mega-analyzer/pkg/internal/types"
)

// ═══════════════════════════════════════════════════════════════════════════════
// THREAT INDICATORS DETECTOR v3 — AC-powered
// ═══════════════════════════════════════════════════════════════════════════════
//
// Архитектура:
//   1. При создании детектора строим Aho-Corasick автоматы из ВСЕХ паттернов
//   2. При Detect: один проход AC → какие паттерны ЕСТЬ → обрабатываем только их
//   3. Regex (IPv4, TLD, Base64) — отдельно (AC для них не подходит)
//
// Раньше: ~100 паттернов × bytes.Index(100KB) = 10 000 000 ops
// Теперь: 1 × AC(100KB) + M × bytes.Index = ~150 000 ops (если M=5)
// Ускорение: ~60x для файлов без угроз, ~15x для файлов с угрозами

type ThreatIndicatorsDetector struct {
	aggregator   *ThreatAggregator
	aggregatorMu sync.Mutex

	// ── Pre-built AC automata ────────────────────────────────────────────
	smaliAC     *threatAC
	manifestAC  *threatAC
	nativeAC    *threatAC
	ipContextAC *matcher.AhoCorasick // для getIPContext
}

// threatACEntry — запись в AC автомате для threat patterns
type threatACEntry struct {
	patternLower  []byte
	signal        SignalType
	context       string
	group         string // имя группы паттернов (для break после первого match)
	caseSensitive bool   // для native patterns
}

// threatAC — Aho-Corasick + метаданные для threat detection
type threatAC struct {
	ac      *matcher.AhoCorasick
	entries []threatACEntry
}

// newThreatAC строит AC из threat паттернов
func newThreatAC(entries []threatACEntry) *threatAC {
	if len(entries) == 0 {
		return nil
	}
	patterns := make([]string, len(entries))
	for i, e := range entries {
		patterns[i] = string(e.patternLower)
	}
	return &threatAC{
		ac:      matcher.NewAhoCorasick(patterns),
		entries: entries,
	}
}

func NewThreatIndicatorsDetector() *ThreatIndicatorsDetector {
	d := &ThreatIndicatorsDetector{
		aggregator: NewThreatAggregator(),
	}
	d.buildSmaliAC()
	d.buildManifestAC()
	d.buildNativeAC()
	d.buildIPContextAC()
	return d
}

func (d *ThreatIndicatorsDetector) Name() string { return "threat_indicators_v3" }

func (d *ThreatIndicatorsDetector) GetAggregator() *ThreatAggregator {
	return d.aggregator
}

func (d *ThreatIndicatorsDetector) Reset() {
	d.aggregatorMu.Lock()
	defer d.aggregatorMu.Unlock()
	d.aggregator = NewThreatAggregator()
}

// ═══════════════════════════════════════════════════════════════════════════════
// BUILD AC AUTOMATA — один раз при создании детектора
// ═══════════════════════════════════════════════════════════════════════════════

func (d *ThreatIndicatorsDetector) buildSmaliAC() {
	var entries []threatACEntry

	for _, group := range SmaliPatterns {
		for _, sp := range group.Patterns {
			groupKey := sp.Context // используем Context как ключ группы
			for _, pattern := range sp.Patterns {
				entries = append(entries, threatACEntry{
					patternLower: pattern, // уже lowercase в SmaliPatterns
					signal:       sp.Signal,
					context:      sp.Context,
					group:        groupKey,
				})
			}
		}
	}

	d.smaliAC = newThreatAC(entries)
}

func (d *ThreatIndicatorsDetector) buildManifestAC() {
	var entries []threatACEntry

	for _, group := range ManifestPatterns {
		for _, sp := range group.Patterns {
			groupKey := sp.Context
			for _, pattern := range sp.Patterns {
				entries = append(entries, threatACEntry{
					patternLower: pattern,
					signal:       sp.Signal,
					context:      sp.Context,
					group:        groupKey,
				})
			}
		}
	}

	d.manifestAC = newThreatAC(entries)
}

func (d *ThreatIndicatorsDetector) buildNativeAC() {
	var entries []threatACEntry

	for _, group := range NativePatterns {
		for _, sp := range group.Patterns {
			groupKey := sp.Context
			for _, pattern := range sp.Patterns {
				entries = append(entries, threatACEntry{
					patternLower:  bytes.ToLower(pattern), // AC работает с lowercase
					signal:        sp.Signal,
					context:       sp.Context,
					group:         groupKey,
					caseSensitive: true, // native = case-sensitive поиск
				})
			}
		}
	}

	d.nativeAC = newThreatAC(entries)
}

func (d *ThreatIndicatorsDetector) buildIPContextAC() {
	contextPatterns := []string{
		"httpurlconnection", "okhttp",
		"->openconnection", "url;->",
	}
	d.ipContextAC = matcher.NewAhoCorasick(contextPatterns)
}

// ═══════════════════════════════════════════════════════════════════════════════
// DETECT — главный метод
// ═══════════════════════════════════════════════════════════════════════════════

func (d *ThreatIndicatorsDetector) Detect(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	fs := NewFileSignals(ctx.Path)

	switch ctx.FileType {
	case types.FileTypeSmali:
		d.detectSmali(ctx, fs, analysis)
	case types.FileTypeXML:
		d.detectManifest(ctx, fs, analysis)
	case types.FileTypeNative:
		d.detectNative(ctx, fs, analysis)
	}

	// Агрегация для cross-file корреляции
	// P18c: drop dex-loader signals the AST resolver disproved, so no
	// cross-file correlation (RUNTIME_LOAD_CHAIN / RUNTIME_LOAD_PARTIAL)
	// can resurrect DYNAMIC_LOAD for a literal app-private path.
	suppressRefutedDexLoaderSignals(ctx, fs)
	if len(fs.Signals) > 0 {
		d.aggregatorMu.Lock()
		d.aggregator.AddFileSignals(fs)
		d.aggregatorMu.Unlock()
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// SMALI DETECTION — AC-powered
// ═══════════════════════════════════════════════════════════════════════════════

func (d *ThreatIndicatorsDetector) detectSmali(ctx *FileDetectContext, fs *FileSignals, analysis *types.FileAnalysis) {
	// ── Phase 1: AC — один проход, все паттерны сразу ─────────────────────
	if d.smaliAC != nil {
		d.detectWithThreatAC(d.smaliAC, ctx.ContentLower, ctx, fs, analysis, false)
	}

	// ── Phase 2: Regex-based (AC не подходит для regex) ───────────────────
	d.detectIPv4(ctx, fs, analysis)
	d.detectSuspiciousTLD(ctx, fs, analysis)
	d.detectBase64Strings(ctx, fs, analysis)
}

// ═══════════════════════════════════════════════════════════════════════════════
// MANIFEST DETECTION — AC-powered
// ═══════════════════════════════════════════════════════════════════════════════

func (d *ThreatIndicatorsDetector) detectManifest(ctx *FileDetectContext, fs *FileSignals, analysis *types.FileAnalysis) {
	pathLower := strings.ToLower(ctx.Path)
	if !strings.HasSuffix(pathLower, "androidmanifest.xml") {
		return
	}

	if d.manifestAC != nil {
		d.detectManifestWithAC(ctx, fs, analysis)
	}
}

func (d *ThreatIndicatorsDetector) detectManifestWithAC(ctx *FileDetectContext, fs *FileSignals, analysis *types.FileAnalysis) {
	ac := d.manifestAC

	// Early exit: есть ли ВООБЩЕ что-то?
	if !ac.ac.ContainsAnyBytes(ctx.ContentLower) {
		return
	}

	// Найти все совпадения
	found := ac.ac.SearchBytes(ctx.ContentLower)
	seenGroups := make(map[string]bool, len(found))
	declarations := make(map[string]rulesPermissionWitness)
	for _, source := range manifestPermissionSources(ctx.Content, analysis.Path) {
		declarations[strings.ToLower(source.Snippet)] = rulesPermissionWitness{line: source.Line, snippet: source.Snippet}
	}

	for _, patIdx := range found {
		if patIdx < 0 || patIdx >= len(ac.entries) {
			continue
		}
		e := &ac.entries[patIdx]
		declaration, declared := declarations[string(e.patternLower)]
		if !declared {
			continue
		}

		// Group dedup: один match на группу паттернов
		if e.group != "" && seenGroups[e.group] {
			continue
		}
		if e.group != "" {
			seenGroups[e.group] = true
		}

		fs.Add(e.signal, declaration.line, e.context, declaration.snippet)
		match := newMatch(types.CategoryManifestPermission, analysis.Path, declaration.line,
			"Declared permission: "+declaration.snippet, declaration.snippet, false)
		match.Severity, match.EvidenceType = types.SeverityInfo, "permission_declaration"
		match.Explanation = &finding.Explanation{Status: "observation", Summary: match.Context,
			Limitations: []string{"A manifest declaration does not establish a granted permission, collection, transmission or malware behavior."}}
		analysis.Matches = append(analysis.Matches, match)
	}
}

type rulesPermissionWitness struct {
	line    int
	snippet string
}

// ═══════════════════════════════════════════════════════════════════════════════
// NATIVE DETECTION — AC-powered
// ═══════════════════════════════════════════════════════════════════════════════

func (d *ThreatIndicatorsDetector) detectNative(ctx *FileDetectContext, fs *FileSignals, analysis *types.FileAnalysis) {
	if d.nativeAC == nil {
		return
	}

	// Names and embedded version strings do not authenticate native code.
	// Scan the entire binary until a verified content baseline is available.
	const maxHits = 10

	// AC prefilters folded content; witnesses are resolved in original bytes.
	found := d.nativeAC.ac.SearchBytes(ctx.ContentLower)
	if len(found) == 0 {
		return
	}

	hitCount := 0
	seenGroups := make(map[string]bool, len(found))
	var witnesses []finding.Evidence

	for _, patIdx := range found {
		if hitCount >= maxHits {
			break
		}
		if patIdx < 0 || patIdx >= len(d.nativeAC.entries) {
			continue
		}
		e := &d.nativeAC.entries[patIdx]

		if e.group != "" && seenGroups[e.group] {
			continue
		}

		// Unicode lowercasing can change byte lengths in binary data. Resolve
		// the witness in original bytes with ASCII folding to retain its offset.
		idx := nativeStringIndex(ctx.Content, e.patternLower)

		if idx < 0 {
			continue
		}

		if e.group != "" {
			seenGroups[e.group] = true
		}

		line := lineAt(ctx.LineOffsets, idx)
		matched := string(ctx.Content[idx : idx+len(e.patternLower)])
		fs.Add(e.signal, line, e.context, matched)
		hitCount++
		witnesses = append(witnesses, finding.NewEvidence("native_string",
			fmt.Sprintf("%s string at byte offset 0x%x", e.context, idx), matched, finding.Location{File: analysis.Path}))

		if e.signal == SignalNativeDexLoader {
			analysis.Matches = append(analysis.Matches, nativeDexReference(analysis.Path, matched, idx))
		} else if e.signal == SignalFrida || e.signal == SignalXposed || e.signal == SignalSubstrate {
			analysis.Matches = append(analysis.Matches, nativeInstrumentationReference(analysis.Path, matched, idx))
		} else if isHighPriorityNative(e.signal) {
			analysis.Matches = append(analysis.Matches, newMatch(
				types.CategorySuspiciousNativePayload,
				analysis.Path, line,
				e.context, matched,
				true,
			))
		}
	}

	// Co-present strings are retained, but do not prove a connected payload.
	if fs.HasAny(SignalFrida, SignalXposed, SignalPtrace) &&
		fs.HasAny(SignalNativeC2, SignalNativeHTTP, SignalNativeDexLoader) {
		m := newMatch(
			types.CategorySuspiciousNativePayload,
			analysis.Path, 0,
			"Native instrumentation and loader/network string references",
			"ANTI_ANALYSIS+PAYLOAD",
			false,
		)
		m.Score, m.Severity = 0, types.SeverityInfo
		if m.Metadata == nil {
			m.Metadata = make(map[string]string)
		}
		m.Metadata["finding_kind"] = "inventory"
		m.EvidenceType, m.Evidence = "native_string_combination", witnesses
		m.Explanation = &finding.Explanation{Status: "observation", Summary: m.Context,
			Limitations: []string{"The strings coexist in one native file; no common execution path, loader input, request or malicious payload is established by their co-presence."},
			NextChecks:  []string{"Trace native cross-references from reachable JNI entries to the loader/network calls and identify their inputs."}}
		analysis.Matches = append(analysis.Matches, m)
	}
}

func accessibilityInvokeWitness(ctx *FileDetectContext, sig SignalType) (finding.Evidence, bool) {
	method := "getRootInActiveWindow"
	if sig == SignalAccessibilityGlobalAction {
		method = "performGlobalAction"
	}
	if ctx.Class != nil {
		for _, m := range ctx.Class.Methods {
			for _, inv := range m.Invokes {
				if inv.Method == method {
					loc := finding.Location{File: ctx.Path, Line: inv.Line, Class: ctx.Class.Name, Method: m.Name}
					return finding.NewEvidence("api_call", method+" invocation", firstNonEmpty(inv.Raw, inv.FullSignature()), loc), true
				}
			}
		}
		return finding.Evidence{}, false
	}
	// Compact inputs may lack an AST. An actual invoke line is still required;
	// a declaration, comment or string containing the method name is not a call.
	for i, line := range bytes.Split(ctx.Content, []byte{'\n'}) {
		code := strings.TrimSpace(string(line))
		if strings.HasPrefix(code, "invoke-") && strings.Contains(code, ";->"+method+"(") {
			loc := finding.Location{File: ctx.Path, Line: i + 1}
			return finding.NewEvidence("api_call", method+" invocation", code, loc), true
		}
	}
	return finding.Evidence{}, false
}

// ═══════════════════════════════════════════════════════════════════════════════
// GENERIC AC DETECTION — общий метод для smali/manifest/native
// ═══════════════════════════════════════════════════════════════════════════════

func (d *ThreatIndicatorsDetector) detectWithThreatAC(
	tac *threatAC,
	contentLower []byte,
	ctx *FileDetectContext,
	fs *FileSignals,
	analysis *types.FileAnalysis,
	_ bool,
) {
	// Early exit
	if !tac.ac.ContainsAnyBytes(contentLower) {
		return
	}

	found := tac.ac.SearchBytes(contentLower)
	seenGroups := make(map[string]bool, len(found))

	for _, patIdx := range found {
		if patIdx < 0 || patIdx >= len(tac.entries) {
			continue
		}
		e := &tac.entries[patIdx]

		// Group dedup
		if e.group != "" && seenGroups[e.group] {
			continue
		}
		if e.group != "" {
			seenGroups[e.group] = true
		}

		// Получаем позицию для номера строки
		idx := bytes.Index(contentLower, e.patternLower)
		if idx < 0 {
			continue
		}

		line := lineAt(ctx.LineOffsets, idx)
		if e.signal == SignalAccessibilityRootWindow || e.signal == SignalAccessibilityGlobalAction {
			witness, ok := accessibilityInvokeWitness(ctx, e.signal)
			if !ok {
				continue
			}
			line = witness.Location.Line
			fs.Add(e.signal, line, e.context, witness.Snippet)
			match := newMatch(types.CategoryAccessibilityCapability, analysis.Path, line, e.context+" API reference", witness.Snippet, false)
			match.Severity, match.EvidenceType = types.SeverityInfo, "api_capability"
			match.Evidence = []finding.Evidence{witness}
			match.Explanation = &finding.Explanation{Status: "observation", Summary: match.Context,
				Limitations: []string{"The call does not identify the target UI, collected data, remote command source or malicious intent."}}
			analysis.Matches = append(analysis.Matches, match)
			continue
		}
		fs.Add(e.signal, line, e.context, string(e.patternLower))

		// Немедленный match для высокоприоритетных сигналов
		if shouldEmitImmediate(e.signal) {
			analysis.Matches = append(analysis.Matches, newMatch(
				signalToCategory(e.signal),
				analysis.Path, line,
				e.context, string(e.patternLower),
				true,
			))
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// REGEX DETECTIONS (IPv4, TLD, Base64)
// ═══════════════════════════════════════════════════════════════════════════════

func (d *ThreatIndicatorsDetector) detectIPv4(ctx *FileDetectContext, fs *FileSignals, analysis *types.FileAnalysis) {
	if !ctx.HasDigits() { // используем кешированную проверку!
		return
	}
	if inOIDPackage(analysis.Path) { // dotted OID constants are the content here
		return
	}

	const maxIPsPerFile = 8
	matches := CompiledPatterns.IPv4.FindAllIndex(ctx.Content, maxIPsPerFile*2)

	emitted := 0
	for _, m := range matches {
		if emitted >= maxIPsPerFile {
			break
		}

		ip := string(ctx.Content[m[0]:m[1]])
		// The `\b` regex cannot tell an address from a longer dotted number:
		// inside the OID 2.16.840.1.101.3.4.2.1 the fragment 1.101.3.4 is
		// surrounded by dots, not by word boundaries. Reject any candidate
		// that is glued to more digits or dots on either side.
		if !isStandaloneDottedNumber(ctx.Content, m[0], m[1]) {
			continue
		}
		if isWellKnownOID(ip) {
			continue
		}
		if role := networkrefs.ResolverRole(ip); role != "" {
			match := newMatch(types.CategoryHardcodedIP, analysis.Path, lineAt(ctx.LineOffsets, m[0]), role, ip, false)
			match.Severity, match.Confidence, match.EvidenceType = types.SeverityInfo, "high", "address_inventory"
			match.Metadata = map[string]string{"network_role": role, "host": ip, "title": role}
			analysis.Matches = append(analysis.Matches, match)
			emitted++
			continue
		}
		if IsReservedIP(ip) {
			continue
		}

		line := lineAt(ctx.LineOffsets, m[0])
		fs.Add(SignalHardcodedIPv4, line, "Hardcoded IPv4", ip)

		// Контекст через AC (один проход вместо 4 × bytes.Contains)
		ipContext := d.getIPContextAC(ctx, m[0])

		desc := "Hardcoded IPv4"
		if ipContext != "" {
			desc = "Hardcoded IPv4" + ipContext
		} else {
			desc = "Hardcoded IPv4 (no obvious network context)"
		}

		match := newMatch(
			types.CategoryHardcodedIP,
			analysis.Path, line,
			desc, ip, false,
		)
		match.Severity, match.EvidenceType = types.SeverityInfo, "address_inventory"
		match.FalsePositiveHints = "A numeric address and nearby network vocabulary do not establish maliciousness or an actual connection."
		match.RequiredNextEvidence = "Trace the address into a connection or resolver call and inspect the protocol/command handling."
		analysis.Matches = append(analysis.Matches, match)
		emitted++
	}
}

// isStandaloneDottedNumber reports whether the match at [start,end) is bounded
// by anything other than a digit or a dot. Go's regexp (RE2) has no
// look-around, so the IPv4 pattern's `\b` still matches inside longer dotted
// sequences such as X.509 OIDs; this closes that gap post-match.
func isStandaloneDottedNumber(content []byte, start, end int) bool {
	if start > 0 {
		if c := content[start-1]; (c >= '0' && c <= '9') || c == '.' {
			return false
		}
	}
	if end < len(content) {
		if c := content[end]; (c >= '0' && c <= '9') || c == '.' {
			return false
		}
	}
	return true
}

// oidPrefixAllowlist lists dotted prefixes of ASN.1 OBJECT IDENTIFIER arcs
// that pass the IPv4 shape test yet are never host addresses. They appear in
// certificate/PKCS#7 constants and attribute names across virtually every APK
// that touches crypto code.
var oidPrefixAllowlist = []string{
	"2.5.4.",    // X.520 attribute types (countryName, commonName, ...)
	"1.3.14.",   // OIW / NIST-OIW arcs (sha1WithRSA and friends)
	"2.16.840.", // US government arc (NIST hash/AES OIDs)
	"1.2.840.",  // ISO US member body (RSA PKCS#1, EC, SHA-2 signatures)
	"1.3.6.1.",  // internet arc (PKIX, LDAP, SNMP)
	"2.23.134.", // ISO 18033 / Russian crypto
	"1.3.132.",  // SECG elliptic curve arcs
}

func isWellKnownOID(ip string) bool {
	for _, prefix := range oidPrefixAllowlist {
		if strings.HasPrefix(ip, prefix) {
			return true
		}
	}
	return false
}

// inOIDPackage reports whether the file belongs to a signing/ASN.1 package
// (apksig, pkcs*, oid*) where dotted OID constants are the bulk of the digit
// content, so IPv4 inventory there is noise by construction.
func inOIDPackage(path string) bool {
	p := strings.ToLower(filepath.ToSlash(path))
	if strings.Contains(p, "apksig") {
		return true
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "oid" || strings.HasPrefix(seg, "oid") || strings.Contains(seg, "pkcs") {
			return true
		}
	}
	return false
}

// getIPContextAC — проверяет контекст IP через AC (один проход вместо 4).
//
// Раньше: 4 × bytes.Contains(500 bytes) = 2000 сравнений
// Теперь: 1 × AC(500 bytes) = 500 переходов
func (d *ThreatIndicatorsDetector) getIPContextAC(ctx *FileDetectContext, idx int) string {
	if d.ipContextAC == nil {
		return ""
	}

	start := idx - 250
	if start < 0 {
		start = 0
	}
	end := idx + 250
	if end > len(ctx.ContentLower) {
		end = len(ctx.ContentLower)
	}

	surrounding := string(ctx.ContentLower[start:end])
	if d.ipContextAC.ContainsAny(surrounding) {
		return " (network vocabulary nearby; usage unresolved)"
	}
	return ""
}

func (d *ThreatIndicatorsDetector) detectSuspiciousTLD(ctx *FileDetectContext, fs *FileSignals, analysis *types.FileAnalysis) {
	matches := CompiledPatterns.SuspiciousTLD.FindAllIndex(ctx.Content, 5)
	for _, m := range matches {
		url := string(ctx.Content[m[0]:m[1]])
		line := lineAt(ctx.LineOffsets, m[0])
		fs.Add(SignalSuspiciousTLD, line, "Domain reference", url)
		match := newMatch(types.CategoryNetworkEndpoint, analysis.Path, line, "Domain reference (TLD does not establish reputation)", url, false)
		match.Severity, match.EvidenceType = types.SeverityInfo, "address_inventory"
		match.Explanation = &finding.Explanation{Status: "observation", Summary: "A URL is present in the analyzed file.",
			Limitations: []string{"The top-level domain alone does not establish C2, malicious reputation or a connection to this address."}}
		analysis.Matches = append(analysis.Matches, match)
	}
}

func (d *ThreatIndicatorsDetector) detectBase64Strings(ctx *FileDetectContext, fs *FileSignals, analysis *types.FileAnalysis) {
	matches := CompiledPatterns.Base64Long.FindAllIndex(ctx.Content, 10)
	for _, m := range matches {
		start := m[0] - 100
		if start < 0 {
			start = 0
		}
		end := m[1] + 100
		if end > len(ctx.ContentLower) {
			end = len(ctx.ContentLower)
		}
		surrounding := ctx.ContentLower[start:end]

		if bytes.Contains(surrounding, []byte("base64;->decode")) ||
			bytes.Contains(surrounding, []byte("base64;->getdecoder")) {
			line := lineAt(ctx.LineOffsets, m[0])
			b64str := string(ctx.Content[m[0]:m[1]])
			if len(b64str) > 50 {
				b64str = b64str[:50] + "..."
			}
			fs.Add(SignalBase64LongString, line, "Base64 encoded string with decode", b64str)

			// Inventory, not a critical finding: embedded public keys and
			// license blobs use exactly this shape. Only dynamic execution
			// (class loader / dex load) is critical.
			analysis.Matches = append(analysis.Matches, newMatch(
				types.CategoryObfuscatedCode,
				analysis.Path, line,
				"Long Base64 string with decode operation (likely obfuscated data)",
				b64str, false,
			))
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

func shouldEmitImmediate(sig SignalType) bool {
	switch sig {
	case SignalDiscordWebhook:
		return true
	default:
		return false
	}
}

func isHighPriorityNative(sig SignalType) bool {
	switch sig {
	case SignalFrida, SignalXposed, SignalSubstrate,
		SignalNativeC2, SignalNativeDexLoader:
		return true
	default:
		return false
	}
}

func signalToCategory(sig SignalType) types.Category {
	switch {
	case sig >= SignalDexClassLoader && sig <= SignalDexFileLoad:
		return types.CategoryDynamicCodeLoad
	case sig >= SignalNetworkHTTP && sig <= SignalNetworkRetrofit:
		return types.CategoryNetwork
	case sig >= SignalDiscordWebhook && sig <= SignalHardcodedIPv4:
		return types.CategorySuspiciousURL
	case sig >= SignalWebViewLoadURL && sig <= SignalWebViewOverrideURL:
		return types.CategoryWebViewRemoteJS
	case sig >= SignalAccessibilityPermission && sig <= SignalAccessibilityNodeInfo:
		return types.CategoryAccessibilityCapability
	case sig >= SignalFrida && sig <= SignalRootCheck:
		return types.CategoryAntiAnalysis
	default:
		return types.CategoryStealerIndicator
	}
}
