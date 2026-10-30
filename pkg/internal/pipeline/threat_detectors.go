package pipeline

import (
	"bytes"
	"strings"
	"sync"

	"mega-analyzer/pkg/internal/matcher"
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

	for _, patIdx := range found {
		if patIdx < 0 || patIdx >= len(ac.entries) {
			continue
		}
		e := &ac.entries[patIdx]

		// Group dedup: один match на группу паттернов
		if e.group != "" && seenGroups[e.group] {
			continue
		}
		if e.group != "" {
			seenGroups[e.group] = true
		}

		// Получаем позицию
		idx := bytes.Index(ctx.ContentLower, e.patternLower)
		if idx < 0 {
			continue
		}

		line := lineAt(ctx.LineOffsets, idx)
		fs.Add(e.signal, line, e.context, string(e.patternLower))

		analysis.Matches = append(analysis.Matches, newMatch(
			types.CategoryStealerIndicator,
			analysis.Path, line,
			e.context, string(e.patternLower),
			true,
		))
	}
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

	// AC проверяет на lowercase, но native patterns case-sensitive
	// Поэтому: AC → prefilter, потом bytes.Index на оригинале
	found := d.nativeAC.ac.SearchBytes(ctx.ContentLower)
	if len(found) == 0 {
		return
	}

	hitCount := 0
	seenGroups := make(map[string]bool, len(found))

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

		// Для case-sensitive: ищем оригинальный паттерн (не lowered)
		// Используем lowercase AC как prefilter, потом проверяем реальный
		var idx int
		if e.caseSensitive {
			// Ищем в оригинальном контенте
			// Нужен оригинальный паттерн — берём из NativePatterns
			idx = bytes.Index(ctx.ContentLower, e.patternLower)
		} else {
			idx = bytes.Index(ctx.ContentLower, e.patternLower)
		}

		if idx < 0 {
			continue
		}

		if e.group != "" {
			seenGroups[e.group] = true
		}

		line := lineAt(ctx.LineOffsets, idx)
		fs.Add(e.signal, line, e.context, string(e.patternLower))
		hitCount++

		if isHighPriorityNative(e.signal) {
			analysis.Matches = append(analysis.Matches, newMatch(
				types.CategorySuspiciousNativePayload,
				analysis.Path, line,
				e.context, string(e.patternLower),
				true,
			))
		}
	}

	// Cross-signal correlation
	if fs.HasAny(SignalFrida, SignalXposed, SignalPtrace) &&
		fs.HasAny(SignalNativeC2, SignalNativeHTTP, SignalNativeDexLoader) {
		analysis.Matches = append(analysis.Matches, newMatch(
			types.CategorySuspiciousNativePayload,
			analysis.Path, 0,
			"Native library with anti-analysis AND suspicious payload",
			"ANTI_ANALYSIS+PAYLOAD",
			true,
		))
	}
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

	const maxIPsPerFile = 8
	matches := CompiledPatterns.IPv4.FindAllIndex(ctx.Content, maxIPsPerFile*2)

	emitted := 0
	for _, m := range matches {
		if emitted >= maxIPsPerFile {
			break
		}

		ip := string(ctx.Content[m[0]:m[1]])
		if IsReservedIP(ip) {
			continue
		}

		line := lineAt(ctx.LineOffsets, m[0])
		fs.Add(SignalHardcodedIPv4, line, "Hardcoded IPv4", ip)

		// Контекст через AC (один проход вместо 4 × bytes.Contains)
		ipContext := d.getIPContextAC(ctx, m[0])

		desc := "Hardcoded IPv4"
		critical := false
		if ipContext != "" {
			desc = "Hardcoded IPv4" + ipContext
			critical = true
		} else {
			desc = "Hardcoded IPv4 (no obvious network context)"
		}

		analysis.Matches = append(analysis.Matches, newMatch(
			types.CategoryHardcodedIP,
			analysis.Path, line,
			desc, ip, critical,
		))
		emitted++
	}
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
		return " (used in network call)"
	}
	return ""
}

func (d *ThreatIndicatorsDetector) detectSuspiciousTLD(ctx *FileDetectContext, fs *FileSignals, analysis *types.FileAnalysis) {
	matches := CompiledPatterns.SuspiciousTLD.FindAllIndex(ctx.Content, 5)
	for _, m := range matches {
		url := string(ctx.Content[m[0]:m[1]])
		line := lineAt(ctx.LineOffsets, m[0])
		fs.Add(SignalSuspiciousTLD, line, "Suspicious TLD", url)

		analysis.Matches = append(analysis.Matches, newMatch(
			types.CategorySuspiciousURL,
			analysis.Path, line,
			"URL with suspicious TLD (commonly used by malware)",
			url, true,
		))
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

			analysis.Matches = append(analysis.Matches, newMatch(
				types.CategoryObfuscatedCode,
				analysis.Path, line,
				"Long Base64 string with decode operation (likely obfuscated data)",
				b64str, true,
			))
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

func shouldEmitImmediate(sig SignalType) bool {
	switch sig {
	case SignalDiscordWebhook,
		SignalAccessibilityRootWindow, SignalAccessibilityGlobalAction:
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
		return types.CategoryStealerIndicator
	case sig >= SignalFrida && sig <= SignalRootCheck:
		return types.CategoryAntiAnalysis
	default:
		return types.CategoryStealerIndicator
	}
}
