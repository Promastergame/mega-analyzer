package pipeline

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"mega-analyzer/pkg/internal/configs"
	"mega-analyzer/pkg/internal/rules"
	"mega-analyzer/pkg/internal/types"
	"mega-analyzer/pkg/internal/verdict"
	"mega-analyzer/pkg/logger"
)

// ─────────────────────────────────────────────────────────────────────────────
// RULE ENGINE INTEGRATION
// ─────────────────────────────────────────────────────────────────────────────

// loadedRulesFingerprint is an FNV-1a hash of every rule file the engine
// loaded. It is mixed into the content-cache version so cached analysis
// results are invalidated automatically whenever detection rules change.
var loadedRulesFingerprint atomic.Uint32

func mixFNV(h uint32, data []byte) uint32 {
	for _, b := range data {
		h ^= uint32(b)
		h *= 16777619
	}
	return h
}

func loadRulesEngine() *rules.Engine {
	engine := rules.NewEngine()

	ruleFiles := []string{
		"permission_rules.json",
		"malware_combos.json",
		"banking_threats.json",
		"context_downgrades.json",
	}

	baseDirs := []string{
		"pkg/internal/configs",
		"internal/configs",
		"configs",
		"",
	}

	loaded := 0
	fp := uint32(2166136261) // FNV-1a offset basis
	for _, file := range ruleFiles {
		if data, ok := loadRulesFile(engine, baseDirs, file); ok {
			loaded++
			fp = mixFNV(fp, data)
		} else {
			// Набор правил недоступен: скан пойдёт с меньшим числом проверок,
			// и «чисто» по такому скану ничего не доказывает.
			verdict.MarkDegraded("rules", "rule file "+file+" could not be loaded")
		}
	}

	// Пользовательские правила (в том числе context-правила для гашения
	// ложных срабатываний) подхватываются из каталога, если он задан.
	if dir := strings.TrimSpace(os.Getenv("MEGA_ANALYZER_RULES_DIR")); dir != "" {
		if err := engine.LoadRulesFromDir(dir); err != nil {
			verdict.MarkDegraded("rules", "extra rules directory unreadable: "+err.Error())
		} else {
			fp = mixExtraRulesFingerprint(fp, dir)
		}
	}
	loadedRulesFingerprint.Store(fp)

	if loaded == 0 || engine.Stats().TotalRules == 0 {
		verdict.MarkDegraded("rules", "no rules loaded")
		return nil
	}

	reportRuleHealth(engine)
	return engine
}

// reportRuleHealth проверяет межправиловые контракты (ссылки композитов,
// context-правила) после загрузки ВСЕХ наборов и фиксирует деградацию, если
// часть правил отброшена или граф правил сломан.
func reportRuleHealth(engine *rules.Engine) {
	for _, issue := range engine.Lint() {
		if issue.Level == rules.LintError {
			logger.Warn("Rule lint error", "rule", issue.RuleID, "message", issue.Message)
		} else {
			logger.Debug("Rule lint warning", "rule", issue.RuleID, "message", issue.Message)
		}
	}
	if h := engine.Health(); h.Degraded() {
		verdict.MarkDegraded("rules", h.String())
	}
}

// mixExtraRulesFingerprint подмешивает содержимое каталога пользовательских
// правил в отпечаток, чтобы кэш анализа инвалидировался при их изменении.
func mixExtraRulesFingerprint(fp uint32, dir string) uint32 {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fp
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, n := range names {
		fp = mixFNV(fp, []byte(n))
		if data, err := os.ReadFile(filepath.Join(dir, n)); err == nil {
			fp = mixFNV(fp, data)
		}
	}
	return fp
}

func loadRulesFile(engine *rules.Engine, baseDirs []string, file string) ([]byte, bool) {
	for _, dir := range baseDirs {
		path := file
		if dir != "" {
			path = filepath.Join(dir, file)
		}
		if _, err := os.Stat(path); err != nil {
			continue
		}
		if err := engine.LoadRulesFromFile(path); err != nil {
			logger.Warn("Failed to load rules file", "file", path, "error", err)
			return nil, false
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			// Fingerprint falls back to the path; loading itself succeeded.
			data = []byte(path)
		}
		return data, true
	}

	// No on-disk file found: fall back to the database baked into the binary.
	if data, ok := configs.File(file); ok {
		if err := engine.LoadRulesFromBytes(file, data); err != nil {
			logger.Warn("Failed to load embedded rules", "file", file, "error", err)
			return nil, false
		}
		return data, true
	}
	return nil, false
}

func (p *Pipeline) applyRuleEngine() {
	if p.rulesEngine == nil || p.result == nil {
		return
	}

	// 1. Global rules — permission gates and single-indicator rules are checked
	//    against the whole-APK context (the manifest + every file's evidence).
	globalCtx := buildRuleContext(p.result)
	results := p.rulesEngine.EvaluateGlobalRules(globalCtx)

	// 2. File-scoped behavioral combos — checked per file so that a "banking
	//    trojan" pattern only fires when its pieces (overlay + accessibility +
	//    exfil, etc.) actually live together in ONE file. Manifest permissions
	//    are APK-wide, so they're injected into every per-file context — that
	//    keeps permission+behavior combos working without re-introducing the
	//    "co-present anywhere" false positives. A real vulnerability inside a
	//    single SDK file still fires: its conditions are co-located there.
	fileScoped := p.evaluateFileScopedCombos(globalCtx.Permissions)
	results = append(results, fileScoped...)

	// Filter out banking threat rules for game applications (too many false positives).
	isGame := isGameApp(p.result)
	if isGame {
		results = filterBankingRules(results)
		results = filterGameRules(results)
	}

	if len(results) == 0 {
		return
	}

	matches := make([]types.Match, 0, len(results))
	for _, res := range results {
		matches = append(matches, buildRuleMatch(res))
	}

	p.result.RuleMatches = append(p.result.RuleMatches, matches...)
	logger.Info("Rule engine matched",
		"matches", len(matches),
		"file_scoped", len(fileScoped),
	)
}

// evaluateFileScopedCombos runs the file-scoped behavioral combo rules against
// each file individually and returns one result per matching rule (deduped by
// rule ID, tagged with the first file it fired in). globalPerms carries the
// APK-wide manifest permissions into every per-file context.
func (p *Pipeline) evaluateFileScopedCombos(globalPerms []string) []rules.RuleEvaluationResult {
	filesMap := p.result.Files
	if len(filesMap) == 0 {
		return nil
	}

	// Deterministic order: p.result.Files is a map with randomised iteration.
	// Sorting by path makes both the output order and the "first file that
	// fired this rule" attribution stable across runs.
	keys := make([]string, 0, len(filesMap))
	for k := range filesMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	files := make([]*types.FileAnalysis, len(keys))
	for i, k := range keys {
		files[i] = filesMap[k]
	}

	// This loop was the single slowest thing in post-processing: one full
	// rule-context rebuild plus a pass over every file-scoped rule, for every
	// file in the APK, on one core while the scan workers sat idle.
	//
	// Each file is evaluated against read-only analysis state, so the work
	// parallelises cleanly. Results are collected per file and merged in file
	// order afterwards, which keeps both the output order and the "first file
	// that fired this rule" attribution byte-identical to the serial version.
	perFile := make([][]rules.RuleEvaluationResult, len(files))

	workers := runtime.NumCPU()
	if workers > len(files) {
		workers = len(files)
	}

	if workers > 1 {
		var wg sync.WaitGroup
		var next atomic.Int64
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					i := int(next.Add(1)) - 1
					if i >= len(files) {
						return
					}
					perFile[i] = evaluateOneFileScoped(p.rulesEngine, files[i], globalPerms)
				}
			}()
		}
		wg.Wait()
	} else {
		for i := range files {
			perFile[i] = evaluateOneFileScoped(p.rulesEngine, files[i], globalPerms)
		}
	}

	seen := make(map[string]bool, 16)
	var out []rules.RuleEvaluationResult
	for i, results := range perFile {
		for _, res := range results {
			if seen[res.RuleID] {
				continue
			}
			seen[res.RuleID] = true
			// files[i] is guaranteed non-nil when results is non-empty, because
			// evaluateOneFileScoped returns nil for nil/evidenceless files.
			if files[i] != nil {
				res.MatchedFile = files[i].Path
			} else {
				res.MatchedFile = keys[i]
			}
			out = append(out, res)
		}
	}
	return out
}

// evaluateOneFileScoped evaluates the file-scoped combo rules against a single
// file's evidence. Returns nil when the file carries nothing worth evaluating.
func evaluateOneFileScoped(engine *rules.Engine, fa *types.FileAnalysis, globalPerms []string) []rules.RuleEvaluationResult {
	if !fileMayMatchCombo(fa) {
		return nil
	}
	fileCtx := buildFileContext(fa, globalPerms)
	if fileCtx == nil {
		return nil
	}
	return engine.EvaluateFileScopedRules(fileCtx)
}

// fileMayMatchCombo is a cheap pre-filter: behavioral combos need code-level
// evidence, so only files with a parsed smali class or existing matches are
// worth building a per-file context for.
func fileMayMatchCombo(fa *types.FileAnalysis) bool {
	if fa == nil {
		return false
	}
	if fa.SmaliClass != nil {
		return true
	}
	return len(fa.Matches) > 0
}

// buildFileContext builds a rule-evaluation context from a SINGLE file's
// evidence (its matches + parsed smali class), with the APK-wide manifest
// permissions injected so permission conditions still resolve. Returns nil
// when the file carries no code-level signal worth evaluating.
func buildFileContext(fa *types.FileAnalysis, globalPerms []string) *rules.ConditionContext {
	apiCol := newCollector()
	patternCol := newCollector()
	stringCol := newCollector()
	classCol := newCollector()
	methodCol := newCollector()

	for _, m := range fa.Matches {
		patternCol.addWithLower(m.Pattern)
		patternCol.addWithLower(m.Text)
		patternCol.addWithLower(m.Context)
		stringCol.addWithLower(m.Pattern)
		stringCol.addWithLower(m.Text)
		stringCol.addWithLower(m.Context)

		if m.ClassName != "" {
			classCol.addWithLower(m.ClassName)
			apiCol.addWithLower(m.ClassName)
		}
		if m.MethodName != "" {
			methodCol.addWithLower(m.MethodName)
			apiCol.addWithLower(m.MethodName)
		}
	}

	// Plaintext recovered from encrypted literals is evidence like any other,
	// and it is the evidence most worth matching: an obfuscator went to the
	// trouble of hiding it.
	for _, s := range fa.RecoveredStrings {
		stringCol.addWithLower(s)
		patternCol.addWithLower(s)
	}

	if fa.SmaliClass != nil {
		cls := fa.SmaliClass
		classCol.addWithLower(cls.Name)
		classCol.addWithLower(cls.PackageName)
		classCol.addWithLower(cls.SuperClass)
		for _, iface := range cls.Interfaces {
			classCol.addWithLower(iface)
		}

		for i := range cls.Methods {
			m := &cls.Methods[i]
			methodCol.addWithLower(m.Name)
			apiCol.addWithLower(m.Name)
			apiCol.addWithLower(m.FullSignature(cls.Name))
			for j := range m.Invokes {
				addInvoke(apiCol, classCol, methodCol, &m.Invokes[j])
			}
		}
	}

	// Nothing code-like to match a behavioral combo against.
	if len(apiCol.items) == 0 && len(classCol.items) == 0 && len(stringCol.items) == 0 {
		return nil
	}

	// Deliberately not calling ctx.Build() here. Build materialises all six
	// exact-match indexes plus the concatenated allValues slice, and this
	// function runs once per file. The engine builds exactly the indexes its
	// loaded rules can read, on first evaluation, via BuildFor.
	return &rules.ConditionContext{
		Permissions: globalPerms,
		APICalls:    apiCol.items,
		Patterns:    patternCol.items,
		Strings:     stringCol.items,
		Classes:     classCol.items,
		Methods:     methodCol.items,
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// CONTEXT BUILDING
// ─────────────────────────────────────────────────────────────────────────────

type stringCollector struct {
	set   map[string]struct{}
	items []string
}

func newCollector() *stringCollector {
	return &stringCollector{set: make(map[string]struct{}, 128)}
}

func (c *stringCollector) add(val string) {
	v := strings.TrimSpace(val)
	if v == "" {
		return
	}
	if _, ok := c.set[v]; ok {
		return
	}
	c.set[v] = struct{}{}
	c.items = append(c.items, v)
}

func (c *stringCollector) addWithLower(val string) {
	c.add(val)
	lower := strings.ToLower(val)
	if lower != val {
		c.add(lower)
	}
}

func buildRuleContext(result *types.AnalysisResult) *rules.ConditionContext {
	permCol := newCollector()
	apiCol := newCollector()
	patternCol := newCollector()
	stringCol := newCollector()
	classCol := newCollector()
	methodCol := newCollector()

	for _, perm := range extractPermissionsFromManifest(result.TargetDir) {
		permCol.addWithLower(perm)
	}

	for _, fa := range result.Files {
		if fa == nil {
			continue
		}
		for _, m := range fa.Matches {
			patternCol.addWithLower(m.Pattern)
			patternCol.addWithLower(m.Text)
			patternCol.addWithLower(m.Context)
			stringCol.addWithLower(m.Pattern)
			stringCol.addWithLower(m.Text)
			stringCol.addWithLower(m.Context)

			if m.ClassName != "" {
				classCol.addWithLower(m.ClassName)
				apiCol.addWithLower(m.ClassName)
			}
			if m.MethodName != "" {
				methodCol.addWithLower(m.MethodName)
				apiCol.addWithLower(m.MethodName)
			}
		}

		if fa.XMLData != nil {
			for _, perm := range fa.XMLData.Permissions {
				permCol.addWithLower(perm)
			}
		}

		if fa.SmaliClass != nil {
			cls := fa.SmaliClass
			classCol.addWithLower(cls.Name)
			classCol.addWithLower(cls.PackageName)
			classCol.addWithLower(cls.SuperClass)
			for _, iface := range cls.Interfaces {
				classCol.addWithLower(iface)
			}

			for i := range cls.Methods {
				m := &cls.Methods[i]
				methodCol.addWithLower(m.Name)
				apiCol.addWithLower(m.Name)
				apiCol.addWithLower(m.FullSignature(cls.Name))
				for j := range m.Invokes {
					addInvoke(apiCol, classCol, methodCol, &m.Invokes[j])
				}
			}
		}
	}

	// See buildFileContext: the engine sizes the indexes itself via BuildFor.
	return &rules.ConditionContext{
		Permissions: permCol.items,
		APICalls:    apiCol.items,
		Patterns:    patternCol.items,
		Strings:     stringCol.items,
		Classes:     classCol.items,
		Methods:     methodCol.items,
	}
}

func addInvoke(apiCol, classCol, methodCol *stringCollector, inv *types.Invoke) {
	if inv == nil {
		return
	}
	apiCol.addWithLower(inv.Class)
	apiCol.addWithLower(inv.Method)
	apiCol.addWithLower(inv.FullSignature())
	methodCol.addWithLower(inv.Method)

	simple := smaliSimpleClass(inv.Class)
	if simple != "" {
		apiCol.addWithLower(simple)
		classCol.addWithLower(simple)
	}
	classCol.addWithLower(inv.Class)
}

func smaliSimpleClass(className string) string {
	if className == "" {
		return ""
	}
	trim := strings.TrimPrefix(className, "L")
	trim = strings.TrimSuffix(trim, ";")
	if idx := strings.LastIndex(trim, "/"); idx >= 0 && idx+1 < len(trim) {
		return trim[idx+1:]
	}
	return trim
}

// ─────────────────────────────────────────────────────────────────────────────
// MANIFEST PERMISSIONS
// ─────────────────────────────────────────────────────────────────────────────

var manifestPermRe = regexp.MustCompile(`(?i)<uses-permission[^>]*android:name\s*=\s*"([^"]+)"`)
var permLiteralRe = regexp.MustCompile(`(?i)android.permission\.[A-Z0-9_]+`)

func extractPermissionsFromManifest(targetDir string) []string {
	manifestPath := filepath.Join(targetDir, "AndroidManifest.xml")
	data, err := os.ReadFile(manifestPath)
	if err != nil || len(data) == 0 {
		return nil
	}

	content := string(data)
	permCol := newCollector()

	matches := manifestPermRe.FindAllStringSubmatch(content, -1)
	for _, m := range matches {
		if len(m) > 1 {
			permCol.add(m[1])
		}
	}

	literals := permLiteralRe.FindAllString(content, -1)
	for _, p := range literals {
		permCol.add(p)
	}

	return permCol.items
}

// ─────────────────────────────────────────────────────────────────────────────
// RULE MATCH CONVERSION
// ─────────────────────────────────────────────────────────────────────────────

func buildRuleMatch(res rules.RuleEvaluationResult) types.Match {
	category := ruleCategoryToCategory(res.Category)

	// File-scoped combos carry the file they actually fired in; global rules
	// keep the synthetic "rule:<id>" location.
	file := "rule:" + res.RuleID
	scope := "global"
	if res.MatchedFile != "" {
		file = res.MatchedFile
		scope = "file"
	}

	meta := map[string]string{
		"rule_id":       res.RuleID,
		"rule_name":     res.RuleName,
		"rule_set":      res.Category,
		"severity":      res.Severity,
		"score":         strconv.Itoa(res.Score),
		"references":    strings.Join(res.References, "; "),
		"tags":          strings.Join(res.Tags, ", "),
		"description":   res.Message,
		"engine_source": "json_rules",
		"rule_scope":    scope,
	}
	if res.MatchedFile != "" {
		meta["matched_file"] = res.MatchedFile
	}

	return types.Match{
		SourceLocation: types.SourceLocation{File: file, Line: 0},
		Categorized:    types.Categorized{Category: category},
		Scored:         types.Scored{Score: float64(res.Score)},
		Text:           res.RuleName,
		Pattern:        res.RuleID,
		Context:        res.Message,
		Metadata:       meta,
		IsCritical:     res.IsHighOrAbove(),
	}
}

// isGameApp detects if the analyzed app is a game. Games have many false positives
// with banking trojan rules due to WebView usage, Firebase, networking, etc.
func isGameApp(result *types.AnalysisResult) bool {
	if result == nil {
		return false
	}

	pkg := strings.ToLower(result.AppPackage)

	// Known game indicators
	gameKeywords := []string{
		"game", "games", "supercell", "brawl", "clash",
		"unity", "unreal", "godot", "cocos",
		"libunity", "libue4", "libgodot",
	}

	for _, kw := range gameKeywords {
		if strings.Contains(pkg, kw) {
			return true
		}
	}

	// Check for game engines in files
	for _, fa := range result.Files {
		if fa == nil {
			continue
		}
		path := strings.ToLower(fa.Path)
		if strings.Contains(path, "libunity") || strings.Contains(path, "libue4") ||
			strings.Contains(path, "libgodot") || strings.Contains(path, "libcocos") {
			return true
		}
	}

	return false
}

// filterBankingRules removes banking threat rules from results for non-financial apps.
// Banking trojan detection rules have high false positive rates for legitimate apps
// that use similar APIs (WebView, Firebase, networking).
func filterBankingRules(results []rules.RuleEvaluationResult) []rules.RuleEvaluationResult {
	bankingRuleIDs := map[string]bool{
		"bank_overlay_classic":           true,
		"bank_overlay_a11y_modern":       true,
		"bank_overlay_webview_inject":    true,
		"bank_overlay_webview_js_bridge": true,
		"bank_overlay_custom_tab":        true,
		"bank_overlay_dynamic_html":      true,
		"bank_session_cookie_steal":      true,
		"bank_session_hijack_intercept":  true,
		"bank_session_hook_network":      true,
		"bank_2fa_intercept_sms":         true,
		"bank_2fa_intercept_notif":       true,
		"bank_2fa_intercept_a11y":        true,
		"bank_2fa_intercept_push":        true,
		"bank_credential_keylog":         true,
		"bank_credential_screen_capture": true,
		"bank_credential_form_inject":    true,
		"bank_c2_firebase":               true,
		"bank_c2_push":                   true,
		"bank_c2_sms":                    true,
		"bank_atm_emulator":              true,
		"bank_call_intercept":            true,
		"bank_call_forward":              true,
		"bank_payment_hijack":            true,
		"bank_payment_redirect":          true,
		"bank_crypto_wallet_target":      true,
		"bank_crypto_private_key":        true,
		"bank_app_probe":                 true,
		"bank_app_target_list":           true,
		"bank_evasion_emulator_check":    true,
		"bank_evasion_geo_targeting":     true,
		"bank_social_push_phishing":      true,
		"bank_social_sms_phishing":       true,
		"rat_reverse_connection":         true,
	}

	filtered := make([]rules.RuleEvaluationResult, 0, len(results))
	for _, res := range results {
		if !bankingRuleIDs[res.RuleID] {
			filtered = append(filtered, res)
		}
	}
	return filtered
}

func ruleCategoryToCategory(ruleSet string) types.Category {
	switch strings.ToLower(ruleSet) {
	case "permission_rules":
		return types.CategoryPermissionRule
	case "malware_indicators":
		return types.CategoryMalwareCombo
	case "banking_threats":
		return types.CategoryBankingThreat
	default:
		return types.CategorySecurity
	}
}

func filterGameRules(results []rules.RuleEvaluationResult) []rules.RuleEvaluationResult {
	gameRuleIDs := map[string]bool{
		"c2_firebase_abuse":           true,
		"bank_target_resolver_probe":  true,
		"adware_hidden_browser":       true,
		"privacy_installed_apps_scan": true,
	}

	filtered := make([]rules.RuleEvaluationResult, 0, len(results))
	for _, res := range results {
		if !gameRuleIDs[res.RuleID] {
			filtered = append(filtered, res)
		}
	}
	return filtered
}
