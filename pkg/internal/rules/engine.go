package rules

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"mega-analyzer/pkg/logger"
)

// ═══════════════════════════════════════════════════════════════════════════════
// RULE ENGINE — Центральная система обработки правил
//
// Загружает JSON-конфиги, валидирует их, и применяет при анализе.
// Поддерживает AND/OR/NOT операторы на уровне условий,
// AND/OR логику на уровне правил, и O(1) матчинг через индексы.
// ═══════════════════════════════════════════════════════════════════════════════

// ── Condition ──────────────────────────────────────────────────────────────

// Condition определяет одно условие для проверки.
//
// Type: "permission", "api_call", "pattern", "combo", "class", "method", "string"
// Operator: "and" (default), "or", "not"
//
// Для Type="combo": Values содержит список значений,
// которые ищутся ACROSS ALL context types (permissions + api_calls + patterns).
type Condition struct {
	Type     string   `json:"type"`               // permission, api_call, pattern, combo, class, method, string
	Value    string   `json:"value,omitempty"`    // значение для проверки (exact или substring)
	Values   []string `json:"values,omitempty"`   // для combo — список values
	Operator string   `json:"operator,omitempty"` // "and" (default), "or", "not"
	Exact    bool     `json:"exact,omitempty"`    // exact match вместо substring
}

// ── Rule ───────────────────────────────────────────────────────────────────

// Rule определяет одно правило анализа.
//
// Logic управляет объединением условий:
//   - "and" (default): все условия обязательны
//   - "or": хотя бы одно условие
//   - "threshold": минимум MinMatch условий из списка
type Rule struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Category    string      `json:"category"` // security, privacy, malware, etc.
	Severity    string      `json:"severity"` // critical, high, medium, low, info
	Score       int         `json:"score"`    // 1-100
	Conditions  []Condition `json:"conditions"`
	Logic       string      `json:"logic,omitempty"`      // "and" (default), "or", "threshold"
	MinMatch    int         `json:"min_match,omitempty"`  // для logic="threshold"
	Scope       string      `json:"scope,omitempty"`      // "file"/"class" → per-file; "global"/"apk" → whole-APK; "" → auto
	References  []string    `json:"references,omitempty"` // CVE, MITRE ATT&CK
	Tags        []string    `json:"tags,omitempty"`       // для фильтрации
	Enabled     bool        `json:"enabled"`

	// ── Композиция и контекст (rules/v2) ─────────────────────────────────
	//
	// Kind: "" / "detect" — обычное правило, "context" — доброкачественный
	// контекст (известный SDK, тулчейн, вендорский код). Context-правило
	// никогда не попадает в результаты и не может быть положительным
	// свидетельством: на него ссылаются только Unless/Downgrade.
	Kind string `json:"kind,omitempty"`
	// Requires — ID других правил, которые должны сработать на том же
	// контексте (композит). Вместе с Conditions действует как AND.
	Requires []string `json:"requires,omitempty"`
	// Unless — ID context-правил; если любое сработало, находка гасится.
	Unless []string `json:"unless,omitempty"`
	// Downgrade — ID context-правил; если любое сработало, severity падает
	// на ступень, а score уменьшается вдвое (находка остаётся видимой).
	Downgrade []string `json:"downgrade,omitempty"`
	// Confidence — уверенность правила 0..1, независимая от severity.
	// 0 (не задано) трактуется как 1.0.
	Confidence float64 `json:"confidence,omitempty"`
	// Suppresses / Downgrades — только для context-правил: селекторы целей,
	// которые гасятся / понижаются, когда контекст сработал. Селектор — точный
	// ID, префикс "bank_*", "tag:<тег>" или "category:<категория>". Так один
	// context-файл покрывает десятки правил без правки каждого из них.
	Suppresses []string `json:"suppresses,omitempty"`
	Downgrades []string `json:"downgrades,omitempty"`
	// Reason — обязательное для context-правил объяснение, ПОЧЕМУ этот
	// контекст безопасен (какой ложный сработка его породило).
	Reason string `json:"reason,omitempty"`

	// scopeResolved caches IsFileScoped, which is otherwise recomputed for
	// every rule against every file: it lowercases Scope and walks the whole
	// condition list on each call. Unexported, so encoding/json ignores it.
	scopeResolved bool
	scopeIsFile   bool
}

// IsFileScoped reports whether ALL of a rule's conditions must be satisfied
// within a SINGLE file, rather than merely co-present somewhere in the APK.
//
// Behavioral combos (≥2 non-permission code conditions, or a combo condition
// bundling ≥2 values) default to file scope: a legitimate app that simply
// *contains* the right SDKs scattered across many files (e.g. flutter_inappwebview
// + Firebase FCM + an accessibility bridge) must not trip a "banking trojan"
// combo. Permission-only rules stay global, since permissions are an APK-wide
// property of the manifest. A genuine vulnerability co-located inside one SDK
// file still fires — its conditions live together in that file.
//
// An explicit Scope of "global"/"apk" or "file"/"class" always wins.
func (r *Rule) IsFileScoped() bool {
	if r.scopeResolved {
		return r.scopeIsFile
	}
	return r.computeFileScoped()
}

// resolveScope precomputes IsFileScoped at load time so evaluation never pays
// for it. Called before the rule is published into the engine's indexes, so no
// concurrent reader can observe the write.
func (r *Rule) resolveScope() {
	r.scopeIsFile = r.computeFileScoped()
	r.scopeResolved = true
}

func (r *Rule) computeFileScoped() bool {
	switch strings.ToLower(r.Scope) {
	case "file", "class":
		return true
	case "global", "apk", "any":
		return false
	}
	behavioral := 0
	for i := range r.Conditions {
		c := &r.Conditions[i]
		if strings.EqualFold(c.Type, "permission") {
			continue
		}
		if strings.EqualFold(c.Type, "combo") {
			if len(c.Values) >= 2 {
				behavioral += len(c.Values)
			} else {
				behavioral++
			}
			continue
		}
		behavioral++
	}
	return behavioral >= 2
}

// Validate проверяет корректность правила
func (r *Rule) Validate() error {
	if r.ID == "" {
		return fmt.Errorf("rule has empty ID")
	}
	if r.Name == "" {
		return fmt.Errorf("rule %q has empty Name", r.ID)
	}
	if len(r.Conditions) == 0 && len(r.Requires) == 0 {
		return fmt.Errorf("rule %q has no conditions", r.ID)
	}
	if err := r.validateComposition(); err != nil {
		return err
	}
	if r.Score < 0 || r.Score > 100 {
		return fmt.Errorf("rule %q has invalid score %d (must be 1-100)", r.ID, r.Score)
	}

	validSeverities := map[string]bool{
		"critical": true, "high": true, "medium": true, "low": true, "info": true,
	}
	if r.Severity != "" && !validSeverities[r.Severity] {
		return fmt.Errorf("rule %q has invalid severity %q", r.ID, r.Severity)
	}

	validTypes := map[string]bool{
		"permission": true, "api_call": true, "pattern": true,
		"combo": true, "class": true, "method": true, "string": true,
	}
	for i, cond := range r.Conditions {
		if !validTypes[cond.Type] {
			return fmt.Errorf("rule %q condition[%d] has invalid type %q", r.ID, i, cond.Type)
		}
		if cond.Type == "combo" && len(cond.Values) == 0 {
			return fmt.Errorf("rule %q condition[%d] type=combo but Values is empty", r.ID, i)
		}
		if cond.Type != "combo" && cond.Value == "" {
			return fmt.Errorf("rule %q condition[%d] has empty Value", r.ID, i)
		}
	}

	if r.Logic == "threshold" && r.MinMatch <= 0 {
		return fmt.Errorf("rule %q has logic=threshold but MinMatch=%d", r.ID, r.MinMatch)
	}

	return nil
}

// ── RuleSet ────────────────────────────────────────────────────────────────

// RuleSet — набор правил одной категории (JSON root)
type RuleSet struct {
	Category    string `json:"category"`
	Version     string `json:"version"`
	Description string `json:"description,omitempty"`
	Rules       []Rule `json:"rules"`
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONDITION CONTEXT — данные для оценки правил
//
// Все поля индексируются при создании для O(1) lookup.
// Вызывающий код заполняет slices, затем вызывает Build().
// ═══════════════════════════════════════════════════════════════════════════════

type ConditionContext struct {
	// Входные данные (заполняются вызывающим кодом)
	Permissions []string
	APICalls    []string
	Patterns    []string
	Strings     []string
	Classes     []string
	Methods     []string
	Custom      map[string]any

	// Индексы для O(1) lookup (строятся Build()-ом)
	permSet    map[string]struct{}
	apiSet     map[string]struct{}
	patternSet map[string]struct{}
	stringSet  map[string]struct{}
	classSet   map[string]struct{}
	methodSet  map[string]struct{}

	// Все значения из всех типов — для combo и cross-type поиска
	allValues []string

	built bool
}

// Build создаёт индексы для O(1) lookup. Вызывать после заполнения полей.
//
// Build materialises everything unconditionally and stays that way for direct
// callers. Rule evaluation goes through BuildFor instead.
func (ctx *ConditionContext) Build() {
	ctx.BuildFor(true, true)
}

// BuildFor materialises only the indexes the caller asks for.
//
// This matters because the context is rebuilt for every file in the APK. The
// six exact-match sets are read only by conditions with "exact": true, and
// allValues only by non-exact combo conditions. Building both for every file
// when no loaded rule can use them was pure allocation.
func (ctx *ConditionContext) BuildFor(needSets, needAllValues bool) {
	if needSets {
		ctx.permSet = buildSet(ctx.Permissions)
		ctx.apiSet = buildSet(ctx.APICalls)
		ctx.patternSet = buildSet(ctx.Patterns)
		ctx.stringSet = buildSet(ctx.Strings)
		ctx.classSet = buildSet(ctx.Classes)
		ctx.methodSet = buildSet(ctx.Methods)
	}

	if needAllValues {
		// allValues — объединение всех типов для combo/cross-type search.
		//
		// Deduplicated: the pipeline pushes identical content into both
		// Patterns and Strings, so the union used to carry every literal at
		// least twice and every combo scan paid for the duplicates. Dropping
		// them cannot change the result of a substring search.
		totalCap := len(ctx.Permissions) + len(ctx.APICalls) + len(ctx.Patterns) +
			len(ctx.Strings) + len(ctx.Classes) + len(ctx.Methods)
		seen := make(map[string]struct{}, totalCap)
		ctx.allValues = make([]string, 0, totalCap)
		for _, group := range [][]string{
			ctx.Permissions, ctx.APICalls, ctx.Patterns,
			ctx.Strings, ctx.Classes, ctx.Methods,
		} {
			for _, v := range group {
				if _, dup := seen[v]; dup {
					continue
				}
				seen[v] = struct{}{}
				ctx.allValues = append(ctx.allValues, v)
			}
		}
	}

	ctx.built = true
}

// recomputeCapabilitiesLocked records which context indexes the currently
// loaded rules can actually read. Callers must hold e.mu for writing.
func (e *Engine) recomputeCapabilitiesLocked() {
	needExact, needAll := false, false
	for _, set := range e.rules {
		for i := range set {
			for j := range set[i].Conditions {
				c := &set[i].Conditions[j]
				switch {
				case c.Exact:
					needExact = true
				case strings.EqualFold(c.Type, "combo"):
					needAll = true
				}
			}
		}
	}
	e.needsExactSets = needExact
	e.needsAllValues = needAll
}

// buildSet создаёт set из slice для O(1) exact lookup
func buildSet(items []string) map[string]struct{} {
	if len(items) == 0 {
		return nil
	}
	s := make(map[string]struct{}, len(items))
	for _, item := range items {
		s[item] = struct{}{}
	}
	return s
}

// containsExact — O(1) exact match в set
func containsExact(set map[string]struct{}, val string) bool {
	_, ok := set[val]
	return ok
}

// containsSubstring — O(n) substring match в slice (fallback для Exact=false)
func containsSubstring(items []string, sub string) bool {
	for _, item := range items {
		if strings.Contains(item, sub) {
			return true
		}
	}
	return false
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENGINE
// ═══════════════════════════════════════════════════════════════════════════════

type Engine struct {
	mu       sync.RWMutex
	rules    map[string][]Rule // category → rules
	ruleByID map[string]*Rule  // id → rule (для быстрого lookup)

	// Capability flags, recomputed whenever rules are loaded.
	//
	// The shipped rule sets do not set "exact" on a single one of their 732
	// conditions, so every condition takes the substring path and the six
	// exact-match indexes were built for every file and never read once.
	// These flags let BuildFor skip whatever the loaded rules cannot consume.
	needsExactSets bool
	needsAllValues bool

	// skipped — сколько правил каждой категории отброшено валидацией при
	// загрузке. Нужно, чтобы отличить «полный» набор правил от урезанного
	// (см. Health): вердикт по урезанному набору нельзя считать чистым.
	skipped map[string]int

	// suppressBy / downgradeBy — обратный индекс «правило → context-правила»,
	// построенный из селекторов Suppresses/Downgrades при загрузке.
	suppressBy  map[string][]string
	downgradeBy map[string][]string
}

func NewEngine() *Engine {
	return &Engine{
		rules:    make(map[string][]Rule),
		ruleByID: make(map[string]*Rule),
		skipped:  make(map[string]int),
	}
}

// ── Loading ────────────────────────────────────────────────────────────────

// LoadRulesFromFile загружает правила из JSON файла.
// Валидирует каждое правило; невалидные логгируются и пропускаются.
// При повторной загрузке той же категории — правила ЗАМЕНЯЮТСЯ (не дублируются).
func (e *Engine) LoadRulesFromFile(filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("read rules file %s: %w", filePath, err)
	}
	return e.LoadRulesFromBytes(filepath.Base(filePath), data)
}

// LoadRulesFromBytes loads a rule set from in-memory JSON. srcName is used only
// for logging/diagnostics (e.g. the base filename or "embedded").
func (e *Engine) LoadRulesFromBytes(srcName string, data []byte) error {
	var ruleset RuleSet
	if err := json.Unmarshal(data, &ruleset); err != nil {
		return fmt.Errorf("parse rules JSON %s: %w", srcName, err)
	}

	if ruleset.Category == "" {
		ruleset.Category = "default"
	}

	// Валидация + фильтрация
	valid := make([]Rule, 0, len(ruleset.Rules))
	skipped := 0
	for i := range ruleset.Rules {
		rule := &ruleset.Rules[i]

		// Наследуем категорию из ruleset если не задана
		if rule.Category == "" {
			rule.Category = ruleset.Category
		}

		if err := rule.Validate(); err != nil {
			logger.Warn("Skipping invalid rule", "file", srcName, "error", err)
			skipped++
			continue
		}
		if dup := findDuplicateID(valid, rule.ID); dup {
			logger.Warn("Skipping rule with duplicate ID", "file", srcName, "rule", rule.ID)
			skipped++
			continue
		}

		rule.resolveScope()
		valid = append(valid, *rule)
	}

	e.mu.Lock()
	// Удаляем старые правила этой категории из индекса
	if old, ok := e.rules[ruleset.Category]; ok {
		for i := range old {
			delete(e.ruleByID, old[i].ID)
		}
	}

	// Сохраняем новые
	e.rules[ruleset.Category] = valid
	e.setSkippedLocked(ruleset.Category, skipped)

	// Обновляем индекс по ID
	for i := range valid {
		e.ruleByID[valid[i].ID] = &e.rules[ruleset.Category][i]
	}
	e.resolveCompositeScopesLocked()
	e.resolveContextLinksLocked()
	e.recomputeCapabilitiesLocked()
	e.mu.Unlock()

	logger.Info("Loaded rules",
		"file", srcName,
		"category", ruleset.Category,
		"version", ruleset.Version,
		"loaded", len(valid),
		"skipped", skipped,
	)

	return nil
}

// LoadRulesFromDir загружает все *.json файлы из директории
func (e *Engine) LoadRulesFromDir(dirPath string) error {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return fmt.Errorf("read rules directory %s: %w", dirPath, err)
	}

	loaded := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		// ✅ filepath.Join вместо fmt.Sprintf + os.PathSeparator
		fullPath := filepath.Join(dirPath, entry.Name())
		if err := e.LoadRulesFromFile(fullPath); err != nil {
			logger.Warn("Failed to load rules file", "file", entry.Name(), "error", err)
			continue
		}
		loaded++
	}

	logger.Info("Rules directory loaded", "dir", dirPath, "files", loaded)
	return nil
}

// ── Evaluation ─────────────────────────────────────────────────────────────

// EvaluateCondition проверяет одно условие.
// Operator: "not" инвертирует результат.
func (e *Engine) EvaluateCondition(cond Condition, ctx *ConditionContext) bool {
	result := e.evalConditionInner(cond, ctx)

	// Operator "not" инвертирует результат
	if cond.Operator == "not" {
		return !result
	}
	return result
}

// evalConditionInner — внутренняя проверка без учёта Operator
func (e *Engine) evalConditionInner(cond Condition, ctx *ConditionContext) bool {
	switch cond.Type {
	case "permission":
		return e.matchInSet(cond, ctx.permSet, ctx.Permissions)
	case "api_call":
		return e.matchInSet(cond, ctx.apiSet, ctx.APICalls)
	case "pattern":
		return e.matchInSet(cond, ctx.patternSet, ctx.Patterns)
	case "string":
		return e.matchInSet(cond, ctx.stringSet, ctx.Strings)
	case "class":
		return e.matchInSet(cond, ctx.classSet, ctx.Classes)
	case "method":
		return e.matchInSet(cond, ctx.methodSet, ctx.Methods)
	case "combo":
		return e.checkCombo(cond, ctx)
	default:
		return false
	}
}

// matchInSet проверяет наличие значения в set (O(1)) или slice (O(n) substring).
//
// Если cond.Exact=true → O(1) exact match через map.
// Если cond.Exact=false → O(n) substring match (как в оригинале, но на конкретном slice).
func (e *Engine) matchInSet(cond Condition, set map[string]struct{}, items []string) bool {
	if cond.Exact {
		return containsExact(set, cond.Value)
	}
	return containsSubstring(items, cond.Value)
}

// checkCombo проверяет, что все values из combo найдены ACROSS ALL context types.
// ✅ Fix: оригинал искал combo только в Permissions.
func (e *Engine) checkCombo(cond Condition, ctx *ConditionContext) bool {
	if len(cond.Values) == 0 {
		return false
	}

	for _, val := range cond.Values {
		found := false
		if cond.Exact {
			// O(1) проверка по всем set'ам
			found = containsExact(ctx.permSet, val) ||
				containsExact(ctx.apiSet, val) ||
				containsExact(ctx.patternSet, val) ||
				containsExact(ctx.stringSet, val) ||
				containsExact(ctx.classSet, val) ||
				containsExact(ctx.methodSet, val)
		} else {
			// O(n) substring по объединённому списку
			found = containsSubstring(ctx.allValues, val)
		}
		if !found {
			return false
		}
	}
	return true
}

// EvaluateRule проверяет правило полностью.
//
// Logic:
//   - "and" (default): все условия обязательны
//   - "or": хотя бы одно условие
//   - "threshold": минимум MinMatch условий
func (e *Engine) EvaluateRule(rule Rule, ctx *ConditionContext) bool {
	if len(rule.Requires) > 0 {
		// Композит: нужен доступ к другим правилам по ID.
		e.mu.RLock()
		defer e.mu.RUnlock()
		return e.matchRuleLocked(&rule, ctx, newMemo())
	}
	return e.evalOwnConditions(rule, ctx)
}

// evalOwnConditions проверяет только собственные Conditions правила
// (без Requires). Именно это делал EvaluateRule до появления композитов.
func (e *Engine) evalOwnConditions(rule Rule, ctx *ConditionContext) bool {
	if !rule.Enabled || len(rule.Conditions) == 0 {
		return false
	}

	// Lazy build: если контекст ещё не проиндексирован
	if !ctx.built {
		ctx.Build()
	}

	logic := rule.Logic
	if logic == "" {
		logic = "and"
	}

	switch logic {
	case "and":
		for _, cond := range rule.Conditions {
			if !e.EvaluateCondition(cond, ctx) {
				return false
			}
		}
		return true

	case "or":
		for _, cond := range rule.Conditions {
			if e.EvaluateCondition(cond, ctx) {
				return true
			}
		}
		return false

	case "threshold":
		matched := 0
		for _, cond := range rule.Conditions {
			if e.EvaluateCondition(cond, ctx) {
				matched++
			}
		}
		minRequired := rule.MinMatch
		if minRequired <= 0 {
			minRequired = len(rule.Conditions)
		}
		return matched >= minRequired

	default:
		return false
	}
}

// EvaluateAll оценивает ВСЕ enabled правила и возвращает результаты.
// Возвращает только сработавшие правила (Matched=true).
func (e *Engine) EvaluateAll(ctx *ConditionContext) []RuleEvaluationResult {
	return e.evaluateFiltered(ctx, nil)
}

// EvaluateGlobalRules оценивает только правила с APK-wide scope (не file-scoped).
// Используется для пермишен-правил и одиночных индикаторов, которые корректно
// проверять по всему APK сразу.
func (e *Engine) EvaluateGlobalRules(ctx *ConditionContext) []RuleEvaluationResult {
	return e.evaluateFiltered(ctx, func(r *Rule) bool { return !r.IsFileScoped() })
}

// EvaluateFileScopedRules оценивает только file-scoped поведенческие комбо
// против контекста ОДНОГО файла. Вызывается по разу на файл; вызывающий код
// дедуплицирует результаты по RuleID и проставляет MatchedFile.
func (e *Engine) EvaluateFileScopedRules(ctx *ConditionContext) []RuleEvaluationResult {
	return e.evaluateFiltered(ctx, func(r *Rule) bool { return r.IsFileScoped() })
}

// evaluateFiltered оценивает все enabled правила, проходящие предикат keep
// (keep==nil → все правила). Возвращает только сработавшие.
func (e *Engine) evaluateFiltered(ctx *ConditionContext, keep func(*Rule) bool) []RuleEvaluationResult {
	return e.evaluateDetailed(ctx, keep).Results
}

// ── Query ──────────────────────────────────────────────────────────────────

// GetRulesForCategory возвращает копию правил для категории
func (e *Engine) GetRulesForCategory(category string) []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	rules := e.rules[category]
	if len(rules) == 0 {
		return nil
	}
	result := make([]Rule, len(rules))
	copy(result, rules)
	return result
}

// GetRuleByID возвращает правило по ID (O(1) lookup)
func (e *Engine) GetRuleByID(id string) (*Rule, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	r, ok := e.ruleByID[id]
	return r, ok
}

// GetAllRules возвращает defensive copy всех правил
func (e *Engine) GetAllRules() map[string][]Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make(map[string][]Rule, len(e.rules))
	for k, v := range e.rules {
		cp := make([]Rule, len(v))
		copy(cp, v)
		result[k] = cp
	}
	return result
}

// Stats возвращает статистику загруженных правил
func (e *Engine) Stats() EngineStats {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var s EngineStats
	s.Categories = len(e.rules)
	for _, rules := range e.rules {
		s.TotalRules += len(rules)
		for i := range rules {
			if rules[i].Enabled {
				s.EnabledRules++
			}
		}
	}
	s.DisabledRules = s.TotalRules - s.EnabledRules
	return s
}

type EngineStats struct {
	Categories    int
	TotalRules    int
	EnabledRules  int
	DisabledRules int
}

func (s EngineStats) String() string {
	return fmt.Sprintf("Rules: %d total (%d enabled, %d disabled) across %d categories",
		s.TotalRules, s.EnabledRules, s.DisabledRules, s.Categories)
}

// ═══════════════════════════════════════════════════════════════════════════════
// EVALUATION RESULT
// ═══════════════════════════════════════════════════════════════════════════════

// RuleEvaluationResult — результат оценки одного правила.
// Создаётся EvaluateAll() для каждого сработавшего правила.
type RuleEvaluationResult struct {
	RuleID      string
	RuleName    string
	Category    string
	Matched     bool
	Score       int
	Severity    string
	Message     string
	References  []string
	Tags        []string
	MatchedFile string // file where a file-scoped rule fired ("" for global rules)

	// Confidence — уверенность правила (0..1), независимая от Severity.
	// Правила без явного значения дают 1.0.
	Confidence float64
	// DowngradedBy — ID context-правила, понизившего severity/score ("" если нет).
	DowngradedBy string
}

// IsCritical возвращает true если severity = critical
func (r *RuleEvaluationResult) IsCritical() bool {
	return r.Severity == "critical"
}

// IsHighOrAbove возвращает true если severity = high или critical
func (r *RuleEvaluationResult) IsHighOrAbove() bool {
	return r.Severity == "critical" || r.Severity == "high"
}
