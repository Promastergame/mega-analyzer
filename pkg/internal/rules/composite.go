package rules

import (
	"fmt"
	"sort"
	"strings"

	"mega-analyzer/pkg/logger"
)

// ═══════════════════════════════════════════════════════════════════════════════
// COMPOSITION LAYER (rules/v2)
//
// Плоские правила «условия → находка» плохо масштабируются: одна и та же
// подсказка («есть accessibility-сервис») нужна десяткам правил, а ложные
// срабатывания приходится гасить кодом в fpfilter. Этот слой добавляет три
// вещи, оставляя старый формат JSON полностью совместимым:
//
//   - Requires  — композит: правило срабатывает, когда сработали другие правила;
//   - Unless    — context-правило (известный безопасный контекст) гасит находку;
//   - Downgrade — context-правило понижает находку, но оставляет её видимой.
//
// Context-правила (Kind="context") — контракт «глушителей»: они не выдаются как
// находки, не могут быть положительным свидетельством, обязаны объяснять причину
// (Reason) и проверяются Lint() после загрузки всех наборов.
// ═══════════════════════════════════════════════════════════════════════════════

const (
	// KindDetect — обычное правило (значение по умолчанию).
	KindDetect = "detect"
	// KindContext — доброкачественный контекст, только для Unless/Downgrade.
	KindContext = "context"
)

// IsContext сообщает, что правило — context-«глушитель».
func (r *Rule) IsContext() bool { return strings.EqualFold(r.Kind, KindContext) }

// EffectiveConfidence возвращает Confidence с учётом умолчания (1.0).
func (r *Rule) EffectiveConfidence() float64 {
	if r.Confidence <= 0 {
		return 1.0
	}
	return r.Confidence
}

// validateComposition проверяет то, что можно проверить без остальных правил.
// Ссылки на другие правила проверяет Lint (нужен полный набор).
func (r *Rule) validateComposition() error {
	switch strings.ToLower(r.Kind) {
	case "", KindDetect, KindContext:
	default:
		return fmt.Errorf("rule %q has invalid kind %q", r.ID, r.Kind)
	}
	if r.Confidence < 0 || r.Confidence > 1 {
		return fmt.Errorf("rule %q has invalid confidence %v (must be 0..1)", r.ID, r.Confidence)
	}
	for _, list := range [][]string{r.Requires, r.Unless, r.Downgrade} {
		for _, id := range list {
			if strings.TrimSpace(id) == "" {
				return fmt.Errorf("rule %q references an empty rule ID", r.ID)
			}
			if id == r.ID {
				return fmt.Errorf("rule %q references itself", r.ID)
			}
		}
	}
	if !r.IsContext() && (len(r.Suppresses) > 0 || len(r.Downgrades) > 0) {
		return fmt.Errorf("rule %q: suppresses/downgrades are allowed only on context rules", r.ID)
	}
	for _, list := range [][]string{r.Suppresses, r.Downgrades} {
		for _, sel := range list {
			if strings.TrimSpace(sel) == "" || sel == "*" {
				return fmt.Errorf("context rule %q has an empty or catch-all selector %q", r.ID, sel)
			}
		}
	}
	if r.IsContext() {
		if len(r.Unless) > 0 || len(r.Downgrade) > 0 {
			return fmt.Errorf("context rule %q must not have unless/downgrade", r.ID)
		}
		if strings.TrimSpace(r.Reason) == "" {
			return fmt.Errorf("context rule %q must explain why it is benign (reason)", r.ID)
		}
	}
	return nil
}

func findDuplicateID(rules []Rule, id string) bool {
	for i := range rules {
		if rules[i].ID == id {
			return true
		}
	}
	return false
}

// ── Memo ───────────────────────────────────────────────────────────────────

// evalMemo кэширует результат правила в рамках ОДНОЙ оценки контекста, чтобы
// общий член композитов и context-правило считались один раз.
type evalMemo struct {
	done       map[string]bool
	inProgress map[string]bool
}

func newMemo() *evalMemo {
	return &evalMemo{done: make(map[string]bool), inProgress: make(map[string]bool)}
}

// matchRuleLocked — сработало ли правило на ctx с учётом Requires. Вызывающий
// держит e.mu. Цикл по Requires трактуется как «не сработало» (Lint сообщит).
func (e *Engine) matchRuleLocked(rule *Rule, ctx *ConditionContext, memo *evalMemo) bool {
	if rule.ID != "" {
		if v, ok := memo.done[rule.ID]; ok {
			return v
		}
		if memo.inProgress[rule.ID] {
			return false
		}
		memo.inProgress[rule.ID] = true
		defer delete(memo.inProgress, rule.ID)
	}

	result := e.matchUncachedLocked(rule, ctx, memo)
	if rule.ID != "" {
		memo.done[rule.ID] = result
	}
	return result
}

func (e *Engine) matchUncachedLocked(rule *Rule, ctx *ConditionContext, memo *evalMemo) bool {
	if !rule.Enabled {
		return false
	}
	if len(rule.Conditions) > 0 && !e.evalOwnConditions(*rule, ctx) {
		return false
	}
	for _, id := range rule.Requires {
		member, ok := e.ruleByID[id]
		if !ok || member.IsContext() {
			return false
		}
		if !e.matchRuleLocked(member, ctx, memo) {
			return false
		}
	}
	return len(rule.Conditions) > 0 || len(rule.Requires) > 0
}

// firstMatchedContext возвращает первое сработавшее context-правило из ids.
func (e *Engine) firstMatchedContext(ids []string, ctx *ConditionContext, memo *evalMemo) *Rule {
	for _, id := range ids {
		c, ok := e.ruleByID[id]
		if !ok || !c.IsContext() {
			continue
		}
		if e.matchRuleLocked(c, ctx, memo) {
			return c
		}
	}
	return nil
}

// ── Detailed evaluation ────────────────────────────────────────────────────

// Suppression описывает находку, погашенную context-правилом. Раньше такие
// подавления были невидимы; теперь их можно показать и проверить.
type Suppression struct {
	RuleID string // погашенное правило
	By     string // context-правило
	Reason string // почему контекст безопасен (Reason context-правила)
}

// Evaluation — полный итог оценки: находки и подавления.
type Evaluation struct {
	Results    []RuleEvaluationResult
	Suppressed []Suppression
}

// EvaluateDetailed оценивает все правила и возвращает и находки, и подавления.
func (e *Engine) EvaluateDetailed(ctx *ConditionContext) Evaluation {
	return e.evaluateDetailed(ctx, nil)
}

func (e *Engine) evaluateDetailed(ctx *ConditionContext, keep func(*Rule) bool) Evaluation {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if !ctx.built {
		ctx.BuildFor(e.needsExactSets, e.needsAllValues)
	}

	memo := newMemo()
	var out Evaluation

	// Детерминированный порядок категорий: результаты не должны зависеть от
	// случайного порядка обхода map.
	categories := make([]string, 0, len(e.rules))
	for c := range e.rules {
		categories = append(categories, c)
	}
	sort.Strings(categories)

	for _, category := range categories {
		rules := e.rules[category]
		for i := range rules {
			rule := &rules[i]
			if rule.IsContext() {
				continue
			}
			if keep != nil && !keep(rule) {
				continue
			}
			if !e.matchRuleLocked(rule, ctx, memo) {
				continue
			}

			if by := e.firstMatchedContext(e.unlessFor(rule), ctx, memo); by != nil {
				out.Suppressed = append(out.Suppressed, Suppression{RuleID: rule.ID, By: by.ID, Reason: by.Reason})
				logger.Debug("Rule suppressed by context", "rule", rule.ID, "context", by.ID, "reason", by.Reason)
				continue
			}

			res := RuleEvaluationResult{
				RuleID:      rule.ID,
				RuleName:    rule.Name,
				Category:    category,
				RuleCategory: rule.Category,
				Matched:     true,
				Score:       rule.Score,
				Severity:    rule.Severity,
				Message:     rule.Description,
				References:  rule.References,
				Tags:        rule.Tags,
				Confidence:  rule.EffectiveConfidence(),
				FindingKind: rule.FindingKind,
				Evidence:    e.ruleEvidenceLocked(rule, ctx, make(map[string]bool)),
				Limitations: append([]string(nil), rule.Limitations...),
				NextChecks:  append([]string(nil), rule.NextChecks...),
			}
			// A threshold may have matched only manifest declarations even when
			// the rule also lists APIs. Declarations establish a permission
			// profile, not a malware family, a grant or an implemented attack.
			if onlyPermissionEvidence(res.Evidence) {
				res.FindingKind = "inventory"
				res.Severity, res.Score = "info", 0
				res.Message = "Manifest declarations match this permission profile. Requested or service-binding permissions do not establish grants, data collection, transmission or malware attribution."
				res.RuleName = "Manifest permission profile"
			}
			if by := e.firstMatchedContext(e.downgradeFor(rule), ctx, memo); by != nil {
				res.Score /= 2
				res.Severity = lowerSeverity(res.Severity)
				res.DowngradedBy = by.ID
			}
			out.Results = append(out.Results, res)
		}
	}
	return out
}

// unlessFor / downgradeFor — явные ссылки правила плюс context-правила,
// нацелившиеся на него селекторами.
func (e *Engine) unlessFor(r *Rule) []string {
	return joinIDs(r.Unless, e.suppressBy[r.ID])
}

func (e *Engine) downgradeFor(r *Rule) []string {
	return joinIDs(r.Downgrade, e.downgradeBy[r.ID])
}

func joinIDs(a, b []string) []string {
	if len(b) == 0 {
		return a
	}
	if len(a) == 0 {
		return b
	}
	out := make([]string, 0, len(a)+len(b))
	return append(append(out, a...), b...)
}

// selectorMatches проверяет селектор context-правила против цели.
func selectorMatches(sel string, r *Rule) bool {
	switch {
	case strings.HasPrefix(sel, "tag:"):
		want := strings.TrimPrefix(sel, "tag:")
		for _, t := range r.Tags {
			if strings.EqualFold(t, want) {
				return true
			}
		}
		return false
	case strings.HasPrefix(sel, "category:"):
		return strings.EqualFold(r.Category, strings.TrimPrefix(sel, "category:"))
	case strings.HasSuffix(sel, "*"):
		return strings.HasPrefix(r.ID, strings.TrimSuffix(sel, "*"))
	default:
		return r.ID == sel
	}
}

// resolveContextLinksLocked строит обратный индекс селекторов. Вызывать под
// e.mu.Lock после любой загрузки.
func (e *Engine) resolveContextLinksLocked() {
	e.suppressBy = make(map[string][]string)
	e.downgradeBy = make(map[string][]string)

	var contexts []*Rule
	for _, rules := range e.rules {
		for i := range rules {
			if rules[i].IsContext() && (len(rules[i].Suppresses) > 0 || len(rules[i].Downgrades) > 0) {
				contexts = append(contexts, &rules[i])
			}
		}
	}
	if len(contexts) == 0 {
		return
	}
	sort.Slice(contexts, func(i, j int) bool { return contexts[i].ID < contexts[j].ID })

	for _, rules := range e.rules {
		for i := range rules {
			target := &rules[i]
			if target.IsContext() {
				continue
			}
			for _, c := range contexts {
				for _, sel := range c.Suppresses {
					if selectorMatches(sel, target) {
						e.suppressBy[target.ID] = append(e.suppressBy[target.ID], c.ID)
						break
					}
				}
				for _, sel := range c.Downgrades {
					if selectorMatches(sel, target) {
						e.downgradeBy[target.ID] = append(e.downgradeBy[target.ID], c.ID)
						break
					}
				}
			}
		}
	}
}

var severityLadder = []string{"info", "low", "medium", "high", "critical"}

// lowerSeverity опускает severity на одну ступень (info — дно, пустая строка
// остаётся пустой).
func lowerSeverity(s string) string {
	for i, name := range severityLadder {
		if name == s {
			if i == 0 {
				return s
			}
			return severityLadder[i-1]
		}
	}
	return s
}

// ── Composite scope ────────────────────────────────────────────────────────

// resolveCompositeScopesLocked переносит file-scope на композиты: если хоть один
// член композита (транзитивно) file-scoped, композит без явного Scope тоже
// file-scoped. Иначе композит, собранный из «файловых» членов, оценивался бы на
// контексте всего APK и возвращал ложные срабатывания «разбросанных» признаков —
// ровно то, от чего file-scope защищает обычные правила. Вызывать под e.mu.Lock.
func (e *Engine) resolveCompositeScopesLocked() {
	visiting := make(map[string]bool)
	var fileScoped func(r *Rule) bool
	fileScoped = func(r *Rule) bool {
		if r.Scope != "" || len(r.Requires) == 0 {
			return r.computeFileScoped()
		}
		if visiting[r.ID] {
			return false
		}
		visiting[r.ID] = true
		defer delete(visiting, r.ID)
		if r.computeFileScoped() {
			return true
		}
		for _, id := range r.Requires {
			if m, ok := e.ruleByID[id]; ok && fileScoped(m) {
				return true
			}
		}
		return false
	}
	for _, rules := range e.rules {
		for i := range rules {
			r := &rules[i]
			r.scopeIsFile = fileScoped(r)
			r.scopeResolved = true
		}
	}
}

// ── Health & Lint ──────────────────────────────────────────────────────────

func (e *Engine) setSkippedLocked(category string, n int) {
	if e.skipped == nil {
		e.skipped = make(map[string]int)
	}
	if n == 0 {
		delete(e.skipped, category)
		return
	}
	e.skipped[category] = n
}

// Health — состояние набора правил. Урезанный набор (часть правил отброшена
// валидацией, битые ссылки в композитах) даёт вердикты, которым нельзя верить
// как «чисто»: см. пакет verdict, код выхода 4.
type Health struct {
	Loaded     int
	Skipped    int
	LintErrors int
}

// Degraded — набор правил неполон или внутренне противоречив.
func (h Health) Degraded() bool { return h.Skipped > 0 || h.LintErrors > 0 }

func (h Health) String() string {
	return fmt.Sprintf("rules: %d loaded, %d skipped, %d lint errors", h.Loaded, h.Skipped, h.LintErrors)
}

// Health возвращает сводку по загруженным правилам (включая Lint).
func (e *Engine) Health() Health {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var h Health
	for _, rs := range e.rules {
		h.Loaded += len(rs)
	}
	for _, n := range e.skipped {
		h.Skipped += n
	}
	for _, is := range e.lintLocked() {
		if is.Level == LintError {
			h.LintErrors++
		}
	}
	return h
}

// LintLevel — серьёзность замечания.
type LintLevel string

const (
	LintError LintLevel = "error"
	LintWarn  LintLevel = "warn"
)

// LintIssue — замечание к набору правил.
type LintIssue struct {
	Level   LintLevel
	RuleID  string
	Message string
}

func (i LintIssue) String() string { return fmt.Sprintf("[%s] %s: %s", i.Level, i.RuleID, i.Message) }

// Lint проверяет межправиловые контракты. Вызывать после загрузки ВСЕХ наборов:
// ссылки могут вести в другую категорию.
func (e *Engine) Lint() []LintIssue {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.lintLocked()
}

func (e *Engine) lintLocked() []LintIssue {
	var issues []LintIssue
	add := func(level LintLevel, id, format string, a ...any) {
		issues = append(issues, LintIssue{Level: level, RuleID: id, Message: fmt.Sprintf(format, a...)})
	}

	referencedContext := make(map[string]bool)

	ids := make([]string, 0, len(e.ruleByID))
	for id := range e.ruleByID {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for _, id := range ids {
		r := e.ruleByID[id]

		for _, ref := range r.Requires {
			m, ok := e.ruleByID[ref]
			switch {
			case !ok:
				add(LintError, id, "requires unknown rule %q", ref)
			case m.IsContext():
				add(LintError, id, "requires context rule %q: context is never positive evidence", ref)
			case !m.Enabled && r.Enabled:
				add(LintWarn, id, "requires disabled rule %q, so it can never fire", ref)
			}
		}
		for _, list := range []struct {
			name string
			ids  []string
		}{{"unless", r.Unless}, {"downgrade", r.Downgrade}} {
			for _, ref := range list.ids {
				m, ok := e.ruleByID[ref]
				switch {
				case !ok:
					add(LintError, id, "%s references unknown rule %q", list.name, ref)
				case !m.IsContext():
					add(LintError, id, "%s target %q is not a context rule (kind=\"context\")", list.name, ref)
				default:
					referencedContext[ref] = true
				}
			}
		}
	}

	for _, list := range []map[string][]string{e.suppressBy, e.downgradeBy} {
		for _, ctxIDs := range list {
			for _, c := range ctxIDs {
				referencedContext[c] = true
			}
		}
	}
	for _, id := range ids {
		r := e.ruleByID[id]
		if r.IsContext() && !referencedContext[id] {
			add(LintWarn, id, "context rule matches no rule: nothing references it by unless/downgrade or suppresses/downgrades selector")
		}
	}

	// Циклы по Requires (DFS с раскраской).
	const (
		white = 0
		grey  = 1
		black = 2
	)
	color := make(map[string]int, len(ids))
	var dfs func(id string, path []string)
	reported := make(map[string]bool)
	dfs = func(id string, path []string) {
		color[id] = grey
		path = append(path, id)
		if r, ok := e.ruleByID[id]; ok {
			for _, ref := range r.Requires {
				if _, exists := e.ruleByID[ref]; !exists {
					continue
				}
				switch color[ref] {
				case white:
					dfs(ref, path)
				case grey:
					if !reported[ref] {
						reported[ref] = true
						add(LintError, ref, "requires cycle: %s -> %s", strings.Join(path, " -> "), ref)
					}
				}
			}
		}
		color[id] = black
	}
	for _, id := range ids {
		if color[id] == white {
			dfs(id, nil)
		}
	}

	return issues
}
