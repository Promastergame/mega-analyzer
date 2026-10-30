package crackpoint

import (
	"fmt"
	"mega-analyzer/pkg/internal/cfg"
	"strings"
)

// invokeNoisePrefixes — class prefixes in invoke operands that should not
// generate crack-point candidates when a gate pattern matches their method
// name.  These are analytics/attribution/support SDKs whose method naming
// happens to look like license/billing gates but is unrelated.
var invokeNoisePrefixes = []string{
	"lcom/appsflyer", "lcom/adjust", "lio/sentry", "lcom/crashlytics",
	"lcom/google/firebase/installations", "lcom/google/firebase/messaging",
	"lcom/google/firebase/analytics", "lcom/google/firebase/perf",
	"lcom/helpshift", "lcom/usercentrics", "lcom/snowplow",
}

func isNoisyInvoke(raw string) bool {
	lower := strings.ToLower(raw)
	if strings.Contains(lower, "lcom/appsflyer/lvl/") {
		return false
	}
	for _, prefix := range invokeNoisePrefixes {
		if strings.Contains(lower, prefix) {
			return true
		}
	}
	return false
}

// ═══════════════════════════════════════════════════════════════════════════════
// CRACK POINT DISCOVERY ENGINE
// ═══════════════════════════════════════════════════════════════════════════════
//
// Задача: найти все «decision points» — места в коде, от которых зависит,
// будет ли приложение работать в Premium / Licensed / Ad-free режиме.
//
// Алгоритм:
//  1. Обнаружение Gate Methods (isPremium, isLicensed, checkRoot и др.)
//  2. Impact Analysis — какие участки зависят от результата gate
//  3. Crack Suggestions — рекомендации по операции для обхода
//  4. Dependency Graph — как далеко «разлетится» патч
//
// ═══════════════════════════════════════════════════════════════════════════════
const (
	// HighConfidenceThreshold — порог для «уверенного» обнаружения точки взлома
	HighConfidenceThreshold = 0.75
)

// CrackPoint — обнаруженная точка, влияющая на ключевую логику защиты
type CrackPoint struct {
	// Идентификация
	MethodName string `json:"method_name"`
	ClassName  string `json:"class_name"`
	NodeID     int    `json:"node_id,omitempty"`
	Line       int    `json:"line,omitempty"`

	// Классификация
	Type       CrackPointType `json:"type"`
	Category   string         `json:"category"` // premium, license, root, debug, billing, tamper
	Confidence float64        `json:"confidence"`

	// Анализ
	ReturnType   string   `json:"return_type"`
	Signals      []string `json:"signals"`
	Impact       int      `json:"impact"`       // сколько мест зависит от этого результата
	Dependencies []string `json:"dependencies"` // от чего зависит сам этот метод
	Dependents   []string `json:"dependents"`   // кто зависит от результата этого метода

	// Рекомендации
	SuggestedAction  string `json:"suggested_action"`
	SuggestedPatch   string `json:"suggested_patch,omitempty"`
	PatchRisk        string `json:"patch_risk"` // low, medium, high, critical
	PatchExplanation string `json:"patch_explanation"`
}

// CrackPointType — тип точки взлома
type CrackPointType int

const (
	CrackPointGateMethod   CrackPointType = iota // метод-гейт (isPremium, isLicensed)
	CrackPointCondition                          // условие (if checkFailed → exit)
	CrackPointCallback                           // callback (onLicenseResult)
	CrackPointFieldCheck                         // проверка поля (this.isPro)
	CrackPointInvokeResult                       // результат вызова (billing.query())
)

var crackPointTypeNames = [...]string{
	"gate_method", "condition", "callback", "field_check", "invoke_result",
}

func (t CrackPointType) String() string {
	if int(t) < len(crackPointTypeNames) {
		return crackPointTypeNames[t]
	}
	return "unknown"
}

// AnalysisResult — полный результат поиска точек взлома
type AnalysisResult struct {
	CrackPoints    []CrackPoint   `json:"crack_points"`
	TotalFound     int            `json:"total_found"`
	HighConfidence int            `json:"high_confidence"` // confidence >= HighConfidenceThreshold
	Categories     map[string]int `json:"categories"`

	// Dependency graph
	MethodDeps map[string][]string `json:"method_deps,omitempty"`
}

// ═══════════════════════════════════════════════════════════════════════════════
// FINDER ENGINE
// ═══════════════════════════════════════════════════════════════════════════════

// Finder — движок поиска точек взлома
type Finder struct {
	gatePatterns     []gatePattern
	fieldPatterns    []string
	callbackPatterns []string
}

type gatePattern struct {
	namePattern string
	category    string
	weight      float64
}

// NewFinder создаёт движок поиска точек взлома
func NewFinder() *Finder {
	return &Finder{
		gatePatterns: defaultGatePatterns(),
		fieldPatterns: []string{
			"ispremium", "ispro", "isvip", "isfree", "issubscribed",
			"islicensed", "isregistered", "isactivated", "istrialexpired",
			"ispaid", "isunlocked", "haslicense", "haspurchased",
			"adsenabled", "showads", "removeads", "adfree",
			"safetynet", "playintegrity", "integrity",
			// Trial / genuineness / validity flags.
			"istrial", "isexpired", "isgenuine", "isvalid", "isactive",
			"isunlimited", "isfullversion", "islimited", "islocked",
			// Anti-instrumentation flags.
			"isrooted", "isemulator", "isdebug", "isxposed", "isfrida",
			"ishooked", "istampered", "isdebuggable",
		},
		callbackPatterns: []string{
			"onlicenseresult", "onpurchaseresult", "onbillingresult",
			"onlicensecheckresult", "licenseresult", "purchasecallback",
			"verificationresult", "onverified", "onauthresult",
			"onsubscriptionresult", "onvalidated",
			"onsafetynet", "onintegrity", "onattestation",
			// Google LVL LicenseCheckerCallback methods — the actual decision
			// sinks: allow() grants access, dontAllow()/applicationError() deny.
			"dontallow", "applicationerror", "onlicensingerror",
			// Billing v5+ purchase lifecycle callbacks.
			"onacknowledgepurchaseresponse", "onconsumeresponse",
			"onpurchasesupdated", "onrestorepurchases", "onproductdetailsresponse",
		},
	}
}

// defaultGatePatterns — предустановленные паттерны gate-методов
func defaultGatePatterns() []gatePattern {
	return []gatePattern{
		// Premium / Pro
		{"ispremium", "premium", 0.95},
		{"ispro", "premium", 0.90},
		{"isvip", "premium", 0.90},
		{"isfreeuser", "premium", 0.85},
		{"issubscribed", "premium", 0.90},
		{"checkpremium", "premium", 0.90},
		{"haspremium", "premium", 0.85},
		{"getsubscriptionstatus", "premium", 0.80},

		// License
		{"islicensed", "license", 0.95},
		{"checklicense", "license", 0.95},
		{"verifylicense", "license", 0.95},
		{"validatelicense", "license", 0.90},
		{"isregistered", "license", 0.85},
		{"isactivated", "license", 0.85},
		{"istrialexpired", "license", 0.80},
		{"checklicensevalid", "license", 0.95},
		{"getlicensestate", "license", 0.90},
		// Google LVL (License Verification Library) — the single most common
		// Android license gate. checkAccess() drives the LicenseCheckerCallback,
		// getLVLResult / the Policy.allowAccess result is the boolean sink.
		{"checkaccess", "license", 0.90},
		{"allowaccess", "license", 0.90},
		{"getlvlresult", "license", 0.92},
		{"licensechecker", "license", 0.88},
		{"processserverresponse", "license", 0.80},
		// Trial / expiry / genuineness gates.
		{"istrial", "license", 0.80},
		{"isexpired", "license", 0.82},
		{"checkexpiry", "license", 0.82},
		{"isgenuine", "license", 0.85},
		{"isvalidlicense", "license", 0.90},
		{"getremainingdays", "license", 0.75},
		{"getdaysleft", "license", 0.75},
		{"verifyonserver", "license", 0.85},
		{"servervalidate", "license", 0.82},

		// Root detection
		{"isrooted", "root", 0.95},
		{"isdevicerooted", "root", 0.95},
		{"checkroot", "root", 0.90},
		{"detectroot", "root", 0.90},
		{"checksuperuser", "root", 0.85},
		{"checksu", "root", 0.85},
		{"ismagiskpresent", "root", 0.90},
		{"checkbusybox", "root", 0.80},
		// RootBeer is the de-facto root-check library; its class path shows
		// up in invokes even when the app's own method names are obfuscated.
		{"rootbeer", "root", 0.88},

		// Anti-hooking / anti-instrumentation (Frida, Xposed, Substrate).
		{"detectfrida", "tamper", 0.90},
		{"isfridadetected", "tamper", 0.90},
		{"checkxposed", "tamper", 0.90},
		{"isxposed", "tamper", 0.90},
		{"detecthook", "tamper", 0.85},
		{"antihook", "tamper", 0.85},
		{"ishooked", "tamper", 0.85},
		{"isinstrumented", "tamper", 0.80},

		// Debug / Tamper
		{"isdebuggable", "debug", 0.90},
		{"isdebugging", "debug", 0.90},
		{"checkdebug", "debug", 0.85},
		{"isadbenabled", "debug", 0.80},
		{"istampered", "tamper", 0.90},
		{"checksignature", "tamper", 0.90},
		{"verifysignature", "tamper", 0.90},
		{"checkintegrity", "tamper", 0.90},
		{"verifyintegrity", "tamper", 0.85},
		{"ismodified", "tamper", 0.80},

		// Billing
		{"checkpurchase", "billing", 0.90},
		{"verifypurchase", "billing", 0.90},
		{"querypurchases", "billing", 0.85},
		{"ispurchased", "billing", 0.90},
		{"hasvalidpurchase", "billing", 0.90},
		{"validatereceipt", "billing", 0.85},
		// Play Billing v5+ subscription lifecycle.
		{"acknowledgepurchase", "billing", 0.85},
		{"verifysubscription", "billing", 0.90},
		{"issubscriptionactive", "billing", 0.90},
		{"getpurchasetoken", "billing", 0.75},
		{"handlepurchase", "billing", 0.80},
		{"verifyvalidsignature", "billing", 0.90},
		// Play Billing v5–v7 entry point for the purchase flow.
		{"queryproductdetails", "billing", 0.80},

		// Ad control
		{"shouldshowads", "ads", 0.85},
		{"isadsremoved", "ads", 0.85},
		{"hasremoveads", "ads", 0.80},
		{"isadmobloaded", "ads", 0.70},

		// Emulator detection
		{"isemulator", "emulator", 0.90},
		{"checkemulator", "emulator", 0.85},
		{"detectemulator", "emulator", 0.85},
		{"isvirtualdevice", "emulator", 0.85},

		// SafetyNet / Play Integrity / Attestation
		{"safetynet", "tamper", 0.95},
		{"playintegrity", "tamper", 0.95},
		{"integritymanager", "tamper", 0.90},
		{"attest", "tamper", 0.85},
		{"verifywithserver", "tamper", 0.85},
		{"getpackagesignatures", "tamper", 0.90},
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN ANALYSIS
// ═══════════════════════════════════════════════════════════════════════════════

// FindCrackPoints выполняет полный поиск точек взлома в CFG
func (f *Finder) FindCrackPoints(graph *cfg.ControlFlowGraph, className string) *AnalysisResult {
	if graph == nil {
		return &AnalysisResult{Categories: make(map[string]int)}
	}

	result := &AnalysisResult{
		Categories: make(map[string]int),
		MethodDeps: make(map[string][]string),
	}

	// ── 1. Сканируем все ноды на gate patterns ───────────────
	f.scanForGateNodes(graph, className, result)

	// ── 2. Сканируем на field-based проверки ─────────────────
	f.scanForFieldChecks(graph, className, result)

	// ── 3. Сканируем invoke-вызовы к gate-методам ────────────
	f.scanForGateInvocations(graph, className, result)

	// ── 3b. Сканируем SafetyNet / Play Integrity / Подписи ───
	f.scanForAdvancedTamperAndIntegrity(graph, className, result)

	// ── 3c. Схлопываем дубликаты от нескольких скан-проходов ──
	// scanForGateNodes, scanForGateInvocations и scanForAdvancedTamperAndIntegrity
	// могут пометить одну и ту же инструкцию (напр. invoke к safetynet, чьё имя
	// совпадает и с gate-паттерном, и с advanced-tamper-веткой). Без схлопывания
	// в отчёт попадают две-три «точки» на одну строку кода.
	result.CrackPoints = dedupeCrackPoints(result.CrackPoints)

	// ── 4. Анализируем Impact (зависимости) ──────────────────
	f.analyzeImpact(graph, result)

	// ── 5. Генерируем Crack Suggestions ──────────────────────
	f.generateSuggestions(result)

	// Финальная статистика
	result.TotalFound = len(result.CrackPoints)
	for _, cp := range result.CrackPoints {
		if cp.Confidence >= HighConfidenceThreshold {
			result.HighConfidence++
		}
		result.Categories[cp.Category]++
	}

	return result
}

// ═══════════════════════════════════════════════════════════════════════════════
// SCAN PASSES
// ═══════════════════════════════════════════════════════════════════════════════

// scanForGateNodes ищет ноды с вызовами gate-методов
func (f *Finder) scanForGateNodes(graph *cfg.ControlFlowGraph, className string, result *AnalysisResult) {
	for _, node := range graph.Nodes {
		for _, instr := range node.Instructions {
			if !strings.HasPrefix(instr.Opcode, "invoke") {
				continue
			}
			// Skip invocations targeting known analytics/attribution SDK
			// classes — their method names collide with gate patterns but
			// the calling class is not a protection gate itself.
			if isNoisyInvoke(instr.Raw) {
				continue
			}

			methodRef := strings.ToLower(instr.Raw)

			for _, gp := range f.gatePatterns {
				if !strings.Contains(methodRef, gp.namePattern) {
					continue
				}

				cp := CrackPoint{
					ClassName:  className,
					MethodName: f.extractMethodName(instr.Raw),
					NodeID:     node.ID,
					Line:       instr.Index,
					Type:       CrackPointGateMethod,
					Category:   gp.category,
					Confidence: gp.weight,
					Signals: []string{
						fmt.Sprintf("Gate method pattern: %s", gp.namePattern),
						fmt.Sprintf("Invoked at node %d", node.ID),
					},
				}

				// Повышаем уверенность если метод возвращает boolean
				if f.isFollowedByBooleanCheck(node, instr.Index) {
					cp.Confidence = minFloat(cp.Confidence+0.05, 1.0)
					cp.ReturnType = "boolean"
					cp.Signals = append(cp.Signals, "Followed by boolean condition check")
				}

				result.CrackPoints = append(result.CrackPoints, cp)
				break
			}
		}
	}
}

// scanForFieldChecks ищет field-based проверки (iget-boolean + if)
func (f *Finder) scanForFieldChecks(graph *cfg.ControlFlowGraph, className string, result *AnalysisResult) {
	for _, node := range graph.Nodes {
		for _, instr := range node.Instructions {
			if !strings.HasPrefix(instr.Opcode, "iget-boolean") &&
				!strings.HasPrefix(instr.Opcode, "sget-boolean") {
				continue
			}

			fieldRef := strings.ToLower(instr.Raw)

			for _, fp := range f.fieldPatterns {
				if !strings.Contains(fieldRef, fp) {
					continue
				}

				cp := CrackPoint{
					ClassName:  className,
					MethodName: f.extractFieldName(instr.Raw),
					NodeID:     node.ID,
					Line:       instr.Index,
					Type:       CrackPointFieldCheck,
					Category:   f.categorizeField(fp),
					Confidence: 0.75,
					ReturnType: "boolean",
					Signals: []string{
						fmt.Sprintf("Boolean field pattern: %s", fp),
						fmt.Sprintf("Field access at node %d", node.ID),
					},
				}

				result.CrackPoints = append(result.CrackPoints, cp)
				break
			}
		}
	}
}

// scanForGateInvocations ищет вызовы Gate-методов и callback-паттерны
func (f *Finder) scanForGateInvocations(graph *cfg.ControlFlowGraph, className string, result *AnalysisResult) {
	for _, node := range graph.Nodes {
		for _, instr := range node.Instructions {
			if !strings.HasPrefix(instr.Opcode, "invoke") {
				continue
			}
			if isNoisyInvoke(instr.Raw) {
				continue
			}

			methodRef := strings.ToLower(instr.Raw)

			for _, cb := range f.callbackPatterns {
				if !strings.Contains(methodRef, cb) {
					continue
				}

				cp := CrackPoint{
					ClassName:  className,
					MethodName: f.extractMethodName(instr.Raw),
					NodeID:     node.ID,
					Line:       instr.Index,
					Type:       CrackPointCallback,
					Category:   "callback",
					Confidence: 0.80,
					Signals: []string{
						fmt.Sprintf("Callback pattern: %s", cb),
						fmt.Sprintf("Callback invoked at node %d", node.ID),
					},
				}

				result.CrackPoints = append(result.CrackPoints, cp)
				break
			}
		}
	}
}

// scanForAdvancedTamperAndIntegrity scans for SafetyNet, Play Integrity, and signature/certificate extraction checks
func (f *Finder) scanForAdvancedTamperAndIntegrity(graph *cfg.ControlFlowGraph, className string, result *AnalysisResult) {
	for _, node := range graph.Nodes {
		for _, instr := range node.Instructions {
			if !strings.HasPrefix(instr.Opcode, "invoke") {
				continue
			}
			// Same analytics-SDK noise gate as the other invoke passes:
			// without it e.g. an attribution SDK method whose name contains
			// "integrity"/"signature" is reported as a tamper check.
			if isNoisyInvoke(instr.Raw) {
				continue
			}

			methodRef := strings.ToLower(instr.Raw)
			isTamper := false
			category := "tamper"
			confidence := 0.85
			var signals []string

			if strings.Contains(methodRef, "safetynet") || strings.Contains(methodRef, "gms/safetynet") {
				isTamper = true
				category = "tamper"
				confidence = 0.90
				signals = append(signals, "SafetyNet attestation invoke pattern")
			}
			if strings.Contains(methodRef, "play/core/integrity") || strings.Contains(methodRef, "playintegrity") || strings.Contains(methodRef, "integritymanager") {
				isTamper = true
				category = "tamper"
				confidence = 0.95
				signals = append(signals, "Play Integrity check invoke pattern")
			}
			if strings.Contains(methodRef, "signature") && (strings.Contains(methodRef, "tobytearray") || strings.Contains(methodRef, "get_signatures") || strings.Contains(methodRef, "get_signing_certificates") || strings.Contains(methodRef, "getpackagemanager") || strings.Contains(methodRef, "getpackageinfo")) {
				isTamper = true
				category = "security"
				confidence = 0.85
				signals = append(signals, "Signature/Certificate extraction pattern")
			}

			if isTamper {
				cp := CrackPoint{
					ClassName:  className,
					MethodName: f.extractMethodName(instr.Raw),
					NodeID:     node.ID,
					Line:       instr.Index,
					Type:       CrackPointInvokeResult,
					Category:   category,
					Confidence: confidence,
					Signals:    signals,
				}
				result.CrackPoints = append(result.CrackPoints, cp)
			}
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// IMPACT ANALYSIS
// ═══════════════════════════════════════════════════════════════════════════════

// categoryBaseImpact is the minimum semantic impact for a crack point category,
// independent of how many CFG nodes depend on the gate. A single-node LVL
// license callback is still a 9/10 target even if its local CFG is trivial.
var categoryBaseImpact = map[string]int{
	"license":  9, // Google LVL, custom license gates — primary target
	"tamper":   8, // Play Integrity, SafetyNet, signature checks
	"billing":  8, // purchase verification — primary target
	"root":     6, // root detection bypass
	"emulator": 5, // emulator detection bypass
	"debug":    5, // debugger/decompiler detection bypass
	"premium":  4, // premium/pro flag gates
	"ads":      3, // ad-removal gates
	"callback": 4, // billing/license callbacks
	"security": 5, // generic security checks
}

func (f *Finder) analyzeImpact(graph *cfg.ControlFlowGraph, result *AnalysisResult) {
	if graph == nil {
		// Even without a graph we can assign category-based semantic impact.
		for i := range result.CrackPoints {
			cp := &result.CrackPoints[i]
			if base, ok := categoryBaseImpact[cp.Category]; ok {
				cp.Impact = base
			}
		}
		return
	}

	for i := range result.CrackPoints {
		cp := &result.CrackPoints[i]
		node := graph.GetNode(cp.NodeID)

		dependentCount := 0
		if node != nil {
			// Count CFG nodes reachable from this gate node.
			visited := make(map[int]bool)
			queue := make([]*cfg.CFGNode, 0, len(node.Successors))
			for _, succ := range node.Successors {
				queue = append(queue, succ)
			}
			for len(queue) > 0 {
				current := queue[0]
				queue = queue[1:]
				if visited[current.ID] {
					continue
				}
				visited[current.ID] = true
				dependentCount++
				for _, succ := range current.Successors {
					if !visited[succ.ID] {
						queue = append(queue, succ)
					}
				}
			}
		}

		// Impact = max(category semantic base, local CFG reach).
		// This ensures getLVLResult() isn't buried at 0/10 just because
		// its own method body is tiny.
		base := categoryBaseImpact[cp.Category]
		if dependentCount > base {
			cp.Impact = dependentCount
		} else {
			cp.Impact = base
		}

		if dependentCount > 10 {
			cp.Confidence = minFloat(cp.Confidence+0.05, 1.0)
			cp.Signals = append(cp.Signals,
				fmt.Sprintf("High impact: %d nodes depend on this decision", dependentCount))
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CRACK SUGGESTIONS
// ═══════════════════════════════════════════════════════════════════════════════

// negativeGateMarkers are substrings in a gate/field/callback name that flip
// its polarity: when present, a `true` result means the protection is
// ACTIVE (expired, tampered, ads shown, access denied) rather than granted.
// Categories like "license" and "ads" mix both polarities under one bucket
// (e.g. isLicensed vs isTrialExpired), so the suggested patch must inspect
// the actual name instead of assuming the whole category wants `true`.
var negativeGateMarkers = []string{
	"expired", "trialexpired", "invalid", "isinvalid", "denied", "blocked",
	"restricted", "limited", "islocked", "dontallow", "applicationerror",
	"licensingerror", "showads", "shouldshowads", "adsenabled", "isadmobloaded",
	"istampered", "ishooked", "isfrida", "isxposed", "isinstrumented",
	"isrooted", "isdevicerooted", "isdebuggable", "isdebugging", "isemulator",
	"isvirtualdevice", "notlicensed", "notregistered", "notactivated",
}

// isNegativeGate reports whether a true result from this gate represents a
// triggered/denied state, so the neutralizing patch must force it to FALSE
// instead of the category's default TRUE.
func isNegativeGate(methodOrField string) bool {
	lower := strings.ToLower(methodOrField)
	for _, marker := range negativeGateMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func (f *Finder) generateSuggestions(result *AnalysisResult) {
	for i := range result.CrackPoints {
		cp := &result.CrackPoints[i]
		negative := isNegativeGate(cp.MethodName)

		switch cp.Category {
		case "premium", "license":
			switch {
			case negative:
				cp.SuggestedAction = "Return false (neutralize negative gate: expired/invalid/denied check)"
				cp.SuggestedPatch = "const/4 v0, 0x0\nreturn v0"
				cp.PatchRisk = "medium"
				cp.PatchExplanation = "This gate's name indicates a NEGATIVE check (e.g. isExpired/isTrialExpired/dontAllow) — a true/triggered result means the app is restricted. Forcing false disables the restriction. Do not force true here, that would keep the restriction active."
			case cp.ReturnType == "boolean":
				cp.SuggestedAction = "Return true (force licensed)"
				cp.SuggestedPatch = "const/4 v0, 0x1\nreturn v0"
				cp.PatchRisk = "medium"
				cp.PatchExplanation = "Forces the method to always return true, bypassing the license verification. Other checks that depend on this result will also see 'licensed' status."
			default:
				cp.SuggestedAction = "Investigate return value and conditional branches"
				cp.PatchRisk = "high"
				cp.PatchExplanation = "Non-boolean gate — requires manual analysis of expected return values."
			}

		case "root", "emulator":
			cp.SuggestedAction = "Return false (hide detection)"
			cp.SuggestedPatch = "const/4 v0, 0x0\nreturn v0"
			cp.PatchRisk = "low"
			cp.PatchExplanation = "Hides the root/emulator environment from the application."

		case "debug", "tamper":
			lowerName := strings.ToLower(cp.MethodName)
			switch {
			case strings.Contains(lowerName, "safetynet") || strings.Contains(lowerName, "integrity"):
				cp.SuggestedAction = "Mock successful attestation verdict"
				cp.SuggestedPatch = "const/4 v0, 0x0\nreturn-object v0"
				cp.PatchRisk = "critical"
				cp.PatchExplanation = "Mocks GMS / Play Core Integrity response to indicate a clean, unmodified environment (MEETS_STRONG_INTEGRITY)."
			case strings.Contains(lowerName, "frida") || strings.Contains(lowerName, "xposed") ||
				strings.Contains(lowerName, "hook") || strings.Contains(lowerName, "instrument"):
				cp.SuggestedAction = "Return false (hide instrumentation/hooking framework)"
				cp.SuggestedPatch = "const/4 v0, 0x0\nreturn v0"
				cp.PatchRisk = "medium"
				cp.PatchExplanation = "Anti-hooking probe (Frida/Xposed/Substrate detection) — forcing false hides the injected runtime from the app's self-check. Some apps re-check via multiple independent probes (port scan, thread name, maps scan) that need patching separately."
			default:
				cp.SuggestedAction = "Return false (disable tamper check)"
				cp.SuggestedPatch = "const/4 v0, 0x0\nreturn v0"
				cp.PatchRisk = "medium"
				cp.PatchExplanation = "Disables integrity verification. Note: some apps have multiple tamper checks that cross-verify each other."
			}

		case "security":
			cp.SuggestedAction = "Bypass signature validation/mock signature bytes"
			cp.SuggestedPatch = "const-string v0, \"[MOCKED_SIGNATURE_BASE64]\"\nreturn-object v0"
			cp.PatchRisk = "high"
			cp.PatchExplanation = "Forces the signature verification block to receive a mocked signature matching the original play store build signature."

		case "billing":
			lowerName := strings.ToLower(cp.MethodName)
			switch {
			case strings.Contains(lowerName, "dontallow") || strings.Contains(lowerName, "applicationerror") || strings.Contains(lowerName, "licensingerror"):
				cp.SuggestedAction = "NOP-out this deny callback (or redirect its call site to the allow() callback)"
				cp.PatchRisk = "medium"
				cp.PatchExplanation = "This is the LVL LicenseCheckerCallback denial sink (dontAllow/applicationError). Emptying its body or rerouting the invoke to allow() stops the app from reacting to a negative license verdict."
			case negative:
				cp.SuggestedAction = "Return false (neutralize negative billing check)"
				cp.SuggestedPatch = "const/4 v0, 0x0\nreturn v0"
				cp.PatchRisk = "high"
				cp.PatchExplanation = "Gate name indicates a negative/denial check — force false to disable it rather than forcing a generic true."
			default:
				cp.SuggestedAction = "Analyze billing flow for verification bypass"
				cp.PatchRisk = "critical"
				cp.PatchExplanation = "Billing bypass requires careful analysis of the purchase verification chain. Multiple checks may need to be modified."
			}

		case "ads":
			if negative {
				cp.SuggestedAction = "Return false (hide from ad-serving check, e.g. shouldShowAds/isAdsEnabled)"
				cp.SuggestedPatch = "const/4 v0, 0x0\nreturn v0"
				cp.PatchRisk = "low"
				cp.PatchExplanation = "This gate's name (shouldShowAds/isAdsEnabled/isAdMobLoaded) is true when ads ARE shown — force false to suppress them, not true."
			} else {
				cp.SuggestedAction = "Return true (force ads removed)"
				cp.SuggestedPatch = "const/4 v0, 0x1\nreturn v0"
				cp.PatchRisk = "low"
				cp.PatchExplanation = "Forces the app to believe ads have been removed."
			}

		case "callback":
			lowerName := strings.ToLower(cp.MethodName)
			if lowerName != "" && (strings.Contains(lowerName, "dontallow") || strings.Contains(lowerName, "error")) {
				cp.SuggestedAction = "NOP-out this denial callback body"
				cp.PatchRisk = "medium"
				cp.PatchExplanation = "Denial/error callback sink — emptying its body prevents the app from reacting to a failed verification."
			} else {
				cp.SuggestedAction = "Manual investigation needed"
				cp.PatchRisk = "high"
				cp.PatchExplanation = "Callback methods are event sinks, not gates themselves — trace what field/branch they set and patch that instead of the callback signature."
			}

		default:
			cp.SuggestedAction = "Manual investigation needed"
			cp.PatchRisk = "high"
			cp.PatchExplanation = "Unknown crack point category — requires manual code analysis."
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

func (f *Finder) extractMethodName(raw string) string {
	// invoke-virtual {v0}, Lcom/…;->methodName(…)…
	arrowIdx := strings.Index(raw, "->")
	if arrowIdx < 0 {
		return raw
	}
	rest := raw[arrowIdx+2:]
	parenIdx := strings.Index(rest, "(")
	if parenIdx < 0 {
		return rest
	}
	return rest[:parenIdx]
}

func (f *Finder) extractFieldName(raw string) string {
	arrowIdx := strings.Index(raw, "->")
	if arrowIdx < 0 {
		return raw
	}
	rest := raw[arrowIdx+2:]
	colonIdx := strings.Index(rest, ":")
	if colonIdx < 0 {
		return rest
	}
	return rest[:colonIdx]
}

// maxBooleanCheckLookahead bounds how many instructions after the gate
// invoke we scan for a move-result/if-* pair. Counted by slice position, not
// by the Index field: Dalvik instructions are 1-5 words wide, so Index deltas
// between consecutive instructions vary and can exceed a fixed-offset window,
// causing the very next real instruction to be skipped.
const maxBooleanCheckLookahead = 4

func (f *Finder) isFollowedByBooleanCheck(node *cfg.CFGNode, instrIdx int) bool {
	pos := -1
	for i, instr := range node.Instructions {
		if instr.Index == instrIdx {
			pos = i
			break
		}
	}
	if pos < 0 {
		return false
	}

	end := pos + 1 + maxBooleanCheckLookahead
	if end > len(node.Instructions) {
		end = len(node.Instructions)
	}
	for _, instr := range node.Instructions[pos+1 : end] {
		if strings.HasPrefix(instr.Opcode, "move-result") {
			return true
		}
		if strings.HasPrefix(instr.Opcode, "if-") {
			return true
		}
	}
	return false
}

func (f *Finder) categorizeField(fieldName string) string {
	switch {
	case strings.Contains(fieldName, "premium") || strings.Contains(fieldName, "pro") ||
		strings.Contains(fieldName, "vip") || strings.Contains(fieldName, "paid") ||
		strings.Contains(fieldName, "unlocked"):
		return "premium"
	case strings.Contains(fieldName, "license") || strings.Contains(fieldName, "registered") ||
		strings.Contains(fieldName, "activated"):
		return "license"
	case strings.Contains(fieldName, "ad") || strings.Contains(fieldName, "removeads"):
		return "ads"
	default:
		return "premium"
	}
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// dedupeCrackPoints схлопывает точки, указывающие на одно и то же место
// (category+class+method+node+line). При коллизии остаётся точка с
// максимальной confidence, а сигналы обеих объединяются, чтобы не терять
// контекст обнаружения (напр. «gate pattern» + «Play Integrity check»).
// Порядок оставшихся точек сохраняется (по первому появлению).
func dedupeCrackPoints(points []CrackPoint) []CrackPoint {
	if len(points) < 2 {
		return points
	}

	type slot struct{ idx int }
	index := make(map[string]slot, len(points))
	out := make([]CrackPoint, 0, len(points))

	for _, cp := range points {
		// Type is part of the key: different scan passes intentionally
		// classify the same location differently (e.g. a generic "gate
		// pattern" hit from scanForGateNodes vs a specific "SafetyNet
		// attestation" hit from scanForAdvancedTamperAndIntegrity) — those
		// are complementary signals, not duplicates, so both must survive.
		key := fmt.Sprintf("%s|%s|%s|%d|%d|%d",
			cp.Category, cp.ClassName, strings.ToLower(cp.MethodName), cp.NodeID, cp.Line, cp.Type)

		if s, ok := index[key]; ok {
			existing := &out[s.idx]
			existing.Signals = mergeSignals(existing.Signals, cp.Signals)
			// Higher-confidence detection wins; keep its return-type evidence.
			if cp.Confidence > existing.Confidence {
				existing.Confidence = cp.Confidence
				existing.Type = cp.Type
				if cp.ReturnType != "" {
					existing.ReturnType = cp.ReturnType
				}
			}
			continue
		}

		index[key] = slot{idx: len(out)}
		out = append(out, cp)
	}
	return out
}

// mergeSignals concatenates two signal lists, dropping exact duplicates while
// preserving first-seen order.
func mergeSignals(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, s := range append(append([]string{}, a...), b...) {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
