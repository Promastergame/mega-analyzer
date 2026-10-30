package pipeline

import (
	"strconv"
	"strings"

	"mega-analyzer/pkg/internal/types"
)

// ═══════════════════════════════════════════════════════════════════════════════
// OVERLAY / BANK OVERLAY DETECTOR
//
// Обнаруживает комплекс паттернов банковских троянов:
//   - SYSTEM_ALERT_WINDOW overlay-атаки
//   - MediaProjection захват экрана
//   - Перечисление и спуфинг банковских приложений
//   - Фейковые экраны ввода (login, PIN, OTP)
//
// Ведёт кросс-файловое состояние: если манифест объявляет SYSTEM_ALERT_WINDOW,
// код работы с View в smali получает повышенный приоритет.
// Эмитит Signal'ы для кросс-детекторной корреляции в CorrelationEngine.
// ═══════════════════════════════════════════════════════════════════════════════

type OverlayDetector struct {
	// Накопленные сигналы для корреляции (в рамках одного APK)
	signals []Signal

	// Кросс-файловое состояние (ставится в одном файле, используется в другом)
	hasSystemAlertWindow bool
	hasMediaProjection   bool
	overlayCodeFound     bool
}

func NewOverlayDetector() *OverlayDetector {
	return &OverlayDetector{
		signals: make([]Signal, 0, 32),
	}
}

func (d *OverlayDetector) Name() string { return "overlay_bank_detector" }

func (d *OverlayDetector) Detect(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	switch ctx.FileType {
	case types.FileTypeXML:
		d.detectManifestOverlay(ctx, analysis)
	case types.FileTypeSmali:
		d.detectSmaliOverlay(ctx, analysis)
	}
}

// Reset очищает состояние для нового APK (переиспользует underlying array)
func (d *OverlayDetector) Reset() {
	d.hasSystemAlertWindow = false
	d.hasMediaProjection = false
	d.overlayCodeFound = false
	d.signals = d.signals[:0]
}

// ── Signal emission ────────────────────────────────────────────────────────

// emit сохраняет сигнал для кросс-файловой корреляции
func (d *OverlayDetector) emit(s Signal) {
	d.signals = append(d.signals, s)
}

// Signals возвращает накопленные сигналы для передачи в CorrelationEngine.
// Вызывать ПОСЛЕ обработки всех файлов APK.
func (d *OverlayDetector) Signals() []Signal {
	return d.signals
}

// Finalize выполняет кросс-файловую корреляцию, специфичную для overlay-атак.
// Возвращает дополнительные match'и, невозможные на уровне одного файла.
func (d *OverlayDetector) Finalize() []types.Match {
	return d.correlateSignals()
}

// FeedCorrelationEngine передаёт все накопленные сигналы в CorrelationEngine.
// Удобный метод — вызывать перед ce.AnalyzeCorrelations().
func (d *OverlayDetector) FeedCorrelationEngine(ce *CorrelationEngine) {
	ce.AddSignals(d.signals)
}

// ── XML (Manifest + Layouts) ───────────────────────────────────────────────

func (d *OverlayDetector) detectManifestOverlay(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	// ✅ Fix #1: одна конвертация, дальше strings.Index без []byte аллокаций.
	// strings.Index по строковому литералу не аллоцирует (в отличие от bytes.Contains + []byte("...")).
	content := string(ctx.ContentLower)

	// 1️⃣ SYSTEM_ALERT_WINDOW permission
	if idx := strings.Index(content, "system_alert_window"); idx >= 0 {
		d.hasSystemAlertWindow = true
		line := lineAt(ctx.LineOffsets, idx)

		d.emit(Signal{
			ID: "overlay_perm_saw", Type: "permission",
			Value: "SYSTEM_ALERT_WINDOW", Detector: d.Name(),
			Score: 80, Critical: true,
		})
		analysis.Matches = append(analysis.Matches, newMatch(
			types.CategorySecurity, analysis.Path, line,
			"SYSTEM_ALERT_WINDOW permission - can draw over apps",
			"android.permission.SYSTEM_ALERT_WINDOW", true,
		))
	}

	// 2️⃣ CAPTURE_AUDIO_OUTPUT (MediaProjection)
	if idx := strings.Index(content, "capture_audio_output"); idx >= 0 {
		d.hasMediaProjection = true
		line := lineAt(ctx.LineOffsets, idx)

		d.emit(Signal{
			ID: "overlay_perm_capture", Type: "permission",
			Value: "CAPTURE_AUDIO_OUTPUT", Detector: d.Name(),
			Score: 70, Critical: true,
		})
		analysis.Matches = append(analysis.Matches, newMatch(
			types.CategorySecurity, analysis.Path, line,
			"MediaProjection API - can capture screen and audio",
			"android.permission.CAPTURE_AUDIO_OUTPUT", true,
		))
	}

	// 3️⃣ Подозрительные имена layout-файлов (по PATH, не по содержимому)
	if strings.Contains(ctx.Path, "layout") {
		d.detectSuspiciousLayoutName(ctx, analysis)
	}
}

// detectSuspiciousLayoutName проверяет PATH файла на подозрительные имена.
// Оригинал проверял СОДЕРЖИМОЕ — ловил "login" в любом тексте XML (false positive).
func (d *OverlayDetector) detectSuspiciousLayoutName(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	pathLower := strings.ToLower(ctx.Path)

	suspiciousNames := [...]string{
		"login", "bank", "payment", "password", "auth", "verify",
	}
	for _, name := range suspiciousNames {
		if strings.Contains(pathLower, name) {
			d.emit(Signal{
				ID: "overlay_suspicious_layout", Type: "pattern",
				Value: "SUSPICIOUS_LAYOUT:" + name, Detector: d.Name(),
				Score: 20,
			})
			analysis.Matches = append(analysis.Matches, newMatch(
				types.CategorySecurity, analysis.Path, 0,
				"Suspicious layout name: "+name,
				"Found: "+name+" in "+ctx.Path, false,
			))
			return // одного совпадения на файл достаточно
		}
	}
}

// ── Smali ──────────────────────────────────────────────────────────────────

func (d *OverlayDetector) detectSmaliOverlay(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	// ✅ Fix #1: одна конвертация для всего файла
	content := string(ctx.ContentLower)

	// ✅ Fix #2: pre-compute context flags ДО циклов.
	// Вместо повторных full-scan внутри каждой итерации banking-пакетов.
	hasOverlayType := strings.Contains(content, "type_system_overlay") ||
		strings.Contains(content, "type_system_alert") ||
		strings.Contains(content, "type_application_overlay")

	hasWindowManager := strings.Contains(content, "windowmanager")

	hasPkgEnumeration := strings.Contains(content, "getpackagename") ||
		strings.Contains(content, "getinstalledpackages") ||
		strings.Contains(content, "resolveactivity")

	// 1️⃣ Overlay window types
	if hasOverlayType {
		d.detectOverlayTypes(content, ctx, analysis)
	}

	// 2️⃣ MediaProjection API
	d.detectMediaProjection(content, ctx, analysis)

	// 3️⃣ LayoutParams — ✅ Fix #3: ТОЛЬКО при WindowManager + overlay type.
	// Без этого контекста layoutparams = легитимный UI-код (99% приложений).
	if hasWindowManager && hasOverlayType {
		d.detectLayoutParams(content, ctx, analysis)
	}

	// 4️⃣ Banking package spoofing — с pre-computed hasPkgEnumeration
	d.detectBankingSpoofing(content, ctx, analysis, hasPkgEnumeration)

	// 5️⃣ View manipulation — ✅ Fix #4: ТОЛЬКО при overlay-контексте.
	// hasSystemAlertWindow может быть set из другого файла (кросс-файловый state).
	if hasOverlayType || d.hasSystemAlertWindow {
		d.detectViewManipulation(content, ctx, analysis)
	}
}

// detectOverlayTypes ищет TYPE_SYSTEM_OVERLAY / TYPE_SYSTEM_ALERT / TYPE_APPLICATION_OVERLAY
func (d *OverlayDetector) detectOverlayTypes(
	content string, ctx *FileDetectContext, analysis *types.FileAnalysis,
) {
	type pat struct {
		text string
		desc string
	}
	patterns := [...]pat{
		{"type_system_overlay", "TYPE_SYSTEM_OVERLAY — classic overlay attack"},
		{"type_system_alert", "TYPE_SYSTEM_ALERT — overlay alert window"},
		{"type_application_overlay", "TYPE_APPLICATION_OVERLAY (API 26+)"},
	}

	for _, p := range patterns {
		// ✅ Fix #1: один strings.Index вместо Contains + Index (два прохода)
		if idx := strings.Index(content, p.text); idx >= 0 {
			d.overlayCodeFound = true
			line := lineAt(ctx.LineOffsets, idx)

			d.emit(Signal{
				ID: "overlay_window_type", Type: "api_call",
				Value: "OVERLAY_TYPE_FOUND", Detector: d.Name(),
				Score: 85, Critical: true,
			})
			analysis.Matches = append(analysis.Matches, newMatch(
				types.CategorySecurity, analysis.Path, line,
				"WindowManager overlay configuration found: "+p.desc,
				p.text, true,
			))
		}
	}
}

// detectMediaProjection ищет использование MediaProjection API в smali
func (d *OverlayDetector) detectMediaProjection(
	content string, ctx *FileDetectContext, analysis *types.FileAnalysis,
) {
	if idx := strings.Index(content, "mediaprojection"); idx >= 0 {
		d.hasMediaProjection = true
		line := lineAt(ctx.LineOffsets, idx)

		d.emit(Signal{
			ID: "overlay_media_projection", Type: "api_call",
			Value: "MEDIA_PROJECTION", Detector: d.Name(),
			Score: 75, Critical: true,
		})
		analysis.Matches = append(analysis.Matches, newMatch(
			types.CategorySecurity, analysis.Path, line,
			"MediaProjection API usage - screen/audio capture",
			"MediaProjection", true,
		))
	}
}

// detectLayoutParams репортит LayoutParams ТОЛЬКО при WindowManager + overlay type.
// ✅ Fix #3: без контекста это легитимный UI-код.
func (d *OverlayDetector) detectLayoutParams(
	content string, ctx *FileDetectContext, analysis *types.FileAnalysis,
) {
	if idx := strings.Index(content, "layoutparams"); idx >= 0 {
		line := lineAt(ctx.LineOffsets, idx)

		d.emit(Signal{
			ID: "overlay_layout_params", Type: "pattern",
			Value: "OVERLAY_LAYOUT_PARAMS", Detector: d.Name(),
			Score: 60,
		})
		analysis.Matches = append(analysis.Matches, newMatch(
			types.CategorySecurity, analysis.Path, line,
			"WindowManager LayoutParams with overlay type — overlay attack setup",
			"LayoutParams + WindowManager + overlay type", true,
		))
	}
}

// detectBankingSpoofing ищет банковские пакеты при наличии package enumeration.
// ✅ Fix #2: hasPkgEnumeration уже pre-computed — не сканируем повторно в каждой итерации.
func (d *OverlayDetector) detectBankingSpoofing(
	content string, ctx *FileDetectContext, analysis *types.FileAnalysis,
	hasPkgEnumeration bool,
) {
	// Без контекста перечисления пакетов — не репортим, слишком много false positive
	if !hasPkgEnumeration {
		return
	}

	type bankPat struct {
		pkg  string
		name string
	}
	bankingPatterns := [...]bankPat{
		{"com/android/vending", "Google Play"},
		{"com/google/android/gms", "Google Services"},
		{"com/paypal", "PayPal"},
		{"com/spotify", "Spotify"},
		{"com/whatsapp", "WhatsApp"},
		{"com/facebook", "Facebook"},
		{"com/instagram", "Instagram"},
		{"com/sberbank", "Sberbank"},
		{"com/alfabank", "Alfa-Bank"},
		{"com/tinkoff", "Tinkoff"},
	}

	matched := 0
	for _, bp := range bankingPatterns {
		// ✅ Fix #1: один strings.Index вместо Contains + Index
		idx := strings.Index(content, bp.pkg)
		if idx < 0 {
			continue
		}
		matched++
		line := lineAt(ctx.LineOffsets, idx)

		d.emit(Signal{
			ID: "overlay_banking_ref", Type: "pattern",
			Value: "BANKING_PKG_REF", Detector: d.Name(),
			Score: 50,
		})
		analysis.Matches = append(analysis.Matches, newMatch(
			types.CategorySecurity, analysis.Path, line,
			"Potential banking app spoofing/overlay: "+bp.name,
			bp.pkg, false,
		))
	}

	// ≥3 банковских пакетов в одном файле — сильный индикатор target list
	if matched >= 3 {
		d.emit(Signal{
			ID: "overlay_banking_target_list", Type: "behavior",
			Value: "BANKING_TARGET_LIST", Detector: d.Name(),
			Score: 90, Critical: true,
		})
		analysis.Matches = append(analysis.Matches, newMatch(
			types.CategorySecurity, analysis.Path, 0,
			"Multiple banking targets ("+strconv.Itoa(matched)+") — banking trojan target list",
			"banking_target_list", true,
		))
	}
}

// detectViewManipulation — View ops ТОЛЬКО при overlay-контексте.
// ✅ Fix #3: убран "margin" (слишком generic, 99% легитимного кода).
// ✅ Fix #4: гейтится hasOverlayType || d.hasSystemAlertWindow (кросс-файловый state).
func (d *OverlayDetector) detectViewManipulation(
	content string, ctx *FileDetectContext, analysis *types.FileAnalysis,
) {
	type viewPat struct {
		text string
		desc string
	}
	viewPatterns := [...]viewPat{
		{"setvisibility", "setVisibility"},
		{"bringtofront", "bringToFront"},
		{"setbackground", "setBackground"},
		// "margin" убран — слишком generic, даёт false positive
	}

	for _, vp := range viewPatterns {
		if idx := strings.Index(content, vp.text); idx >= 0 {
			line := lineAt(ctx.LineOffsets, idx)

			d.emit(Signal{
				ID: "overlay_view_manipulation", Type: "api_call",
				Value: "OVERLAY_VIEW_MANIPULATION", Detector: d.Name(),
				Score: 40,
			})
			analysis.Matches = append(analysis.Matches, newMatch(
				types.CategorySecurity, analysis.Path, line,
				"View manipulation in overlay context: "+vp.desc,
				vp.text, false,
			))
		}
	}
}

// ── Cross-file correlation ─────────────────────────────────────────────────

// correlateSignals анализирует ВСЕ сигналы со всех файлов APK.
// Генерирует match'и, невозможные на уровне одного файла.
func (d *OverlayDetector) correlateSignals() []types.Match {
	if len(d.signals) == 0 {
		return nil
	}

	// Подсчёт сигналов по Value (O(n) вместо повторных проходов)
	counts := make(map[string]int, 8)
	for i := range d.signals {
		counts[d.signals[i].Value]++
	}

	var result []types.Match

	// Rule 1: overlay window type + banking references → banking trojan
	if counts["OVERLAY_TYPE_FOUND"] > 0 && counts["BANKING_PKG_REF"] > 0 {
		result = append(result, newMatch(
			types.CategorySecurity, "cross-file-correlation", 0,
			"CRITICAL: Overlay types + banking app references — banking trojan pattern",
			"overlay_type + banking_ref signals", true,
		))
	}

	// Rule 2: full overlay attack chain
	if counts["SYSTEM_ALERT_WINDOW"] > 0 &&
		counts["OVERLAY_TYPE_FOUND"] > 0 &&
		counts["OVERLAY_VIEW_MANIPULATION"] > 0 {
		result = append(result, newMatch(
			types.CategorySecurity, "cross-file-correlation", 0,
			"Confirmed overlay attack: permission + overlay type + view manipulation",
			"full overlay attack chain", true,
		))
	}

	// Rule 3: media projection + banking → screen recording trojan
	if counts["MEDIA_PROJECTION"] > 0 && counts["BANKING_PKG_REF"] > 0 {
		result = append(result, newMatch(
			types.CategorySecurity, "cross-file-correlation", 0,
			"Screen capture + banking app targeting — potential recording trojan",
			"media_projection + banking_ref signals", true,
		))
	}

	// Rule 4: target list detected (≥3 banking refs через несколько файлов)
	if n := counts["BANKING_PKG_REF"]; n >= 5 {
		result = append(result, newMatch(
			types.CategorySecurity, "cross-file-correlation", 0,
			"Extensive banking target list ("+strconv.Itoa(n)+" refs) — banking trojan",
			"extensive banking target list", true,
		))
	}

	return result
}
