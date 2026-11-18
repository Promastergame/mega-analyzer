package main

import (
	"fmt"
	"io"
	"mega-analyzer/pkg/internal/report"
	"mega-analyzer/pkg/internal/types"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// OUTPUT — форматированный вывод результатов анализа
// ═══════════════════════════════════════════════════════════════════════════════

// Output управляет форматированным выводом в консоль.
// Поддерживает тихий режим (quiet), темизацию, перенаправление вывода
// и счётчики ошибок/предупреждений для финальной сводки.
type Output struct {
	theme     Theme
	quiet     bool
	tui       bool
	writer    io.Writer
	errWriter io.Writer

	// progressWriter, when non-nil, receives the live progress bar instead of
	// writer. --save_log routes writer to a stdout+file tee but keeps
	// progressWriter on the real stdout TTY, so the animated progress bar stays
	// on screen and never floods the plain-text log file.
	progressWriter io.Writer

	// Счётчики событий — атомарные, можно читать из любой горутины.
	errorCount    atomic.Int64
	warningCount  atomic.Int64
	criticalCount atomic.Int64

	lastStage   string
	lastCurrent int
	lastTotal   int
	lastStatus  string

	// Progress repaint throttle state. TTY repaints are cheap but pointless
	// faster than the eye; redirected output must be throttled hard, see
	// printPlainProgress.
	lastProgressAt   time.Time
	lastPlainPercent int
}

// NewOutput создаёт новый Output с заданной темой и режимом.
func NewOutput(theme Theme, quiet bool) *Output {
	return &Output{
		theme:     theme,
		quiet:     quiet,
		tui:       true,
		writer:    os.Stdout,
		errWriter: os.Stderr,
	}
}

// NewOutputWithWriter создаёт Output с произвольным writer (удобно для тестов).
func NewOutputWithWriter(theme Theme, quiet bool, w io.Writer) *Output {
	return &Output{
		theme:     theme,
		quiet:     quiet,
		tui:       true,
		writer:    w,
		errWriter: w,
	}
}

func (o *Output) SetTUI(enabled bool) {
	o.tui = enabled
}

// SetProgressWriter redirects the live progress bar to w (typically the real
// os.Stdout) while regular output keeps flowing to writer. Pass nil to fall
// back to writer. --save_log uses this so the animated bar stays on the
// terminal and never floods the log file.
func (o *Output) SetProgressWriter(w io.Writer) {
	o.progressWriter = w
}

// progressOut returns the writer that should receive progress repaints.
// It falls back to writer when no dedicated progress sink was set.
func (o *Output) progressOut() io.Writer {
	if o.progressWriter != nil {
		return o.progressWriter
	}
	return o.writer
}

// progressPrintf writes a progress frame to progressOut (never the log tee).
func (o *Output) progressPrintf(format string, args ...interface{}) {
	fmt.Fprintf(o.progressOut(), format, args...)
}

// GeneratedFile описывает сгенерированный отчёт или артефакт.
type GeneratedFile struct {
	Name string
	Desc string
}

// ═══════════════════════════════════════════════════════════════════════════════
// MODE-SPECIFIC TERMINOLOGY (Task 7.8)
// ═══════════════════════════════════════════════════════════════════════════════

// GetPatchLabel returns mode-specific label for patches
func GetPatchLabel(mode string, isHighRisk bool) string {
	if mode == "defensive" {
		if isHighRisk {
			return "Impact"
		}
		return "Weakness"
	}
	if isHighRisk {
		return "Bypass"
	}
	return "Exploit suggestion"
}

// PrintTerminologyLegend displays mode-specific terminology explanation
func (o *Output) PrintTerminologyLegend(mode string) {
	if o.quiet {
		return
	}

	t := o.theme

	o.fprintln()
	o.printLine()
	o.fprintf("%s TERMINOLOGY %s\n", t.Bold, t.Reset)
	o.printLine()

	if mode == "defensive" {
		o.fprintf("  %s🛡️  Defensive Mode%s - Strengthening security\n", t.Green, t.Reset)
		o.fprintf("  • %sWeakness%s  - Where check can be bypassed\n", t.Bold, t.Reset)
		o.fprintf("  • %sImpact%s    - What an attacker could achieve\n", t.Bold, t.Reset)
	} else {
		o.fprintf("  %s⚔️  Research Mode%s - Security analysis and testing\n", t.Yellow, t.Reset)
		o.fprintf("  • %sBypass%s             - Circumvent high-risk security checks\n", t.Bold, t.Reset)
		o.fprintf("  • %sExploit suggestion%s - Circumvent medium/low-risk checks\n", t.Bold, t.Reset)
	}

	o.printLine()
	o.fprintln()
}

// ═══════════════════════════════════════════════════════════════════════════════
// ВНУТРЕННИЕ ХЕЛПЕРЫ ВЫВОДА
// ═══════════════════════════════════════════════════════════════════════════════

func (o *Output) fprintf(format string, args ...interface{}) {
	fmt.Fprintf(o.writer, format, args...)
}

func (o *Output) fprintln(args ...interface{}) {
	fmt.Fprintln(o.writer, args...)
}

func (o *Output) eprintf(format string, args ...interface{}) {
	fmt.Fprintf(o.errWriter, format, args...)
}

func (o *Output) printLine() {
	o.fprintf("%s%s%s\n", o.theme.Edge, strings.Repeat("─", o.uiWidth()), o.theme.Reset)
}

func (o *Output) printDoubleLine() {
	o.fprintf("%s%s%s\n", o.theme.Primary, strings.Repeat("═", o.uiWidth()), o.theme.Reset)
}

// termCols returns terminal width in characters from real syscall first,
// falling back to env COLUMNS, then to 0 (unknown).
func termCols() int {
	if c, _ := terminalSize(); c > 0 {
		return c
	}
	if v, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && v > 0 {
		return v
	}
	return 0
}

// termRows returns terminal height in characters.
func termRows() int {
	if _, r := terminalSize(); r > 0 {
		return r
	}
	if v, err := strconv.Atoi(os.Getenv("LINES")); err == nil && v > 0 {
		return v
	}
	return 0
}

// uiWidth returns panel width adapted to the terminal.
// It reserves a small margin on each side and clamps to a sane band so
// content does not stretch absurdly on ultra-wide terminals.
func (o *Output) uiWidth() int {
	cols := termCols()
	if cols <= 0 {
		cols = 100
	}
	margin := 4
	switch {
	case cols < 64:
		margin = 0
	case cols < 110:
		margin = 2
	}
	width := cols - margin
	if width < 40 {
		width = 40
	}
	if width > 176 {
		width = 176
	}
	if width%2 != 0 {
		width--
	}
	return width
}

// uiEdge returns left-side padding that centers a panel of uiWidth() inside
// the actual terminal.
func (o *Output) uiEdge() int {
	cols := termCols()
	w := o.uiWidth()
	if cols <= w {
		return 0
	}
	return (cols - w) / 2
}

// uiWide reports whether the terminal is wide enough for side-by-side panels.
func (o *Output) uiWide() bool {
	return termCols() >= 130
}

// uiCompact reports whether the terminal is too short to render full panels.
func (o *Output) uiCompact() bool {
	rows := termRows()
	return rows > 0 && rows < 36
}

func centerText(s string, width int) string {
	pad := width - visibleLen(s)
	if pad <= 0 {
		return s
	}
	left := pad / 2
	return strings.Repeat(" ", left) + s + strings.Repeat(" ", pad-left)
}

// centerTextNoRightPad центрирует текст, но не добавляет пробелы справа,
// что предотвращает ненужный перенос строк в узких терминалах.
func centerTextNoRightPad(s string, width int) string {
	pad := width - visibleLen(s)
	if pad <= 0 {
		return s
	}
	left := pad / 2
	return strings.Repeat(" ", left) + s
}

// visibleLen возвращает видимую ширину строки в колонках терминала,
// игнорируя ANSI escape-последовательности и учитывая wide-символы (2 колонки).
func visibleLen(s string) int {
	// Fast path for ASCII strings without escape sequences
	hasSpecial := false
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b >= 0x80 || b == 0x1b {
			hasSpecial = true
			break
		}
	}
	if !hasSpecial {
		return len(s)
	}

	count := 0
	inEscape := false
	prevNarrowSymbol := false
	for _, r := range s {
		if inEscape {
			if r == 'm' {
				inEscape = false
			}
			continue
		}
		if r == 0x1b {
			inEscape = true
			continue
		}
		if r >= 0xfe00 && r <= 0xfe0f {
			// Variation selectors occupy no column of their own, but U+FE0F
			// requests emoji presentation, which turns a 1-column text glyph
			// (⚠, ⚙, ⚔) into a 2-column emoji one.
			if r == 0xfe0f && prevNarrowSymbol {
				count++
				prevNarrowSymbol = false
			}
			continue
		}
		if isWideRune(r) {
			count += 2
			prevNarrowSymbol = false
		} else {
			count++
			prevNarrowSymbol = vs16WidensRune(r)
		}
	}
	return count
}

// isWideRune возвращает true, если символ занимает 2 колонки в терминале.
// Это простая и легковесная замена golang.org/x/text/width.
func isWideRune(r rune) bool {
	if r >= 0xfe00 && r <= 0xfe0f {
		return false
	}
	if (r >= 0x231a && r <= 0x231b) || (r >= 0x23f0 && r <= 0x23f3) {
		return true
	}
	if r >= 0x2600 && r <= 0x27bf {
		return wideSymbolRune(r)
	}
	// Fullwidth, CJK, Emoji and other wide characters
	if r >= 0x1100 &&
		(r <= 0x115F || r == 0x2329 || r == 0x232A ||
			(r >= 0x2E80 && r <= 0xA4CF && r != 0x303F) ||
			(r >= 0xAC00 && r <= 0xD7A3) ||
			(r >= 0xF900 && r <= 0xFAFF) ||
			(r >= 0xFE10 && r <= 0xFE19) ||
			(r >= 0xFE30 && r <= 0xFE6F) ||
			(r >= 0xFF00 && r <= 0xFF60) ||
			(r >= 0xFFE0 && r <= 0xFFE6) ||
			(r >= 0x1F000 && r <= 0x1FAFF) || // Emojis
			(r >= 0x20000 && r <= 0x2FFFD) ||
			(r >= 0x30000 && r <= 0x3FFFD)) {
		return true
	}
	return false
}

// wideSymbolRune решает ширину внутри Miscellaneous Symbols и Dingbats
// (U+2600–U+27BF). Блок смешанный: часть символов имеет East Asian Width = W и
// занимает 2 колонки (✅, ⚡), остальные — Ambiguous/Neutral и рисуются в одну
// (✓, ✗, ❯, ⚠, ⚙). Раньше весь диапазон считался широким, из-за чего рамки с
// ❯ и ✓/✗ съезжали на колонку.
func wideSymbolRune(r rune) bool {
	switch {
	case r >= 0x2614 && r <= 0x2615, // ☔ ☕
		r >= 0x2648 && r <= 0x2653, // зодиак
		r == 0x267f,                // ♿
		r == 0x2693,                // ⚓
		r == 0x26a1,                // ⚡
		r >= 0x26aa && r <= 0x26ab, // ⚪ ⚫
		r >= 0x26bd && r <= 0x26be, // ⚽ ⚾
		r >= 0x26c4 && r <= 0x26c5, // ⛄ ⛅
		r == 0x26ce,                // ⛎
		r == 0x26d4,                // ⛔
		r == 0x26ea,                // ⛪
		r >= 0x26f2 && r <= 0x26f3, // ⛲ ⛳
		r == 0x26f5,                // ⛵
		r == 0x26fa,                // ⛺
		r == 0x26fd,                // ⛽
		r == 0x2705,                // ✅
		r >= 0x270a && r <= 0x270b, // ✊ ✋
		r == 0x2728,                // ✨
		r == 0x274c,                // ❌
		r == 0x274e,                // ❎
		r >= 0x2753 && r <= 0x2755, // ❓ ❔ ❕
		r == 0x2757,                // ❗
		r >= 0x2795 && r <= 0x2797, // ➕ ➖ ➗
		r == 0x27b0,                // ➰
		r == 0x27bf:                // ➿
		return true
	}
	return false
}

// vs16WidensRune возвращает true, если символ рисуется в одну колонку как текст,
// но следующий за ним U+FE0F переключает его в двухколоночную emoji-форму.
// Буквы и цифры так себя не ведут — только символьные блоки.
func vs16WidensRune(r rune) bool {
	switch {
	case r == 0x00a9 || r == 0x00ae || r == 0x2122: // © ® ™
		return true
	case r >= 0x2000 && r <= 0x2bff: // стрелки, геометрия, символы, dingbats
		return true
	case r == 0x3030 || r == 0x303d || r == 0x3297 || r == 0x3299:
		return true
	}
	return false
}

// padRight дополняет строку пробелами справа до нужной видимой длины.
func padRight(s string, width int) string {
	pad := width - visibleLen(s)
	if pad <= 0 {
		return s
	}
	return s + strings.Repeat(" ", pad)
}

// wrapText разбивает строку на части не длиннее width.
func wrapText(s string, width int) []string {
	if width <= 0 || visibleLen(s) <= width {
		return []string{s}
	}

	var result []string
	words := strings.Fields(s)
	if len(words) == 0 {
		return []string{s}
	}

	current := ""
	for _, w := range words {
		if current == "" {
			current = w
			continue
		}
		if visibleLen(current)+1+visibleLen(w) > width {
			result = append(result, current)
			current = w
		} else {
			current += " " + w
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

// ═══════════════════════════════════════════════════════════════════════════════
// УНИВЕРСАЛЬНАЯ РАМКА (BOX RENDERER)
// ═══════════════════════════════════════════════════════════════════════════════

// boxStyle описывает стиль рамки.
type boxStyle struct {
	topLeft, topRight, botLeft, botRight string
	horizontal, vertical                 string
	color                                string
	titleColor                           string
	icon                                 string
}

// renderBoxLines собирает строки рамки без записи в writer.
// Удобно для центрирования или составной верстки.
func (o *Output) renderBoxLines(style boxStyle, title string, lines []string, width int) []string {
	t := o.theme
	inner := width - 2 // место под содержимое
	out := make([]string, 0, len(lines)+4)

	// Верхняя граница с заголовком
	titleStr := ""
	if title != "" {
		titleStr = fmt.Sprintf(" %s%s %s%s ",
			style.titleColor, style.icon, title, t.Reset)
	}

	titleVis := visibleLen(titleStr)
	leftPad := 2
	rightPad := inner - titleVis - leftPad
	if rightPad < 0 {
		rightPad = 0
	}

	out = append(out, fmt.Sprintf("%s%s%s%s%s%s%s%s",
		style.color, style.topLeft,
		strings.Repeat(style.horizontal, leftPad),
		t.Reset, titleStr, style.color,
		strings.Repeat(style.horizontal, rightPad),
		style.topRight+t.Reset,
	))

	emptyCell := strings.Repeat(" ", inner)
	if t.Panel != "" {
		emptyCell = t.Panel + emptyCell + t.Reset
	}
	emptyRow := fmt.Sprintf("%s%s%s%s%s%s",
		style.color, style.vertical, t.Reset,
		emptyCell,
		style.color, style.vertical+t.Reset,
	)
	out = append(out, emptyRow)

	for _, raw := range lines {
		for _, line := range wrapText(raw, inner-4) {
			padded := padRight("  "+line+"  ", inner)
			if t.Panel != "" {
				padded = t.Panel + padded + t.Reset
			}
			out = append(out, fmt.Sprintf("%s%s%s%s%s%s",
				style.color, style.vertical, t.Reset,
				padded,
				style.color, style.vertical+t.Reset,
			))
		}
	}

	out = append(out, emptyRow)
	out = append(out, fmt.Sprintf("%s%s%s%s%s",
		style.color, style.botLeft,
		strings.Repeat(style.horizontal, inner),
		style.botRight, t.Reset,
	))
	return out
}

// drawBox рисует красивую рамку с заголовком и многострочным содержимым.
// width — общая видимая ширина рамки (включая границы).
func (o *Output) drawBox(w io.Writer, style boxStyle, title string, lines []string, width int) {
	for _, ln := range o.renderBoxLines(style, title, lines, width) {
		fmt.Fprintln(w, ln)
	}
}

// drawBoxAt рисует рамку с левым отступом edge, чтобы центрировать её в терминале.
func (o *Output) drawBoxAt(w io.Writer, style boxStyle, title string, lines []string, width, edge int) {
	pad := ""
	if edge > 0 {
		pad = strings.Repeat(" ", edge)
	}
	for _, ln := range o.renderBoxLines(style, title, lines, width) {
		fmt.Fprintln(w, pad+ln)
	}
}

// writeIndented печатает строку с левым отступом edge.
func (o *Output) writeIndented(w io.Writer, edge int, line string) {
	if edge > 0 {
		fmt.Fprint(w, strings.Repeat(" ", edge))
	}
	fmt.Fprintln(w, line)
}

// ═══════════════════════════════════════════════════════════════════════════════
// BANNER
// ═══════════════════════════════════════════════════════════════════════════════

func (o *Output) PrintBanner() {
	if o.quiet {
		return
	}

	t := o.theme
	width := o.uiWidth()
	edge := o.uiEdge()
	pad := ""
	if edge > 0 {
		pad = strings.Repeat(" ", edge)
	}

	logo := []string{
		"█▀▄▀█ █▀▀ █▀▀  ▄▀█   ▄▀█ █▄░█ ▄▀█ █░░ █▄█ ▀█ █▀▀ █▀█",
		"█░▀░█ ██▄ █▄█  █▀█   █▀█ █░▀█ █▀█ █▄▄ ░█░ █▄ ██▄ █▀▄",
	}

	o.fprintln()
	o.fprintf("%s%s%s%s\n", pad, t.Edge, strings.Repeat("─", width), t.Reset)

	o.fprintln(pad + centerTextNoRightPad(fmt.Sprintf("%s%s%s", t.Primary, logo[0], t.Reset), width))
	o.fprintln(pad + centerTextNoRightPad(fmt.Sprintf("%s%s%s", t.Primary+t.Bold, logo[1], t.Reset), width))
	o.fprintln()

	o.fprintln(pad + centerTextNoRightPad(fmt.Sprintf("%sLicense Protection Analyzer v%s%s", t.Warning, Version, t.Reset), width))
	o.fprintln(pad + centerTextNoRightPad(fmt.Sprintf("%sdark cli shell // apk dex native // deobfuscation core%s", t.Muted, t.Reset), width))
	o.fprintln()

	features1 := fmt.Sprintf("%s›%s Pattern Detection      %s›%s Call Graph Analysis      %s›%s Smart Correlation",
		t.Success, t.Reset, t.Secondary, t.Reset, t.Accent, t.Reset)
	features2 := fmt.Sprintf("%s›%s Rust Deobfuscator      %s›%s Detailed Reports         %s›%s ML Patch Signals",
		t.Primary, t.Reset, t.Info, t.Reset, t.Warning, t.Reset)

	o.fprintln(pad + centerTextNoRightPad(features1, width))
	o.fprintln(pad + centerTextNoRightPad(features2, width))
	o.fprintln()

	left := fmt.Sprintf("%s›%s %sMEGA ANALYZER  //  OMNISEC%s", t.Primary, t.Reset, t.Muted, t.Reset)
	right := fmt.Sprintf("%sv%s%s", t.Accent+t.Bold, Version, t.Reset)
	gap := width - visibleLen(left) - visibleLen(right) - 2
	if gap < 1 {
		gap = 1
	}

	o.fprintf("%s %s%s%s \n", pad, left, strings.Repeat(" ", gap), right)
	o.fprintf("%s%s%s%s\n", pad, t.Edge, strings.Repeat("─", width), t.Reset)
	o.fprintln()
}

func (o *Output) printLegacyBanner() {
	t := o.theme
	o.fprintln()
	o.printDoubleLine()
	o.fprintf("%s%s %s v%s%s\n", t.Bold, t.Primary, AppName, Version, t.Reset)
	o.fprintf("%sLicense Protection Analyzer%s\n", t.Muted, t.Reset)
	o.printDoubleLine()
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIG DISPLAY
// ═══════════════════════════════════════════════════════════════════════════════

func (o *Output) PrintConfig(opts *CLIOptions, target string) {
	if o.quiet {
		return
	}
	if !o.tui {
		o.printLegacyConfig(opts, target)
		return
	}

	t := o.theme
	width := o.uiWidth()
	depth := 1
	switch opts.Profile {
	case ProfileBalanced:
		depth = 2
	case ProfileDeep:
		depth = 3
	case ProfileParanoid:
		depth = 4
	}
	featureStatus := func(enabled bool) string {
		if enabled {
			return t.Success + "ACTIVE" + t.Reset
		}
		return t.Muted + "standby" + t.Reset
	}

	lines := []string{
		fmt.Sprintf("%sCONFIGURATION%s  launch matrix loaded", t.Bold+t.Primary, t.Reset),
		"",
		fmt.Sprintf("🎯 %-13s %s%s%s", "Target", t.Warning, target, t.Reset),
		fmt.Sprintf("📁 %-13s %s", "Output", opts.Output),
		fmt.Sprintf("📋 %-13s %s%s%s  %s", "Profile", t.Secondary, opts.Profile, t.Reset, opts.Profile.Description()),
		fmt.Sprintf("👷 %-13s %d parallel workers", "Workers", opts.Workers),
		fmt.Sprintf("🧭 %-13s %s %s%d/4%s", "Depth", t.ProgressBar(depth, 4, 18), t.Muted, depth, t.Reset),
		"",
		fmt.Sprintf("⚙️  %-13s Call Graph %s   Correlations %s   Deep Scan %s",
			"Modules",
			featureStatus(opts.EnableCallGraph),
			featureStatus(opts.EnableCorrelations),
			featureStatus(opts.EnableDeepScan)),
	}

	if opts.MaxFiles > 0 {
		lines = append(lines, fmt.Sprintf("📦 %-13s %d", "Max files", opts.MaxFiles))
	}
	if opts.Timeout > 0 {
		lines = append(lines, fmt.Sprintf("⏳ %-13s %ds", "Timeout", opts.Timeout))
	}
	style := boxStyle{
		topLeft: "╭", topRight: "╮", botLeft: "╰", botRight: "╯",
		horizontal: "─", vertical: "│",
		color:      t.Edge,
		titleColor: t.Bold + t.Secondary,
		icon:       "◈",
	}

	o.fprintln()
	o.drawBox(o.writer, style, "CONFIGURATION", lines, width)
	o.fprintln()
}

func (o *Output) printLegacyConfig(opts *CLIOptions, target string) {
	t := o.theme
	o.fprintln()
	o.printLine()
	o.fprintf("%s CONFIGURATION %s\n", t.Bold, t.Reset)
	o.printLine()
	o.fprintf("  🎯 %s%-14s%s %s%s%s\n", t.Bold, "Target:", t.Reset, t.Yellow, target, t.Reset)
	o.fprintf("  📁 %s%-14s%s %s\n", t.Bold, "Output:", t.Reset, opts.Output)
	o.fprintf("  📋 %s%-14s%s %s%s%s (%s)\n", t.Bold, "Profile:", t.Reset, t.Cyan, opts.Profile, t.Reset, opts.Profile.Description())
	o.fprintf("  👷 %s%-14s%s %d\n", t.Bold, "Workers:", t.Reset, opts.Workers)
	if opts.MaxFiles > 0 {
		o.fprintf("  📦 %s%-14s%s %d\n", t.Bold, "Max files:", t.Reset, opts.MaxFiles)
	}
	var active []string
	if opts.EnableCallGraph {
		active = append(active, t.Green+"Call Graph"+t.Reset)
	}
	if opts.EnableCorrelations {
		active = append(active, t.Green+"Correlations"+t.Reset)
	}
	if opts.EnableDeepScan {
		active = append(active, t.Green+"Deep Scan"+t.Reset)
	}
	if len(active) > 0 {
		o.fprintf("  ⚙ %s%-14s%s %s\n", t.Bold, "Features:", t.Reset, strings.Join(active, ", "))
	}
	o.printLine()
	o.fprintln()
}

// ═══════════════════════════════════════════════════════════════════════════════
// PROGRESS
// ═══════════════════════════════════════════════════════════════════════════════

func (o *Output) PrintProgress(stage string, current, total int) {
	o.printProgress(stage, current, total, "")
}

// PrintProgressStatus refreshes a stalled progress line with the active unit
// of work (for example a large classes.dex and its class counter).
func (o *Output) PrintProgressStatus(stage string, current, total int, status string) {
	o.printProgress(stage, current, total, strings.Join(strings.Fields(status), " "))
}

func (o *Output) printProgress(stage string, current, total int, status string) {
	if o.quiet {
		return
	}
	if o.lastStage == stage && o.lastCurrent == current && o.lastTotal == total && o.lastStatus == status {
		return
	}
	o.lastStage = stage
	o.lastCurrent = current
	o.lastTotal = total
	o.lastStatus = status

	percent := 0
	if total > 0 {
		percent = current * 100 / total
	}

	// Redirected output (file, pipe) cannot honour \r repaints: every bar
	// snapshot becomes a permanent line. A 27-minute run produced a 4MB log
	// of nearly identical bars, so plain mode prints rare newline updates.
	if !o.progressTTY() {
		o.printPlainProgress(stage, current, total, percent, status)
		return
	}

	// Live terminal: \r overwrites one line, but still throttle — the
	// pipeline can report every 80ms and stall refreshes every second.
	done := total > 0 && current >= total
	now := time.Now()
	if !done && now.Sub(o.lastProgressAt) < 250*time.Millisecond {
		return
	}
	o.lastProgressAt = now

	t := o.theme
	if !o.tui {
		bar := t.ProgressBar(current, total, 30)
		statusText := ""
		if status != "" {
			statusText = " · " + types.TruncateString(status, 80)
		}
		o.progressPrintf("\r\x1b[K  %s%s%s %s %3d%% [%d/%d]%s   ",
			t.Cyan, stage, t.Reset, bar, percent, current, total, statusText)
		return
	}
	bar := t.ProgressBar(current, total, 28)

	if bar != "" {
		bar = bar + " "
	}

	str := fmt.Sprintf("  %s %s%s%s %s%s%s %3d%% %s[%d/%d]%s",
		t.SpinnerFrame(current),
		t.Bold, stage, t.Reset,
		bar,
		t.Muted, t.Reset, percent, t.Muted, current, total, t.Reset)
	if status != "" {
		available := o.uiWidth() - visibleLen(str) - 3
		if available > 8 {
			str += " · " + types.TruncateString(status, available)
		}
	}

	// Дополняем пробелами до ширины рамки, чтобы гарантированно затереть старые символы
	// (особенно правую границу '│' от предыдущих блоков в Windows PowerShell)
	visibleWidth := visibleLen(str)
	targetWidth := o.uiWidth()
	if visibleWidth < targetWidth {
		str += strings.Repeat(" ", targetWidth-visibleWidth)
	}

	o.progressPrintf("\r\x1b[K%s", str)
}

func (o *Output) ClearProgress() {
	if o.quiet {
		return
	}
	// Plain (redirected) output has no live line to clear; the progress
	// lines there are already newline-terminated.
	if !o.progressTTY() {
		return
	}
	o.progressPrintf("\r\x1b[K")
}

// progressTTY reports whether progress output goes to an interactive
// terminal. Anything else (file, pipe, in-memory buffer) gets throttled
// newline updates instead of \r repaints.
func (o *Output) progressTTY() bool {
	if o == nil {
		return false
	}
	w := o.progressOut()
	if w == nil {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeCharDevice != 0
}

// printPlainProgress emits a newline-terminated progress line for redirected
// output, throttled to 5% steps, 30s heartbeats, or completion. A stalled
// worker chewing one huge dex (same counters, only elapsed seconds changing)
// stays silent instead of appending thousands of identical bar snapshots.
func (o *Output) printPlainProgress(stage string, current, total, percent int, status string) {
	done := total > 0 && current >= total
	if !done {
		sameBucket := percent/5 == o.lastPlainPercent/5
		if sameBucket && time.Since(o.lastProgressAt) < 30*time.Second {
			return
		}
	}
	o.lastProgressAt = time.Now()
	o.lastPlainPercent = percent
	statusText := ""
	if status != "" {
		statusText = " · " + types.TruncateString(status, 80)
	}
	o.progressPrintf("%s %3d%% [%d/%d]%s\n", stage, percent, current, total, statusText)
}

// ═══════════════════════════════════════════════════════════════════════════════
// RESULTS
// ═══════════════════════════════════════════════════════════════════════════════

type riskLevel struct {
	label string
	color string
}

func (o *Output) PrintResults(result *types.AnalysisResult, duration time.Duration) {
	if o.quiet {
		return
	}
	if result.BundleAnalysis != nil && result.BundleAnalysis.Standalone {
		o.printBundleResults(result)
		return
	}
	if !o.tui {
		o.printLegacyResults(result, duration)
		return
	}

	// The neofetch-style card replaces the old stats box: same numbers, plus
	// the per-module breakdown, in fewer lines.
	o.fprintln()
	o.fprintf("  %s%s✓ ANALYSIS COMPLETE%s\n", o.theme.Bold, o.theme.Success, o.theme.Reset)
	o.PrintSystemCard(result, duration)

	// Финальная сводка ошибок/предупреждений pipeline
	o.PrintIssueSummary()
}

func (o *Output) printLegacyResults(result *types.AnalysisResult, duration time.Duration) {
	t := o.theme
	o.fprintln()
	o.printDoubleLine()
	o.fprintf("%s%s ✅ ANALYSIS COMPLETE %s\n", t.Bold, t.Success, t.Reset)
	o.printDoubleLine()

	type statRow struct {
		icon  string
		label string
		value interface{}
		color string
	}
	stats := []statRow{
		{"⏱", "Duration", duration.Round(time.Millisecond), ""},
		{"📁", "Files scanned", result.Stats.TotalFiles, ""},
		{"📊", "Files analyzed", result.Stats.AnalyzedFiles, t.Green},
		{"🧩", "Application units", result.Stats.AppCodeFiles, ""},
		{"🎯", "Matches found", result.Stats.TotalMatches, o.matchColor(result.Stats.TotalMatches)},
		{"🎯", "Priority matches", result.Stats.CriticalMatches, ""},
		{"🔥", "Hotspots", len(result.Hotspots), t.Purple},
	}
	if result.NcerResult != nil {
		stats = append(stats, statRow{"🌐", "NCER d_Causal", fmt.Sprintf("%.4f", result.NcerResult.DCausal), t.Purple})
		evStatus := "unverified"
		if result.NcerResult.EvidenceVerified {
			evStatus = "verified"
		}
		stats = append(stats, statRow{"🗄", "Evidence refs", fmt.Sprintf("%d (%s)", result.NcerResult.EvidenceCount, evStatus), t.Purple})
	}
	for _, s := range stats {
		value := fmt.Sprintf("%v", s.value)
		if s.color != "" {
			value = s.color + value + t.Reset
		}
		labelWithColon := s.label + ":"
		padLen := 18 - len(s.label)
		if padLen < 1 {
			padLen = 1
		}
		o.fprintf("  %s %s%s%s%s %s\n", s.icon, t.Bold, labelWithColon, strings.Repeat(" ", padLen), t.Reset, value)
	}
	o.printDoubleLine()

	for _, line := range o.systemCardModules(result) {
		o.fprintln("  " + line)
	}

	o.fprintln()
	o.printGauge(result)

	risk := o.calculateRiskLevel(result)
	o.fprintf("\n  %s🛡️  Risk Level: %s%s%s%s\n\n", t.Bold, risk.color, t.Bold, risk.label, t.Reset)
	o.PrintIssueSummary()
}

func (o *Output) matchColor(count int) string {
	switch {
	case count == 0:
		return o.theme.Green
	case count < 10:
		return o.theme.Yellow
	default:
		return o.theme.Red
	}
}

func (o *Output) criticalColor(count int) string {
	if count == 0 {
		return o.theme.Green
	}
	return o.theme.Red
}

func (o *Output) calculateRiskLevel(result *types.AnalysisResult) riskLevel {
	t := o.theme
	if profile := report.SuspicionScore(result).Profile; profile != nil {
		color := t.Green
		switch profile.OverallLevel {
		case "HIGH", "MEDIUM":
			color = t.Yellow
		case "CRITICAL":
			color = t.Red
		}
		return riskLevel{profile.OverallLevel, color}
	}

	if len(result.Hotspots) == 0 && result.Stats.CriticalMatches == 0 {
		return riskLevel{"LOW", t.Green}
	}

	maxScore := 0.0
	for _, hs := range result.Hotspots {
		if hs.Score > maxScore {
			maxScore = hs.Score
		}
	}

	criticals := result.Stats.CriticalMatches

	switch {
	case maxScore >= 60 || criticals >= 10:
		return riskLevel{"CRITICAL", t.Red}
	case maxScore >= 45 || criticals >= 5:
		return riskLevel{"HIGH", t.Yellow}
	case maxScore >= 30:
		return riskLevel{"MEDIUM", t.Yellow}
	default:
		return riskLevel{"LOW", t.Green}
	}
}

// riskScore is the canonical 0-100 suspicion score shared with the HTML
// and Markdown reports (report.SuspicionScore), so every surface shows
// the same number.
func (o *Output) riskScore(result *types.AnalysisResult) int {
	return report.SuspicionScore(result).Score
}

// ═══════════════════════════════════════════════════════════════════════════════
// NEXT STEPS
// ═══════════════════════════════════════════════════════════════════════════════

func (o *Output) PrintNextSteps(outputDir string, includeHTML bool, extraFiles []GeneratedFile) {
	if o.quiet {
		return
	}
	if !o.tui {
		o.printLegacyNextSteps(outputDir, includeHTML, extraFiles)
		return
	}

	if abs, err := filepath.Abs(outputDir); err == nil {
		outputDir = abs
	}

	t := o.theme
	width := o.uiWidth()

	files := []GeneratedFile{
		{Name: "REPORT.md", Desc: "Detailed analysis report"},
	}
	if includeHTML {
		files = append(files, GeneratedFile{Name: "REPORT.html", Desc: "Interactive HTML report"})
	}
	files = append(files, GeneratedFile{Name: "analysis.json", Desc: "JSON data for tools"})
	files = append(files, extraFiles...)

	var steps []string

	if includeHTML {
		steps = append(steps,
			fmt.Sprintf("Open %s%s/REPORT.html%s for interactive triage", t.Yellow, outputDir, t.Reset))
	}
	if len(extraFiles) > 0 {
		steps = append(steps,
			fmt.Sprintf("Check %s%s/%s%s for ML patch points", t.Yellow, outputDir, extraFiles[0].Name, t.Reset))
	}

	steps = append(steps,
		fmt.Sprintf("Open %s%s/REPORT.md%s", t.Yellow, outputDir, t.Reset),
		fmt.Sprintf("Review %sHOTSPOTS%s — most important files", t.Red, t.Reset),
		fmt.Sprintf("Inspect %sanalysis.json%s for programmatic triage", t.Green, t.Reset),
	)

	lines := []string{
		fmt.Sprintf("%s📋 GENERATED FILES:%s", t.Bold+t.Primary, t.Reset),
	}
	for _, f := range files {
		fullPath := filepath.Join(outputDir, f.Name)
		lines = append(lines, fmt.Sprintf("%s•%s %s%s%s — %s", t.Secondary, t.Reset, t.Warning, fullPath, t.Reset, f.Desc))
	}
	lines = append(lines, "", fmt.Sprintf("%s📋 NEXT STEPS:%s", t.Bold+t.Accent, t.Reset))
	for i, step := range steps {
		lines = append(lines, fmt.Sprintf("%s%d.%s %s", t.Secondary, i+1, t.Reset, step))
	}
	style := boxStyle{
		topLeft: "╭", topRight: "╮", botLeft: "╰", botRight: "╯",
		horizontal: "─", vertical: "│",
		color:      t.Edge,
		titleColor: t.Bold + t.Accent,
		icon:       "◆",
	}

	o.fprintln()
	o.drawBox(o.writer, style, "NEXT STEPS", lines, width)
}

func (o *Output) printLegacyNextSteps(outputDir string, includeHTML bool, extraFiles []GeneratedFile) {
	if abs, err := filepath.Abs(outputDir); err == nil {
		outputDir = abs
	}

	t := o.theme
	files := []GeneratedFile{
		{Name: "REPORT.md", Desc: "Detailed analysis report"},
	}
	if includeHTML {
		files = append(files, GeneratedFile{Name: "REPORT.html", Desc: "Interactive HTML report"})
	}
	files = append(files, GeneratedFile{Name: "analysis.json", Desc: "JSON data for tools"})
	files = append(files, extraFiles...)

	o.fprintf("%s📋 GENERATED FILES:%s\n", t.Bold, t.Reset)
	for _, f := range files {
		fullPath := filepath.Join(outputDir, f.Name)
		o.fprintf("  %s•%s %s%s%s — %s\n", t.Cyan, t.Reset, t.Yellow, fullPath, t.Reset, f.Desc)
	}
	o.fprintln()

	var steps []string
	if includeHTML {
		steps = append(steps, fmt.Sprintf("Open %s%s/REPORT.html%s for interactive triage", t.Yellow, outputDir, t.Reset))
	}
	if len(extraFiles) > 0 {
		steps = append(steps, fmt.Sprintf("Check %s%s/%s%s for ML patch points", t.Yellow, outputDir, extraFiles[0].Name, t.Reset))
	}
	steps = append(steps,
		fmt.Sprintf("Open %s%s/REPORT.md%s", t.Yellow, outputDir, t.Reset),
		fmt.Sprintf("Review %sHOTSPOTS%s — most important files", t.Red, t.Reset),
		fmt.Sprintf("Inspect %sanalysis.json%s for programmatic triage", t.Green, t.Reset),
	)

	o.fprintf("%s📋 NEXT STEPS:%s\n", t.Bold, t.Reset)
	for i, step := range steps {
		o.fprintf("  %s%d.%s %s\n", t.Cyan, i+1, t.Reset, step)
	}
	o.printDoubleLine()
}

// ═══════════════════════════════════════════════════════════════════════════════
// ПУБЛИЧНЫЕ МЕТОДЫ ЛОГИРОВАНИЯ
// ═══════════════════════════════════════════════════════════════════════════════

func (o *Output) Print(format string, args ...interface{}) {
	if !o.quiet {
		o.fprintf(format, args...)
	}
}

func (o *Output) Println(args ...interface{}) {
	if !o.quiet {
		o.fprintln(args...)
	}
}

func (o *Output) Success(format string, args ...interface{}) {
	if !o.quiet {
		o.fprintf("%s✓ %s%s\n", o.theme.Success, fmt.Sprintf(format, args...), o.theme.Reset)
	}
}

func (o *Output) Info(format string, args ...interface{}) {
	if !o.quiet {
		o.fprintf("%sℹ %s%s\n", o.theme.Info, fmt.Sprintf(format, args...), o.theme.Reset)
	}
}

func (o *Output) Debug(format string, args ...interface{}) {
	if !o.quiet {
		o.fprintf("%s🔧 %s%s\n", o.theme.Info, fmt.Sprintf(format, args...), o.theme.Reset)
	}
}

// timestamp возвращает короткое время для важных событий.
func timestamp() string {
	return time.Now().Format("15:04:05")
}

// ─────────────────────────────────────────────────────────────────────────────
// 🟡 WARNING — заметное предупреждение
// ─────────────────────────────────────────────────────────────────────────────

// Warning выводит предупреждение (не подавляется в quiet-режиме).
// Теперь в виде яркого баннера, чтобы реально привлекало внимание.
func (o *Output) Warning(format string, args ...interface{}) {
	o.warningCount.Add(1)
	t := o.theme
	msg := fmt.Sprintf(format, args...)

	o.eprintf("%s%s ⚠️  WARNING %s%s [%s] %s%s%s\n",
		t.Bold, t.Yellow, t.Reset,
		t.Yellow, timestamp(),
		t.Bold, msg, t.Reset,
	)
}

// ─────────────────────────────────────────────────────────────────────────────
// 🔴 ERROR — заметная ошибка
// ─────────────────────────────────────────────────────────────────────────────

// Error выводит ошибку — теперь яркую, в одну строку, с таймштампом.
func (o *Output) Error(format string, args ...interface{}) {
	o.errorCount.Add(1)
	t := o.theme
	msg := fmt.Sprintf(format, args...)

	o.eprintf("%s%s 🔴 ERROR %s%s [%s] %s%s%s\n",
		t.Bold, t.Red, t.Reset,
		t.Red, timestamp(),
		t.Bold, msg, t.Reset,
	)
}

// ─────────────────────────────────────────────────────────────────────────────
// 🚨 PIPELINE ERROR / WARNING — самые заметные сообщения для CI/pipeline
// ─────────────────────────────────────────────────────────────────────────────

// PipelineError — ошибка этапа pipeline. Боксированная, невозможно пропустить.
// Заменяет старые ERR-логи на чёткое 🔴 ERROR + контекст.
func (o *Output) PipelineError(stage string, err error, details ...string) {
	o.errorCount.Add(1)
	t := o.theme

	style := boxStyle{
		topLeft: "╔", topRight: "╗", botLeft: "╚", botRight: "╝",
		horizontal: "═", vertical: "║",
		color:      t.Red + t.Bold,
		titleColor: t.Bold + t.Red,
		icon:       "🔴",
	}

	title := fmt.Sprintf("PIPELINE ERROR — %s", strings.ToUpper(stage))

	lines := []string{
		fmt.Sprintf("%s⏱  Time:  %s%s%s", t.Bold, t.Reset, timestamp(), t.Reset),
		fmt.Sprintf("%s🧩 Stage: %s%s%s%s", t.Bold, t.Reset, t.Yellow, stage, t.Reset),
		fmt.Sprintf("%s💥 Error: %s%s%s%s", t.Bold, t.Reset, t.Red, err, t.Reset),
	}

	for _, d := range details {
		if strings.TrimSpace(d) != "" {
			lines = append(lines, fmt.Sprintf("%s📎 %s%s", t.Gray, d, t.Reset))
		}
	}

	o.eprintf("\n")
	o.drawBox(o.errWriter, style, title, lines, 78)
	o.eprintf("\n")
}

// PipelineWarning — заметное предупреждение об этапе pipeline.
// Используется для деградаций, которые не валят весь анализ.
func (o *Output) PipelineWarning(stage string, msg string, details ...string) {
	o.warningCount.Add(1)
	t := o.theme

	style := boxStyle{
		topLeft: "╔", topRight: "╗", botLeft: "╚", botRight: "╝",
		horizontal: "═", vertical: "║",
		color:      t.Yellow + t.Bold,
		titleColor: t.Bold + t.Yellow,
		icon:       "⚠️ ",
	}

	title := fmt.Sprintf("PIPELINE WARNING — %s", strings.ToUpper(stage))

	lines := []string{
		fmt.Sprintf("%s⏱  Time:  %s%s%s", t.Bold, t.Reset, timestamp(), t.Reset),
		fmt.Sprintf("%s🧩 Stage: %s%s%s%s", t.Bold, t.Reset, t.Cyan, stage, t.Reset),
		fmt.Sprintf("%s📣 Msg:   %s%s%s", t.Bold, t.Reset, msg, t.Reset),
	}

	for _, d := range details {
		if strings.TrimSpace(d) != "" {
			lines = append(lines, fmt.Sprintf("%s📎 %s%s", t.Gray, d, t.Reset))
		}
	}

	o.eprintf("\n")
	o.drawBox(o.errWriter, style, title, lines, 78)
	o.eprintf("\n")
}

// Critical — критическое событие (между Error и Fatal).
// Не завершает программу, но кричит максимально громко.
func (o *Output) Critical(format string, args ...interface{}) {
	o.criticalCount.Add(1)
	t := o.theme
	msg := fmt.Sprintf(format, args...)

	style := boxStyle{
		topLeft: "█", topRight: "█", botLeft: "█", botRight: "█",
		horizontal: "█", vertical: "█",
		color:      t.Red + t.Bold,
		titleColor: t.Bold + t.Red,
		icon:       "🚨",
	}

	o.eprintf("\n")
	o.drawBox(o.errWriter, style, "CRITICAL ISSUE", []string{
		fmt.Sprintf("%s⏱  %s%s", t.Bold, t.Reset, timestamp()),
		msg,
	}, 78)
	o.eprintf("\n")
}

// Fatal — выводит критическую ошибку и завершает программу.
func (o *Output) Fatal(exitCode int, format string, args ...interface{}) {
	o.criticalCount.Add(1)
	t := o.theme
	msg := fmt.Sprintf(format, args...)

	style := boxStyle{
		topLeft: "╔", topRight: "╗", botLeft: "╚", botRight: "╝",
		horizontal: "═", vertical: "║",
		color:      t.Red + t.Bold,
		titleColor: t.Bold + t.Red,
		icon:       "💀",
	}

	o.eprintf("\n")
	o.drawBox(o.errWriter, style, "FATAL ERROR", []string{
		fmt.Sprintf("%s⏱  Time: %s%s", t.Bold, t.Reset, timestamp()),
		msg,
		"",
		fmt.Sprintf("%sProgram will exit with code %d%s", t.Gray, exitCode, t.Reset),
	}, 78)
	o.eprintf("\n")

	os.Exit(exitCode)
}

// ─────────────────────────────────────────────────────────────────────────────
// 📦 BOXED HELPERS — универсальные боксированные сообщения
// ─────────────────────────────────────────────────────────────────────────────

// BoxedError выводит ошибку в красивой красной рамке с заголовком.
func (o *Output) BoxedError(title, body string) {
	o.errorCount.Add(1)
	t := o.theme
	style := boxStyle{
		topLeft: "╔", topRight: "╗", botLeft: "╚", botRight: "╝",
		horizontal: "═", vertical: "║",
		color:      t.Red + t.Bold,
		titleColor: t.Bold + t.Red,
		icon:       "🔴",
	}
	o.eprintf("\n")
	o.drawBox(o.errWriter, style, title, strings.Split(body, "\n"), 78)
	o.eprintf("\n")
}

// BoxedWarning выводит предупреждение в жёлтой рамке.
func (o *Output) BoxedWarning(title, body string) {
	o.warningCount.Add(1)
	t := o.theme
	style := boxStyle{
		topLeft: "╔", topRight: "╗", botLeft: "╚", botRight: "╝",
		horizontal: "═", vertical: "║",
		color:      t.Yellow + t.Bold,
		titleColor: t.Bold + t.Yellow,
		icon:       "⚠️ ",
	}
	o.eprintf("\n")
	o.drawBox(o.errWriter, style, title, strings.Split(body, "\n"), 78)
	o.eprintf("\n")
}

// ─────────────────────────────────────────────────────────────────────────────
// 📊 ITOG — финальная сводка по ошибкам/предупреждениям
// ─────────────────────────────────────────────────────────────────────────────

// ErrorCount возвращает накопленное число ошибок.
func (o *Output) ErrorCount() int64 { return o.errorCount.Load() }

// WarningCount возвращает накопленное число предупреждений.
func (o *Output) WarningCount() int64 { return o.warningCount.Load() }

// CriticalCount возвращает накопленное число критических событий.
func (o *Output) CriticalCount() int64 { return o.criticalCount.Load() }

// HasErrors true, если были ошибки или critical-события.
func (o *Output) HasErrors() bool {
	return o.errorCount.Load() > 0 || o.criticalCount.Load() > 0
}

// PrintIssueSummary печатает финальную сводку проблем (если они были).
func (o *Output) PrintIssueSummary() {
	errs := o.errorCount.Load()
	warns := o.warningCount.Load()
	crits := o.criticalCount.Load()

	if errs == 0 && warns == 0 && crits == 0 {
		return
	}

	t := o.theme
	o.fprintln()
	o.printDoubleLine()
	o.fprintf("%s%s 📊 ISSUES SUMMARY %s\n", t.Bold, t.Purple, t.Reset)
	o.printDoubleLine()

	if crits > 0 {
		o.fprintf("  %s🚨 Critical:%s    %s%d%s\n",
			t.Bold, t.Reset, t.Red+t.Bold, crits, t.Reset)
	}
	if errs > 0 {
		o.fprintf("  %s🔴 Errors:%s      %s%d%s\n",
			t.Bold, t.Reset, t.Red, errs, t.Reset)
	}
	if warns > 0 {
		o.fprintf("  %s⚠️  Warnings:%s   %s%d%s\n",
			t.Bold, t.Reset, t.Yellow, warns, t.Reset)
	}

	o.printDoubleLine()
	o.fprintln()
}
