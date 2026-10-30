package main

import (
	"os"
	"runtime"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// THEME - цветовая схема
// ═══════════════════════════════════════════════════════════════════════════════

type Theme struct {
	// Basic colors
	Reset  string
	Red    string
	Green  string
	Yellow string
	Blue   string
	Purple string
	Cyan   string
	White  string
	Gray   string

	// Styles
	Bold      string
	Dim       string
	Italic    string
	Underline string

	// Semantic colors
	Error   string
	Warning string
	Success string
	Info    string
	Hint    string

	// UI elements
	Border    string
	Highlight string
	Muted     string
	Primary   string
	Secondary string
	Accent    string
	Edge      string
	Text      string
	Panel     string
}

// ═══════════════════════════════════════════════════════════════════════════════
// THEME DETECTION
// ═══════════════════════════════════════════════════════════════════════════════

func DetectTheme(noColor bool) Theme {
	// Если цвета отключены
	if noColor || !supportsColor() {
		return NoColorTheme()
	}

	// Проверяем тёмную/светлую тему терминала
	if isDarkTerminal() {
		return DarkTheme()
	}

	return DarkTheme() // По умолчанию тёмная
}

func supportsColor() bool {
	// Проверка NO_COLOR env
	if os.Getenv("NO_COLOR") != "" {
		return false
	}

	// Проверка TERM
	term := os.Getenv("TERM")
	if term == "dumb" {
		return false
	}
	termLower := strings.ToLower(term)

	// Windows
	if runtime.GOOS == "windows" {
		// Windows Terminal и новые консоли поддерживают ANSI
		if os.Getenv("WT_SESSION") != "" {
			return true
		}
		if os.Getenv("ANSICON") != "" {
			return true
		}
		// ConEmu
		if os.Getenv("ConEmuANSI") == "ON" {
			return true
		}
		if strings.Contains(termLower, "xterm") ||
			strings.Contains(termLower, "256color") ||
			strings.Contains(termLower, "ansi") ||
			strings.Contains(termLower, "color") ||
			strings.Contains(termLower, "screen") {
			return true
		}
		// Windows 10+ с включенным VT
		return os.Getenv("TERM_PROGRAM") != ""
	}

	// Unix-like: проверяем stdout
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}

	return (fi.Mode() & os.ModeCharDevice) != 0
}

func isDarkTerminal() bool {
	// Простая эвристика
	colorfgbg := os.Getenv("COLORFGBG")
	if colorfgbg != "" {
		// Формат: "15;0" (fg;bg)
		// Если bg < 8, скорее всего тёмная тема
		return true
	}

	return true // По умолчанию считаем тёмной
}

// ═══════════════════════════════════════════════════════════════════════════════
// PRESET THEMES
// ═══════════════════════════════════════════════════════════════════════════════

func DarkTheme() Theme {
	return Theme{
		// Basic
		Reset:  "\033[0m",
		Red:    "\033[38;2;224;108;117m",
		Green:  "\033[38;2;127;216;143m",
		Yellow: "\033[38;2;245;167;66m",
		Blue:   "\033[38;2;92;156;245m",
		Purple: "\033[38;2;157;124;216m",
		Cyan:   "\033[38;2;86;182;194m",
		White:  "\033[38;2;238;238;238m",
		Gray:   "\033[38;2;128;128;128m",

		// Styles
		Bold:      "\033[1m",
		Dim:       "\033[2m",
		Italic:    "\033[3m",
		Underline: "\033[4m",

		// Semantic (яркие для тёмного фона)
		Error:   "\033[1;38;2;224;108;117m", // Bold red
		Warning: "\033[1;38;2;245;167;66m",  // Bold yellow
		Success: "\033[1;38;2;127;216;143m", // Bold green
		Info:    "\033[1;38;2;86;182;194m",  // Bold cyan
		Hint:    "\033[2;38;2;238;238;238m", // Dim white

		// UI
		Border:    "\033[38;2;72;72;72m",      // Edge gray
		Highlight: "\033[1;38;2;157;124;216m", // Bold purple
		Muted:     "\033[38;2;128;128;128m",   // Gray
		Primary:   "\033[38;2;250;178;131m",
		Secondary: "\033[38;2;92;156;245m",
		Accent:    "\033[38;2;157;124;216m",
		Edge:      "\033[38;2;60;60;60m",
		Text:      "\033[38;2;238;238;238m",
		Panel:     "\033[48;2;20;20;20m",
	}
}

func LightTheme() Theme {
	return Theme{
		// Basic (темнее для светлого фона)
		Reset:  "\033[0m",
		Red:    "\033[91m",
		Green:  "\033[92m",
		Yellow: "\033[93m",
		Blue:   "\033[94m",
		Purple: "\033[95m",
		Cyan:   "\033[96m",
		White:  "\033[97m",
		Gray:   "\033[37m",

		// Styles
		Bold:      "\033[1m",
		Dim:       "\033[2m",
		Italic:    "\033[3m",
		Underline: "\033[4m",

		// Semantic
		Error:   "\033[31m",
		Warning: "\033[33m",
		Success: "\033[32m",
		Info:    "\033[34m",
		Hint:    "\033[90m",

		// UI
		Border:    "\033[34m",
		Highlight: "\033[35m",
		Muted:     "\033[90m",
		Primary:   "\033[38;2;168;89;39m",
		Secondary: "\033[38;2;32;103;196m",
		Accent:    "\033[38;2;108;82;166m",
		Edge:      "\033[38;2;120;120;120m",
		Text:      "\033[38;2;35;35;35m",
		Panel:     "",
	}
}

func NoColorTheme() Theme {
	return Theme{
		Reset: "", Red: "", Green: "", Yellow: "", Blue: "",
		Purple: "", Cyan: "", White: "", Gray: "",
		Bold: "", Dim: "", Italic: "", Underline: "",
		Error: "", Warning: "", Success: "", Info: "", Hint: "",
		Border: "", Highlight: "", Muted: "",
		Primary: "", Secondary: "", Accent: "", Edge: "", Text: "", Panel: "",
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// THEME HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

// Colorize применяет цвет к тексту
func (t Theme) Colorize(color, text string) string {
	if color == "" {
		return text
	}
	return color + text + t.Reset
}

// Error форматирует ошибку
func (t Theme) FormatError(text string) string {
	return t.Error + "✗ " + text + t.Reset
}

// Success форматирует успех
func (t Theme) FormatSuccess(text string) string {
	return t.Success + "✓ " + text + t.Reset
}

// Warning форматирует предупреждение
func (t Theme) FormatWarning(text string) string {
	return t.Warning + "⚠ " + text + t.Reset
}

// Info форматирует информацию
func (t Theme) FormatInfo(text string) string {
	return t.Info + "ℹ " + text + t.Reset
}

// ProgressBar возвращает прогресс-бар
func (t Theme) ProgressBar(current, total int, width int) string {
	if total == 0 {
		return ""
	}

	percent := float64(current) / float64(total)
	filled := int(percent * float64(width))
	if filled > width {
		filled = width
	}

	bar := ""
	filledColor := t.Primary
	if filledColor == "" {
		filledColor = t.Green
	}
	emptyColor := t.Edge
	if emptyColor == "" {
		emptyColor = t.Gray
	}
	for i := 0; i < width; i++ {
		if i < filled {
			bar += filledColor + "█" + t.Reset
		} else {
			bar += emptyColor + "░" + t.Reset
		}
	}

	return bar
}

// Spinner symbols
var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

func (t Theme) SpinnerFrame(frame int) string {
	color := t.Primary
	if color == "" {
		color = t.Cyan
	}
	return color + spinnerFrames[frame%len(spinnerFrames)] + t.Reset
}
