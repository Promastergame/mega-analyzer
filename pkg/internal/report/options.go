package report

// ═══════════════════════════════════════════════════════════════════════════════
// OPTIONS — настройки генерации отчёта
// ═══════════════════════════════════════════════════════════════════════════════

type MarkdownOptions struct {
	// Лимиты
	MaxHotspots        int
	MaxHotspotDetails  int
	MaxReasonLen       int
	MaxPathLen         int
	MaxFilesPerRec     int
	MaxRecommendations int
	MaxDetections      int
	MaxPiracyFindings  int

	// Отображение
	ShowDetails        bool
	ShowMethods        bool
	ShowRelatedFiles   bool
	ShowScoreBar       bool
	ShowEmptyGroups    bool // показывать группы с 0 детекций
	CollapsibleDetails bool

	// Мета
	EngineVersion string
	ReportSchema  string
	Profile       string

	// Фильтры
	MinHotspotScore float64
	MinConfidence   float64
}

// HTMLOptions — настройки генерации HTML-отчёта.
type HTMLOptions struct {
	ContextLinesBefore     int  // строк до совпадения (25)
	ContextLinesAfter      int  // строк после совпадения (25)
	DefaultSnippetLines    int  // по умолчанию показывать N строк в таблице
	MaxSnippetsPerMatch    int  // общий лимит snippets
	MaxSnippetsPerCategory int  // лимит snippets на категорию
	EnableCodeHighlight    bool // подсветка синтаксиса
	EnableFilters          bool // интерактивные фильтры
	DarkTheme              bool // темная тема
}

// ArtifactsOptions — настройки сбора Artifacts (раздел отчёта,
// показывающий извлечённые из APK файлы: картинки, 3D, .so, прочее).
//
// По умолчанию выключено. Если EnableArtifacts == false, сбор не
// запускается и в ReportView/JSON не появится никаких новых полей.
type ArtifactsOptions struct {
	EnableArtifacts bool   // master toggle
	AllowExport     bool   // показывать кнопки Export в HTML
	MaxFileMB       int    // per-file embed cap (default: 10)
	BudgetMB        int    // total embed cap (default: 200)
	NoImageBlur     bool   // отключить blur для possible-sensitive
	ExtractedDir    string // путь к распакованному APK (передаётся runner'ом)
}

// DefaultArtifactsOptions returns the canonical defaults.
func DefaultArtifactsOptions() ArtifactsOptions {
	return ArtifactsOptions{
		EnableArtifacts: false,
		AllowExport:     false,
		MaxFileMB:       10,
		BudgetMB:        200,
		NoImageBlur:     false,
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// PRESETS
// ═══════════════════════════════════════════════════════════════════════════════

func DefaultOptions() MarkdownOptions {
	return MarkdownOptions{
		MaxHotspots:        20,
		MaxHotspotDetails:  10,
		MaxReasonLen:       80,
		MaxPathLen:         60,
		MaxFilesPerRec:     5,
		MaxRecommendations: 15,
		MaxDetections:      30,
		MaxPiracyFindings:  30,

		ShowDetails:        true,
		ShowMethods:        true,
		ShowRelatedFiles:   true,
		ShowScoreBar:       true,
		ShowEmptyGroups:    false,
		CollapsibleDetails: true,

		EngineVersion: "1.0.0",
		ReportSchema:  "2.0",
		Profile:       "balanced",
	}
}

func ShortReportOptions() MarkdownOptions {
	opts := DefaultOptions()
	opts.MaxHotspots = 10
	opts.MaxHotspotDetails = 5
	opts.MaxRecommendations = 5
	opts.MaxDetections = 10
	opts.MaxPiracyFindings = 10
	opts.ShowMethods = false
	opts.ShowRelatedFiles = false
	opts.CollapsibleDetails = false
	return opts
}

func FullReportOptions() MarkdownOptions {
	opts := DefaultOptions()
	opts.MaxHotspots = 100
	opts.MaxHotspotDetails = 50
	opts.MaxRecommendations = 50
	opts.MaxFilesPerRec = 20
	opts.MaxDetections = 200
	opts.MaxPiracyFindings = 200
	// In "full" mode we want to avoid cosmetic truncation in tables.
	// 0 means "no truncation / unlimited" (see builder helpers).
	opts.MaxPathLen = 0
	opts.MaxReasonLen = 0
	opts.ShowEmptyGroups = true
	return opts
}

// AllReportOptions disables all limits/truncation. This can produce very large REPORT.md.
func AllReportOptions() MarkdownOptions {
	opts := DefaultOptions()
	opts.MaxHotspots = 0
	opts.MaxHotspotDetails = 0
	opts.MaxReasonLen = 0
	opts.MaxPathLen = 0
	opts.MaxFilesPerRec = 0
	opts.MaxRecommendations = 0
	opts.MaxDetections = 0
	opts.MaxPiracyFindings = 0
	opts.ShowEmptyGroups = true
	return opts
}

func CIReportOptions() MarkdownOptions {
	opts := DefaultOptions()
	opts.MaxHotspots = 30
	opts.CollapsibleDetails = false
	opts.ShowScoreBar = false
	return opts
}

func DefaultHTMLOptions() HTMLOptions {
	return HTMLOptions{
		ContextLinesBefore:     25,
		ContextLinesAfter:      25,
		DefaultSnippetLines:    7,
		MaxSnippetsPerMatch:    0,
		MaxSnippetsPerCategory: 200,
		EnableCodeHighlight:    true,
		EnableFilters:          true,
		DarkTheme:              true,
	}
}
