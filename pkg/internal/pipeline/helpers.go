// pkg/internal/pipeline/helpers.go
package pipeline

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"strings"

	"mega-analyzer/pkg/internal/types"
)

// ═══════════════════════════════════════════════════════════════════════════════
// FILE JOB
// ═══════════════════════════════════════════════════════════════════════════════

type FileJob struct {
	Path      string
	RelPath   string
	Type      types.FileType
	Size      int64
	Hash      uint64
	WorkUnits int64
	// ForceAppCode marks virtual class streams derived from a primary DEX.
	ForceAppCode bool
}

// dexClassWorkUnits reads class_defs_size from the fixed DEX header. Falling
// back to one unit keeps malformed DEX files visible and lets their raw scan
// complete progress instead of leaving the bar short of 100%.
func dexClassWorkUnits(path string) int64 {
	const (
		dexHeaderBytes  = 0x64
		classDefsOffset = 0x60
	)
	f, err := os.Open(path)
	if err != nil {
		return 1
	}
	defer f.Close()
	var header [dexHeaderBytes]byte
	if _, err := io.ReadFull(f, header[:]); err != nil || !bytes.HasPrefix(header[:], []byte("dex\n")) {
		return 1
	}
	if n := binary.LittleEndian.Uint32(header[classDefsOffset : classDefsOffset+4]); n > 0 {
		return int64(n)
	}
	return 1
}

// dexClassVirtualPath returns an apktool-compatible path for an in-memory DEX
// class stream. The path is never written; it is used solely by the existing
// package classifier and detector rules that are expressed in smali paths.
func dexClassVirtualPath(dexRelPath, className string) string {
	name := strings.TrimSpace(className)
	name = strings.TrimPrefix(name, "L")
	name = strings.TrimSuffix(name, ";")
	name = strings.ReplaceAll(name, ".", "/")
	name = strings.Trim(name, "/")
	if name == "" {
		return filepath.ToSlash(dexRelPath) + "::unknown-class"
	}
	return "smali/" + name + ".smali"
}

// ═══════════════════════════════════════════════════════════════════════════════
// FILE CLASSIFICATION — быстрый lookup по расширению
// ═══════════════════════════════════════════════════════════════════════════════
//
// Раньше: strings.ToLower(filepath.Ext(path)) → switch
//   = 2 аллокации на КАЖДЫЙ файл (ToLower + Ext создают новые строки)
//   Для 50 000 файлов = 100 000 лишних аллокаций
//
// Теперь: extToFileType map + fastLowerExt без аллокаций для ASCII
//   = 0 аллокаций для типичных путей

// extToFileType — предвычисленная карта расширений.
// Все ключи в lowercase. Ищем за O(1).
var extToFileType = map[string]types.FileType{
	// ── Код (основные для APK) ───────────────────────────────────────────
	".smali": types.FileTypeSmali,
	".java":  types.FileTypeSmali, // декомпилированный Java — обрабатываем как код
	".kt":    types.FileTypeSmali, // Kotlin — обрабатываем как код

	// ── Разметка и конфиги ───────────────────────────────────────────────
	".xml":        types.FileTypeXML,
	".plist":      types.FileTypeXML,
	".json":       types.FileTypeJSON,
	".properties": types.FileTypeProperties,

	// ── Текстовые ────────────────────────────────────────────────────────
	".txt":             types.FileTypeText,
	".yml":             types.FileTypeText,
	".yaml":            types.FileTypeText,
	".cfg":             types.FileTypeText,
	".conf":            types.FileTypeText,
	".ini":             types.FileTypeText,
	".md":              types.FileTypeText,
	".log":             types.FileTypeText,
	".env":             types.FileTypeText,
	".toml":            types.FileTypeText,
	".csv":             types.FileTypeText,
	".sql":             types.FileTypeText,
	".strings":         types.FileTypeText,
	".mobileprovision": types.FileTypeText,
	".js":              types.FileTypeText,
	".mjs":             types.FileTypeText,
	".cjs":             types.FileTypeText,
	".ts":              types.FileTypeText,
	".tsx":             types.FileTypeText,
	".lua":             types.FileTypeText,
	".swift":           types.FileTypeText,
	".m":               types.FileTypeText,
	".mm":              types.FileTypeText,
	".pem":             types.FileTypeText,
	".crt":             types.FileTypeText,
	".cer":             types.FileTypeText,
	".key":             types.FileTypeText,
	".pub":             types.FileTypeText,
	".html":            types.FileTypeText,
	".htm":             types.FileTypeText,

	// ── Ресурсы (Media & Documents) ──────────────────────────────────────
	".png":  types.FileTypeMedia,
	".jpg":  types.FileTypeMedia,
	".jpeg": types.FileTypeMedia,
	".webp": types.FileTypeMedia,
	".gif":  types.FileTypeMedia,
	".bmp":  types.FileTypeMedia,
	".svg":  types.FileTypeResource,
	".ico":  types.FileTypeResource,
	".mp4":  types.FileTypeMedia,
	".mp3":  types.FileTypeMedia,
	".wav":  types.FileTypeMedia,
	".ogg":  types.FileTypeMedia,
	".pdf":  types.FileTypeMedia,

	// ── Нативные библиотеки и DEX ────────────────────────────────────────
	".so":   types.FileTypeNative,
	".dex":  types.FileTypeDex,
	".vdex": types.FileTypeDex,
	".odex": types.FileTypeDex,
	".oat":  types.FileTypeDex,
	".art":  types.FileTypeDex,

	// ── Signature artifacts ──────────────────────────────────────────────
	".mf":  types.FileTypeSignature,
	".sf":  types.FileTypeSignature,
	".rsa": types.FileTypeSignature,
	".dsa": types.FileTypeSignature,
	".ec":  types.FileTypeSignature,

	// ── Cache & Patch ────────────────────────────────────────────────────
	".prof":  types.FileTypeCache,
	".patch": types.FileTypePatch,
	".diff":  types.FileTypePatch,
}

// classifyFile определяет тип файла по расширению.
// Использует быстрый lookup O(1) вместо switch.
func classifyFile(path string) types.FileType {
	ext := fastLowerExt(path)
	if ext == "" {
		return types.FileTypeUnknown
	}

	if ft, ok := extToFileType[ext]; ok {
		return ft
	}
	return types.FileTypeUnknown
}

// fastLowerExt извлекает расширение файла в lowercase БЕЗ аллокаций
// для ASCII-путей (99.9% случаев в APK).
//
// filepath.Ext + strings.ToLower = 2 аллокации
// fastLowerExt = 0 аллокаций (для ASCII)
//
// Возвращает "" если расширения нет.
func fastLowerExt(path string) string {
	// Ищем последнюю точку (как filepath.Ext, но без аллокации)
	for i := len(path) - 1; i >= 0; i-- {
		switch path[i] {
		case '.':
			ext := path[i:]
			// Проверяем: нужен ли ToLower?
			// Для ASCII-путей (a-z, A-Z, 0-9, ., _) — делаем inline
			needsLower := false
			for j := 0; j < len(ext); j++ {
				if ext[j] >= 'A' && ext[j] <= 'Z' {
					needsLower = true
					break
				}
			}
			if !needsLower {
				return ext // уже lowercase, 0 аллокаций!
			}
			// Редкий случай: есть uppercase буквы
			return strings.ToLower(ext)

		case '/', '\\':
			// Дошли до разделителя пути — расширения нет
			return ""
		}
	}
	return ""
}

// IsCodeFile проверяет, является ли файл кодом (smali, java, kt, dex)
func IsCodeFile(fileType types.FileType) bool {
	return fileType == types.FileTypeSmali || fileType == types.FileTypeDex
}

// IsTextAnalyzable проверяет, можно ли анализировать содержимое файла как текст
func IsTextAnalyzable(fileType types.FileType) bool {
	switch fileType {
	case types.FileTypeSmali, types.FileTypeXML, types.FileTypeJSON,
		types.FileTypeProperties, types.FileTypeText, types.FileTypeSignature:
		return true
	default:
		return false
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// HYBRID DEX-IN-ZIP DETECTION
// ═══════════════════════════════════════════════════════════════════════════════

var dexEntryMarker = []byte("classes")

func isDexContainer(path string) bool {
	if !quickScanForDexMarker(path) {
		return false
	}
	return confirmDexViaZip(path)
}

func quickScanForDexMarker(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	buf := make([]byte, 65536)
	n, _ := io.ReadAtLeast(f, buf, 4)
	if n < 4 {
		return false
	}
	data := buf[:n]

	pos := 0
	for {
		idx := bytes.Index(data[pos:], dexEntryMarker)
		if idx == -1 {
			return false
		}
		abs := pos + idx
		end := abs + len(dexEntryMarker)

		window := data[end:]
		if len(window) > 12 {
			window = window[:12]
		}
		if bytes.Contains(window, []byte(".dex")) {
			return true
		}
		pos = abs + 1
	}
}

func confirmDexViaZip(path string) bool {
	r, err := zip.OpenReader(path)
	if err != nil {
		return true
	}
	defer r.Close()

	for _, f := range r.File {
		name := strings.ToLower(f.Name)
		if name == "classes.dex" {
			return true
		}
		if strings.HasPrefix(name, "classes") &&
			strings.HasSuffix(name, ".dex") &&
			len(name) <= 14 {
			return true
		}
	}
	return false
}

// ═══════════════════════════════════════════════════════════════════════════════
// DIRECTORY FILTERING — расширенный список для APK
// ═══════════════════════════════════════════════════════════════════════════════

// skipDirs — директории, которые пропускаем при сканировании APK.
// Это служебные/мусорные папки, которые не содержат полезного кода.
var skipDirs = map[string]bool{
	// APKTool служебные
	"original":    true,
	"build":       true,
	"unknown":     true,
	"apktool.yml": true,
	// Analyzer-generated meta (legacy name kept for compatibility)
	"apktool.json":      true,
	"omnisec-meta.json": true,

	// Стандартные мусорные
	"__MACOSX":     true,
	"node_modules": true,
	".git":         true,
	".svn":         true,
	".hg":          true,
	".idea":        true,
	".gradle":      true,
	".vscode":      true,

	// Android специфичные (обычно не содержат анализируемого кода)
	"kotlin":   true, // kotlin stdlib метаданные
	"META-INF": true, // подписи, сертификаты
}

func shouldSkipDir(name string) bool {
	// Скрытые директории (начинаются с точки)
	if len(name) > 0 && name[0] == '.' {
		return true
	}
	return skipDirs[name]
}

// ═══════════════════════════════════════════════════════════════════════════════
// MATCH CONSTRUCTORS
// ═══════════════════════════════════════════════════════════════════════════════

// newMatch создаёт Match со скором из приоритета категории
func newMatch(
	category types.Category,
	file string,
	line int,
	context, matchedValue string,
	isCritical bool,
) types.Match {
	info := types.GetCategoryInfo(category)
	return types.Match{
		SourceLocation: types.SourceLocation{File: file, Line: line},
		Categorized:    types.Categorized{Category: category},
		Scored:         types.Scored{Score: float64(info.Priority)},
		Pattern:        matchedValue,
		Text:           matchedValue,
		Context:        context,
		IsCritical:     isCritical,
	}
}

// newMatchWithScore создаёт Match с кастомным скором.
// Полезно для детекторов, которые вычисляют свой вес находки.
func newMatchWithScore(
	category types.Category,
	file string,
	line int,
	context, matchedValue string,
	score float64,
	isCritical bool,
) types.Match {
	return types.Match{
		SourceLocation: types.SourceLocation{File: file, Line: line},
		Categorized:    types.Categorized{Category: category},
		Scored:         types.Scored{Score: score},
		Pattern:        matchedValue,
		Text:           matchedValue,
		Context:        context,
		IsCritical:     isCritical,
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// BYTE HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

// hasAnyDigit проверяет, есть ли хоть одна цифра в байтах
func hasAnyDigit(b []byte) bool {
	for i := 0; i < len(b); i++ {
		if b[i] >= '0' && b[i] <= '9' {
			return true
		}
	}
	return false
}

// hasAnyUpper проверяет, есть ли хоть одна заглавная буква
func hasAnyUpper(b []byte) bool {
	for i := 0; i < len(b); i++ {
		if b[i] >= 'A' && b[i] <= 'Z' {
			return true
		}
	}
	return false
}

// countChar считает количество вхождений байта
func countChar(b []byte, c byte) int {
	count := 0
	for i := 0; i < len(b); i++ {
		if b[i] == c {
			count++
		}
	}
	return count
}

// ═══════════════════════════════════════════════════════════════════════════════
// STRING SET — для быстрых проверок "содержит ли набор строку"
// ═══════════════════════════════════════════════════════════════════════════════
//
// Раньше: contains(slice, s) — O(N) линейный поиск по слайсу
// Теперь: stringSet.Has(s)   — O(1) lookup по map
//
// Для набора из 100 строк:
//   contains: 100 сравнений в худшем случае
//   Has:      1 lookup

type stringSet map[string]struct{}

// newStringSet создаёт множество строк из слайса
func newStringSet(items ...string) stringSet {
	s := make(stringSet, len(items))
	for _, item := range items {
		s[item] = struct{}{}
	}
	return s
}

// Has проверяет наличие строки в множестве — O(1)
func (s stringSet) Has(item string) bool {
	_, ok := s[item]
	return ok
}

// Add добавляет строку в множество
func (s stringSet) Add(item string) {
	s[item] = struct{}{}
}

// ═══════════════════════════════════════════════════════════════════════════════
// UTILITY FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

// djb2Hash — быстрый некриптографический хеш для распределения задач
func djb2Hash(s string) uint64 {
	var h uint64 = 5381
	for i := 0; i < len(s); i++ {
		h = ((h << 5) + h) + uint64(s[i])
	}
	return h
}

// extractAttribute извлекает значение атрибута из XML-подобного контента.
// Пример: extractAttribute(content, `package="`, '"') → "com.example.app"
func extractAttribute(content []byte, prefix string, delim byte) string {
	idx := bytes.Index(content, []byte(prefix))
	if idx == -1 {
		return ""
	}
	start := idx + len(prefix)
	if start >= len(content) {
		return ""
	}
	end := bytes.IndexByte(content[start:], delim)
	if end == -1 {
		return ""
	}

	value := content[start : start+end]

	// Защита от мусорных значений
	if len(value) == 0 || len(value) > 256 {
		return ""
	}

	return string(value)
}

// contains — линейный поиск строки в слайсе. O(N).
// Для частых проверок используй stringSet.Has() — O(1).
func contains(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

// ═══════════════════════════════════════════════════════════════════════════════
// PIRACY RISK CONVERSION
// ═══════════════════════════════════════════════════════════════════════════════

// piracyRiskLevels — предвычисленная карта вместо switch
var piracyRiskLevels = map[string]types.RiskLevel{
	"critical": types.RiskCritical,
	"high":     types.RiskHigh,
	"medium":   types.RiskMedium,
	"low":      types.RiskLow,
	"info":     types.RiskNone,
	"none":     types.RiskNone,
}

func piracyRiskLevel(level string) types.RiskLevel {
	if rl, ok := piracyRiskLevels[strings.ToLower(level)]; ok {
		return rl
	}
	return types.RiskNone
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXPORT PIRACY CONFIG HELPER
// ═══════════════════════════════════════════════════════════════════════════════

func ExportDefaultPiracyConfig(path string) error {
	return os.WriteFile(path, []byte("{}"), 0644)
}

// ═══════════════════════════════════════════════════════════════════════════════
// NUMERIC HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

// clampInt ограничивает значение в диапазон [minVal, maxVal].
// Единственная версия clamp — без дубликатов!
func clampInt(val, minVal, maxVal int) int {
	if val < minVal {
		return minVal
	}
	if val > maxVal {
		return maxVal
	}
	return val
}

// minInt возвращает минимум из двух чисел
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// maxInt возвращает максимум из двух чисел
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// min3 возвращает минимум из трёх чисел
func min3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}
