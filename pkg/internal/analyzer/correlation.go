// Package analyzer — correlation.go v5.0
// Multi-strategy correlation engine with package clustering,
// cross-file reference tracking, protection chain detection,
// and normalized scoring.
package analyzer

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"mega-analyzer/pkg/internal/types"
)

// ═══════════════════════════════════════════════════════════════════════════════
// CORRELATION FINDER — находит связи между файлами
//
// Стратегии:
//   1. Category correlation — файлы с одинаковыми категориями
//   2. Name correlation — файлы с похожими именами (по keyword индексу)
//   3. Package clustering — пакеты с высокой плотностью находок
//   4. Cross-reference — файлы ссылающиеся друг на друга
//   5. Protection chains — связанные защитные механизмы
//   6. Multi-category — файлы встречающиеся в нескольких категориях
// ═══════════════════════════════════════════════════════════════════════════════

// CorrelationFinder находит корреляции между файлами.
type CorrelationFinder struct {
	files map[string]*types.FileAnalysis

	// ── Precomputed indices ──
	appCodePaths   []string            // sorted app code paths
	pathsLower     map[string]string   // path → lowercase
	pathTokenIndex map[string][]string // keyword → paths

	// ── Structural indices ──
	packageIndex map[string][]string               // package → paths
	classToFile  map[string]string                 // ClassName → file path
	fileCats     map[string]map[types.Category]int // path → category → count

	// ── Config ──
	maxCorrelations int
	maxFilesPerCorr int
}

// correlationKeywords — ключевые слова для индексации
var correlationKeywords = []string{
	"license", "premium", "pro", "billing", "purchase",
	"subscription", "trial", "checker", "validator",
	"verify", "security", "integrity", "signature",
	"crack", "piracy", "tamper", "unlock", "activate",
	"payment", "receipt", "entitlement", "sku",
}

// NewCorrelationFinder создаёт finder с полным предвычислением.
func NewCorrelationFinder(files map[string]*types.FileAnalysis) *CorrelationFinder {
	cf := &CorrelationFinder{
		files:           files,
		appCodePaths:    make([]string, 0, len(files)/2),
		pathsLower:      make(map[string]string, len(files)),
		pathTokenIndex:  make(map[string][]string, len(correlationKeywords)),
		packageIndex:    make(map[string][]string, 64),
		classToFile:     make(map[string]string, len(files)),
		fileCats:        make(map[string]map[types.Category]int, len(files)/2),
		maxCorrelations: 150,
		maxFilesPerCorr: 15,
	}

	cf.buildIndices()
	return cf
}

// buildIndices предвычисляет все индексы за один проход.
func (cf *CorrelationFinder) buildIndices() {
	for path, analysis := range cf.files {
		if !analysis.IsAppCode {
			continue
		}

		cf.appCodePaths = append(cf.appCodePaths, path)

		pathLower := strings.ToLower(path)
		cf.pathsLower[path] = pathLower

		// ── Keyword index ──
		for _, kw := range correlationKeywords {
			if strings.Contains(pathLower, kw) {
				cf.pathTokenIndex[kw] = append(cf.pathTokenIndex[kw], path)
			}
		}

		// ── Package index ──
		pkg := extractPackage(path)
		if pkg != "" {
			cf.packageIndex[pkg] = append(cf.packageIndex[pkg], path)
		}

		// ── Class-to-file map ──
		className := extractClassName(path)
		if className != "" {
			cf.classToFile[className] = path
		}

		// ── Per-file category counts ──
		if len(analysis.Matches) > 0 {
			cats := make(map[types.Category]int, 4)
			for _, m := range analysis.Matches {
				cats[m.Category]++
			}
			cf.fileCats[path] = cats
		}
	}

	// Стабильный порядок
	sort.Strings(cf.appCodePaths)
}

// FindAll находит все корреляции всеми стратегиями.
func (cf *CorrelationFinder) FindAll() []types.Correlation {
	// Собираем из всех стратегий
	var all []types.Correlation

	all = append(all, cf.findCategoryCorrelations()...)
	all = append(all, cf.findSimilarNames()...)
	all = append(all, cf.findPackageClusters()...)
	all = append(all, cf.findCrossReferences()...)
	all = append(all, cf.findProtectionChains()...)
	all = append(all, cf.findMultiCategoryFiles()...)
	all = append(all, cf.findObfuscationClusters()...)

	// Дедупликация по file-set fingerprint
	all = cf.deduplicateCorrelations(all)

	// Нормализация и сортировка
	cf.normalizeScores(all)

	sort.Slice(all, func(i, j int) bool {
		return all[i].Score > all[j].Score
	})

	if len(all) > cf.maxCorrelations {
		all = all[:cf.maxCorrelations]
	}

	return all
}

// ═══════════════════════════════════════════════════════════════════════════════
// STRATEGY 1: Category correlations — файлы связанные через категории
// ═══════════════════════════════════════════════════════════════════════════════

func (cf *CorrelationFinder) findCategoryCorrelations() []types.Correlation {
	byCategory := make(map[types.Category]map[string]struct{}, 32)

	for path, cats := range cf.fileCats {
		for cat := range cats {
			if byCategory[cat] == nil {
				byCategory[cat] = make(map[string]struct{}, 8)
			}
			byCategory[cat][path] = struct{}{}
		}
	}

	correlations := make([]types.Correlation, 0, len(byCategory))

	for category, pathSet := range byCategory {
		if len(pathSet) < 2 {
			continue
		}

		files := setToSortedSlice(pathSet, cf.maxFilesPerCorr)
		info := types.GetCategoryInfo(category)

		corrType := types.CorrelationSimilarPattern
		if info.IsCritical {
			corrType = types.CorrelationCallChain
		}

		// Scoring: file_count × priority × diversity_bonus
		score := float64(len(pathSet)) * float64(info.Priority)

		// Бонус если файлы из разных пакетов (распределённая защита)
		pkgSet := make(map[string]struct{})
		for _, f := range files {
			pkgSet[extractPackage(f)] = struct{}{}
		}
		if len(pkgSet) > 1 {
			score *= 1.0 + float64(len(pkgSet))*0.1
		}

		correlations = append(correlations, types.Correlation{
			Type:        corrType,
			Category:    category,
			Files:       files,
			Description: fmt.Sprintf("%d files linked via %s (priority %d)", len(pathSet), category.String(), info.Priority),
			Score:       score,
		})
	}

	return correlations
}

// ═══════════════════════════════════════════════════════════════════════════════
// STRATEGY 2: Similar names — файлы с общими ключевыми словами
// ═══════════════════════════════════════════════════════════════════════════════

func (cf *CorrelationFinder) findSimilarNames() []types.Correlation {
	// Ключевые слова с весами (для скоринга)
	type kwInfo struct {
		display string
		weight  float64
	}

	keywordsWithWeights := []kwInfo{
		{"License", 3.0}, {"Premium", 2.5}, {"Pro", 1.5},
		{"Billing", 3.0}, {"Purchase", 2.5}, {"Subscription", 2.5},
		{"Trial", 2.0}, {"Checker", 2.0}, {"Validator", 2.0},
		{"Verify", 2.0}, {"Security", 2.0}, {"Integrity", 2.5},
		{"Signature", 2.5}, {"Crack", 3.0}, {"Piracy", 3.0},
		{"Tamper", 3.0}, {"Unlock", 2.0}, {"Activate", 1.5},
		{"Payment", 2.5}, {"Receipt", 2.0}, {"Entitlement", 2.5},
	}

	correlations := make([]types.Correlation, 0, 16)
	seen := make(map[string]bool)

	for _, kwi := range keywordsWithWeights {
		keyLower := strings.ToLower(kwi.display)
		if seen[keyLower] {
			continue
		}
		seen[keyLower] = true

		files := cf.pathTokenIndex[keyLower]
		if len(files) < 2 {
			continue
		}

		filesCopy := make([]string, len(files))
		copy(filesCopy, files)
		sort.Strings(filesCopy)

		limit := cf.maxFilesPerCorr
		if len(filesCopy) < limit {
			limit = len(filesCopy)
		}

		correlations = append(correlations, types.Correlation{
			Type:        types.CorrelationSimilarPattern,
			Files:       filesCopy[:limit],
			Description: fmt.Sprintf("%d files contain '%s' in path", len(files), kwi.display),
			Score:       float64(len(files)) * kwi.weight,
		})
	}

	return correlations
}

// ═══════════════════════════════════════════════════════════════════════════════
// STRATEGY 3: Package clusters — пакеты с высокой плотностью подозрений
// ═══════════════════════════════════════════════════════════════════════════════

func (cf *CorrelationFinder) findPackageClusters() []types.Correlation {
	type packageStats struct {
		files         []string
		totalMatches  int
		criticalCount int
		categorySet   map[types.Category]struct{}
		maxPriority   int
	}

	stats := make(map[string]*packageStats, len(cf.packageIndex))

	for pkg, paths := range cf.packageIndex {
		ps := &packageStats{
			files:       paths,
			categorySet: make(map[types.Category]struct{}, 8),
		}

		for _, path := range paths {
			cats, ok := cf.fileCats[path]
			if !ok {
				continue
			}
			for cat, count := range cats {
				ps.totalMatches += count
				ps.categorySet[cat] = struct{}{}
				info := types.GetCategoryInfo(cat)
				if info.IsCritical {
					ps.criticalCount += count
				}
				if info.Priority > ps.maxPriority {
					ps.maxPriority = info.Priority
				}
			}
		}

		// Интересные пакеты: >= 2 файла с находками И >= 2 разных категории
		suspiciousFiles := 0
		for _, p := range paths {
			if _, ok := cf.fileCats[p]; ok {
				suspiciousFiles++
			}
		}

		if suspiciousFiles >= 2 && len(ps.categorySet) >= 2 {
			stats[pkg] = ps
		}
	}

	correlations := make([]types.Correlation, 0, len(stats))

	for pkg, ps := range stats {
		files := make([]string, len(ps.files))
		copy(files, ps.files)
		sort.Strings(files)

		if len(files) > cf.maxFilesPerCorr {
			files = files[:cf.maxFilesPerCorr]
		}

		// Score: matches × category_diversity × priority_boost
		score := float64(ps.totalMatches) * float64(len(ps.categorySet))
		if ps.criticalCount > 0 {
			score *= 1.5
		}
		score *= 1.0 + float64(ps.maxPriority)*0.1

		correlations = append(correlations, types.Correlation{
			Type:  types.CorrelationSamePackage,
			Files: files,
			Description: fmt.Sprintf("Package '%s': %d files, %d matches across %d categories",
				pkg, len(ps.files), ps.totalMatches, len(ps.categorySet)),
			Score: score,
		})
	}

	return correlations
}

// ═══════════════════════════════════════════════════════════════════════════════
// STRATEGY 4: Cross-references — файлы ссылающиеся на другие файлы
// ═══════════════════════════════════════════════════════════════════════════════

func (cf *CorrelationFinder) findCrossReferences() []types.Correlation {
	if len(cf.classToFile) == 0 {
		return nil
	}

	// Для каждого файла с находками проверяем, ссылается ли он на другие файлы
	type refPair struct {
		from string
		to   string
	}

	refs := make(map[refPair]int) // pair → count

	for path, analysis := range cf.files {
		if !analysis.IsAppCode || len(analysis.Matches) == 0 {
			continue
		}

		for _, m := range analysis.Matches {
			// Ищем ссылки на классы в тексте матча
			text := m.Text
			if text == "" {
				text = m.Pattern
			}

			for className, targetPath := range cf.classToFile {
				if targetPath == path {
					continue
				}
				// Проверяем наличие имени класса в контексте матча
				if strings.Contains(text, className) {
					pair := refPair{from: path, to: targetPath}
					refs[pair]++
				}
			}
		}
	}

	if len(refs) == 0 {
		return nil
	}

	// Группируем по source файлу
	bySource := make(map[string]map[string]int) // from → to → count
	for pair, count := range refs {
		if bySource[pair.from] == nil {
			bySource[pair.from] = make(map[string]int)
		}
		bySource[pair.from][pair.to] += count
	}

	correlations := make([]types.Correlation, 0, len(bySource))

	for source, targets := range bySource {
		if len(targets) == 0 {
			continue
		}

		files := []string{source}
		totalRefs := 0
		for target, count := range targets {
			files = append(files, target)
			totalRefs += count
		}
		sort.Strings(files)

		if len(files) > cf.maxFilesPerCorr {
			files = files[:cf.maxFilesPerCorr]
		}

		correlations = append(correlations, types.Correlation{
			Type:  types.CorrelationCallChain,
			Files: files,
			Description: fmt.Sprintf("%s references %d other suspicious files (%d refs)",
				filepath.Base(source), len(targets), totalRefs),
			Score: float64(totalRefs) * float64(len(targets)) * 2.0,
		})
	}

	return correlations
}

// ═══════════════════════════════════════════════════════════════════════════════
// STRATEGY 5: Protection chains — связанные защитные механизмы
// ═══════════════════════════════════════════════════════════════════════════════

func (cf *CorrelationFinder) findProtectionChains() []types.Correlation {
	// Определяем "anchor" категории — точки входа защиты
	anchorGroups := map[string]float64{
		types.GroupLicense:  3.0,
		types.GroupBilling:  2.5,
		types.GroupSecurity: 2.0,
	}

	// Для каждого пакета с anchor-файлами ищем chain
	type chain struct {
		anchor string
		group  string
		files  []string
		catSet map[types.Category]struct{}
		score  float64
	}

	var chains []chain

	for pkg, paths := range cf.packageIndex {
		_ = pkg

		// Ищем anchor файлы
		for _, path := range paths {
			cats, ok := cf.fileCats[path]
			if !ok {
				continue
			}

			for cat := range cats {
				info := types.GetCategoryInfo(cat)
				anchorWeight, isAnchor := anchorGroups[info.Group]
				if !isAnchor {
					continue
				}

				// Нашли anchor — собираем chain из того же пакета
				ch := chain{
					anchor: path,
					group:  info.Group,
					files:  make([]string, 0, len(paths)),
					catSet: make(map[types.Category]struct{}, 8),
				}

				for _, p := range paths {
					if pCats, ok := cf.fileCats[p]; ok {
						ch.files = append(ch.files, p)
						for c := range pCats {
							ch.catSet[c] = struct{}{}
						}
					}
				}

				if len(ch.files) >= 2 && len(ch.catSet) >= 2 {
					ch.score = float64(len(ch.files)) * float64(len(ch.catSet)) * anchorWeight
					chains = append(chains, ch)
				}

				break // один anchor per file
			}
		}
	}

	// Дедуплицируем chains по anchor group+package
	seen := make(map[string]bool)
	correlations := make([]types.Correlation, 0, len(chains))

	for _, ch := range chains {
		key := ch.group + "|" + extractPackage(ch.anchor)
		if seen[key] {
			continue
		}
		seen[key] = true

		files := make([]string, len(ch.files))
		copy(files, ch.files)
		sort.Strings(files)

		if len(files) > cf.maxFilesPerCorr {
			files = files[:cf.maxFilesPerCorr]
		}

		correlations = append(correlations, types.Correlation{
			Type:  types.CorrelationCallChain,
			Files: files,
			Description: fmt.Sprintf("Protection chain (%s): %d files, %d categories, anchored by %s",
				ch.group, len(ch.files), len(ch.catSet), filepath.Base(ch.anchor)),
			Score: ch.score,
		})
	}

	return correlations
}

// ═══════════════════════════════════════════════════════════════════════════════
// STRATEGY 6: Multi-category files — файлы в нескольких категориях
// ═══════════════════════════════════════════════════════════════════════════════

func (cf *CorrelationFinder) findMultiCategoryFiles() []types.Correlation {
	// Файлы которые затрагивают >= 3 разных категории = hub/orchestrator
	var hubs []string
	hubCats := make(map[string]map[types.Category]int)

	for path, cats := range cf.fileCats {
		if len(cats) >= 3 {
			hubs = append(hubs, path)
			hubCats[path] = cats
		}
	}

	if len(hubs) < 1 {
		return nil
	}

	sort.Strings(hubs)

	correlations := make([]types.Correlation, 0, len(hubs))

	for _, hub := range hubs {
		cats := hubCats[hub]

		// Находим все файлы которые разделяют хотя бы одну категорию с hub
		related := make(map[string]int) // path → shared categories
		for cat := range cats {
			for path := range cf.fileCats {
				if path == hub {
					continue
				}
				if _, ok := cf.fileCats[path][cat]; ok {
					related[path]++
				}
			}
		}

		// Берём только те что разделяют >= 2 категории
		files := []string{hub}
		for path, shared := range related {
			if shared >= 2 {
				files = append(files, path)
			}
		}

		if len(files) < 2 {
			continue
		}

		sort.Strings(files)
		if len(files) > cf.maxFilesPerCorr {
			files = files[:cf.maxFilesPerCorr]
		}

		// Score: categories × related_files × max_priority
		maxPri := 0
		for cat := range cats {
			if pri := types.GetCategoryInfo(cat).Priority; pri > maxPri {
				maxPri = pri
			}
		}

		correlations = append(correlations, types.Correlation{
			Type:  types.CorrelationCallChain,
			Files: files,
			Description: fmt.Sprintf("Hub file %s: %d categories, %d related files",
				filepath.Base(hub), len(cats), len(files)-1),
			Score: float64(len(cats)) * float64(len(files)) * float64(maxPri) * 0.5,
		})
	}

	return correlations
}

// ═══════════════════════════════════════════════════════════════════════════════
// STRATEGY 7: Obfuscation clusters — группировка по плотности обфускации
// ═══════════════════════════════════════════════════════════════════════════════

func (cf *CorrelationFinder) findObfuscationClusters() []types.Correlation {
	var obfuscatedFiles []string
	for path, fa := range cf.files {
		if fa.IsAppCode && fa.ObfuscationDensity > 0.40 {
			obfuscatedFiles = append(obfuscatedFiles, path)
		}
	}

	if len(obfuscatedFiles) < 2 {
		return nil
	}

	// Группируем по пакету (или top-level подкаталогу)
	byTopPackage := make(map[string][]string)
	for _, path := range obfuscatedFiles {
		pkg := extractPackage(path)
		parts := strings.Split(pkg, "/")
		topPkg := pkg
		if len(parts) > 1 {
			topPkg = parts[0] + "/" + parts[1]
		}
		byTopPackage[topPkg] = append(byTopPackage[topPkg], path)
	}

	var correlations []types.Correlation
	for topPkg, paths := range byTopPackage {
		if len(paths) < 2 {
			continue
		}

		files := make([]string, len(paths))
		copy(files, paths)
		sort.Strings(files)

		if len(files) > cf.maxFilesPerCorr {
			files = files[:cf.maxFilesPerCorr]
		}

		correlations = append(correlations, types.Correlation{
			Type:        types.CorrelationSimilarPattern,
			Files:       files,
			Description: fmt.Sprintf("Obfuscation Cluster in '%s': %d files with high short-name density (similar obfuscation)", topPkg, len(paths)),
			Score:       float64(len(paths)) * 12.0,
		})
	}

	return correlations
}

// ═══════════════════════════════════════════════════════════════════════════════
// DEDUPLICATION & NORMALIZATION
// ═══════════════════════════════════════════════════════════════════════════════

func (cf *CorrelationFinder) deduplicateCorrelations(correlations []types.Correlation) []types.Correlation {
	seen := make(map[string]int) // fingerprint → index in result
	result := make([]types.Correlation, 0, len(correlations))

	for _, c := range correlations {
		fp := cf.fileSetFingerprint(c.Files)
		if idx, exists := seen[fp]; exists {
			// Merge: keep higher score
			if c.Score > result[idx].Score {
				result[idx].Score = c.Score
				result[idx].Description = c.Description
				result[idx].Type = c.Type
			}
		} else {
			seen[fp] = len(result)
			result = append(result, c)
		}
	}

	return result
}

func (cf *CorrelationFinder) fileSetFingerprint(files []string) string {
	sorted := make([]string, len(files))
	copy(sorted, files)
	sort.Strings(sorted)
	return strings.Join(sorted, "|")
}

func (cf *CorrelationFinder) normalizeScores(correlations []types.Correlation) {
	if len(correlations) == 0 {
		return
	}

	maxScore := 0.0
	for _, c := range correlations {
		if c.Score > maxScore {
			maxScore = c.Score
		}
	}

	if maxScore <= 0 {
		return
	}

	// Normalize to 0-100 range
	for i := range correlations {
		correlations[i].Score = (correlations[i].Score / maxScore) * 100
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

// extractPackage получает пакет из пути smali файла.
// "smali/com/example/app/MyClass.smali" → "com/example/app"
// "smali_classes2/com/foo/Bar.smali" → "com/foo"
func extractPackage(path string) string {
	// Normalize separators
	normalized := strings.ReplaceAll(path, "\\", "/")

	dir := filepath.Dir(normalized)
	dir = strings.ReplaceAll(dir, "\\", "/")

	// Strip smali prefixes
	for _, prefix := range []string{
		"smali_classes9/", "smali_classes8/", "smali_classes7/",
		"smali_classes6/", "smali_classes5/", "smali_classes4/",
		"smali_classes3/", "smali_classes2/", "smali/",
	} {
		if idx := strings.Index(dir, prefix); idx >= 0 {
			dir = dir[idx+len(prefix):]
			break
		}
	}

	return dir
}

// extractClassName получает имя класса из пути.
// "smali/com/example/MyClass.smali" → "MyClass"
func extractClassName(path string) string {
	base := filepath.Base(path)
	if strings.HasSuffix(base, ".smali") {
		return strings.TrimSuffix(base, ".smali")
	}
	return ""
}

// setToSortedSlice конвертирует set в отсортированный slice с лимитом.
func setToSortedSlice(set map[string]struct{}, maxLen int) []string {
	result := make([]string, 0, len(set))
	for k := range set {
		result = append(result, k)
	}
	sort.Strings(result)
	if len(result) > maxLen {
		result = result[:maxLen]
	}
	return result
}
