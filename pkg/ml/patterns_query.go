package ml

// ═══════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

// GetPatternsByCategory возвращает паттерны для конкретной категории
func GetPatternsByCategory(cat PatchCategory) []VulnerablePattern {
	var result []VulnerablePattern
	for _, p := range VulnerablePatterns {
		if p.Category == cat {
			result = append(result, p)
		}
	}
	return result
}

// GetCategoryInfo возвращает описание категории
func GetCategoryInfo(cat PatchCategory) (CategoryInfo, bool) {
	info, ok := AllCategories[cat]
	return info, ok
}

// GetPatchTemplate возвращает шаблон патча
func GetPatchTemplate(pt PatchType) (PatchTemplate, bool) {
	tmpl, ok := PatchTemplates[pt]
	return tmpl, ok
}

// IsLibraryPath проверяет, является ли путь библиотечным
func IsLibraryPath(path string) bool {
	for _, prefix := range LibraryExcludePaths {
		if len(path) >= len(prefix) {
			// Case-insensitive prefix check
			match := true
			for i := 0; i < len(prefix); i++ {
				a := path[i]
				b := prefix[i]
				// toLower ASCII
				if a >= 'A' && a <= 'Z' {
					a += 32
				}
				if b >= 'A' && b <= 'Z' {
					b += 32
				}
				// Normalize path separator
				if a == '\\' {
					a = '/'
				}
				if a != b {
					match = false
					break
				}
			}
			if match {
				return true
			}
		}
	}
	return false
}

// CountPatterns возвращает общее количество паттернов
func CountPatterns() int {
	return len(VulnerablePatterns)
}

// CountCategories возвращает количество уникальных категорий
func CountCategories() int {
	return len(AllCategories)
}
