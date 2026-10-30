package ml

import (
	"sort"
	"strings"
	"sync"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PATTERN INDEX — O(1) lookup для vulnerable patterns
// ═══════════════════════════════════════════════════════════════════════════════
//
// Task 4.2: Indexed lookup structures for vulnerable patterns
//
// Вместо линейного поиска по всем VulnerablePatterns (O(N)):
//   for _, vp := range VulnerablePatterns { ... }
//
// Используем индексы для O(1) lookup:
//   patterns := index.ByMethodName["islicensed"]
//   patterns := index.ByClass["license"]
//
// Ускорение: O(N) → O(1) для большинства случаев

// PatternIndex — индексированные vulnerable patterns для быстрого поиска
type PatternIndex struct {
	// Индекс по именам методов (lowercase)
	ByMethodName map[string][]*VulnerablePattern

	// Индекс по классам/путям (lowercase)
	ByClass map[string][]*VulnerablePattern

	// Индекс по required calls (lowercase)
	ByRequiredCall map[string][]*VulnerablePattern

	// Индекс по string patterns (lowercase)
	ByStringPattern map[string][]*VulnerablePattern

	// Индекс по return type
	ByReturnType map[string][]*VulnerablePattern

	// Индекс по категории
	ByCategory map[string][]*VulnerablePattern

	// Все паттерны (для fallback)
	AllPatterns []*VulnerablePattern

	// Для thread-safety при ленивой инициализации
	once sync.Once
}

var globalPatternIndexOnce sync.Once
var globalPatternIndex *PatternIndex

// GetPatternIndex возвращает глобальный индекс паттернов (ленивая инициализация)
func GetPatternIndex() *PatternIndex {
	globalPatternIndexOnce.Do(func() {
		globalPatternIndex = BuildPatternIndex()
	})
	return globalPatternIndex
}

// BuildPatternIndex строит индексы для всех VulnerablePatterns (включая SDK patterns)
func BuildPatternIndex() *PatternIndex {
	// Get all patterns including SDK-specific patterns
	allPatterns := GetAllPatterns()

	idx := &PatternIndex{
		ByMethodName:    make(map[string][]*VulnerablePattern, 256),
		ByClass:         make(map[string][]*VulnerablePattern, 128),
		ByRequiredCall:  make(map[string][]*VulnerablePattern, 512),
		ByStringPattern: make(map[string][]*VulnerablePattern, 256),
		ByReturnType:    make(map[string][]*VulnerablePattern, 8),
		ByCategory:      make(map[string][]*VulnerablePattern, 16),
		AllPatterns:     make([]*VulnerablePattern, 0, len(allPatterns)),
	}

	for i := range allPatterns {
		vp := &allPatterns[i]
		idx.AllPatterns = append(idx.AllPatterns, vp)

		// Индекс по именам методов
		for _, name := range vp.MethodNames {
			nameLower := strings.ToLower(name)
			idx.ByMethodName[nameLower] = append(idx.ByMethodName[nameLower], vp)
		}

		// Индекс по классам
		for _, class := range vp.ClassPatterns {
			classLower := strings.ToLower(class)
			idx.ByClass[classLower] = append(idx.ByClass[classLower], vp)
		}

		// Индекс по required calls
		for _, call := range vp.RequiredCalls {
			callLower := strings.ToLower(call)
			idx.ByRequiredCall[callLower] = append(idx.ByRequiredCall[callLower], vp)
		}

		// Индекс по string patterns
		for _, str := range vp.StringPatterns {
			strLower := strings.ToLower(str)
			idx.ByStringPattern[strLower] = append(idx.ByStringPattern[strLower], vp)
		}

		// Индекс по return type
		if vp.ReturnType != "" {
			idx.ByReturnType[vp.ReturnType] = append(idx.ByReturnType[vp.ReturnType], vp)
		}

		// Индекс по категории
		idx.ByCategory[string(vp.Category)] = append(idx.ByCategory[string(vp.Category)], vp)
	}

	return idx
}

// ═══════════════════════════════════════════════════════════════════════════════
// FAST LOOKUP — быстрый поиск кандидатов
// ═══════════════════════════════════════════════════════════════════════════════

// FindCandidates возвращает список паттернов-кандидатов для метода
// Использует индексы для O(1) lookup вместо O(N) линейного поиска
func (idx *PatternIndex) FindCandidates(mi *MethodInfo) []*VulnerablePattern {
	if idx == nil || mi == nil {
		return nil
	}
	candidates := make(map[*VulnerablePattern]bool, 16)

	// 1. Поиск по имени метода (самый точный)
	if patterns, ok := idx.ByMethodName[mi.NameLower]; ok {
		for _, vp := range patterns {
			candidates[vp] = true
		}
	}

	// 2. Поиск по частичному совпадению имени (для подстрок)
	for key, patterns := range idx.ByMethodName {
		if strings.Contains(mi.NameLower, key) {
			for _, vp := range patterns {
				candidates[vp] = true
			}
		}
	}

	// 3. Поиск по классу
	classLower := strings.ToLower(mi.ClassName)
	for key, patterns := range idx.ByClass {
		if strings.Contains(classLower, key) {
			for _, vp := range patterns {
				candidates[vp] = true
			}
		}
	}

	// 4. Поиск по вызовам
	for _, call := range mi.Calls {
		fullCall := strings.ToLower(call.FullCall)
		methodName := strings.ToLower(call.Method)
		if patterns, ok := idx.ByRequiredCall[fullCall]; ok {
			for _, vp := range patterns {
				candidates[vp] = true
			}
		}
		if patterns, ok := idx.ByRequiredCall[methodName]; ok {
			for _, vp := range patterns {
				candidates[vp] = true
			}
		}
		// RequiredCalls in the embedded knowledge base are intentionally short
		// fragments (for example "checklicense"), while FullCall contains the
		// declaring class and descriptor. Exact lookup alone misses obfuscated
		// methods whose only useful evidence is the invoked API.
		for required, patterns := range idx.ByRequiredCall {
			if !strings.Contains(fullCall, required) {
				continue
			}
			for _, vp := range patterns {
				candidates[vp] = true
			}
		}
	}

	// 5. Поиск по строковым константам
	for _, str := range mi.StringConsts {
		strLower := strings.ToLower(str)
		for key, patterns := range idx.ByStringPattern {
			if strings.Contains(strLower, key) {
				for _, vp := range patterns {
					candidates[vp] = true
				}
			}
		}
	}

	// 6. Фильтр по return type (если указан)
	result := make([]*VulnerablePattern, 0, len(candidates))
	for vp := range candidates {
		// Если паттерн требует конкретный return type, проверяем
		if !patternReturnCompatible(vp, mi.ReturnType) {
			continue
		}
		result = append(result, vp)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].ID < result[j].ID
	})

	return result
}

// FindByReturnType возвращает паттерны с указанным return type
func (idx *PatternIndex) FindByReturnType(returnType string) []*VulnerablePattern {
	if patterns, ok := idx.ByReturnType[returnType]; ok {
		return patterns
	}
	return nil
}

// FindByCategory возвращает паттерны указанной категории
func (idx *PatternIndex) FindByCategory(category string) []*VulnerablePattern {
	if patterns, ok := idx.ByCategory[category]; ok {
		return patterns
	}
	return nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// STATISTICS
// ═══════════════════════════════════════════════════════════════════════════════

// Stats возвращает статистику индекса
type IndexStats struct {
	TotalPatterns        int
	MethodNameEntries    int
	ClassEntries         int
	RequiredCallEntries  int
	StringPatternEntries int
	ReturnTypeEntries    int
	CategoryEntries      int
}

func (idx *PatternIndex) Stats() IndexStats {
	return IndexStats{
		TotalPatterns:        len(idx.AllPatterns),
		MethodNameEntries:    len(idx.ByMethodName),
		ClassEntries:         len(idx.ByClass),
		RequiredCallEntries:  len(idx.ByRequiredCall),
		StringPatternEntries: len(idx.ByStringPattern),
		ReturnTypeEntries:    len(idx.ByReturnType),
		CategoryEntries:      len(idx.ByCategory),
	}
}
