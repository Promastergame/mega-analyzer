package ml

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// AdvancedPatcherPattern представляет продвинутый паттерн для обхода защит
type AdvancedPatcherPattern struct {
	ID              string                 `json:"id"`
	Name            string                 `json:"name"`
	Description     string                 `json:"description"`
	Category        string                 `json:"category"` // obfuscation, virtualization, protector, crypto, anti-cheat
	Severity        string                 `json:"severity"` // critical, high, medium, low
	Confidence      float64                `json:"confidence"`
	Patterns        []string               `json:"patterns"` // Regex patterns for detection
	ContextAnalysis ContextAnalysisConfig  `json:"context_analysis"`
	PatchStrategies []PatchStrategyConfig  `json:"patch_strategies"`
	SMTConstraints  []SMTConstraint        `json:"smt_constraints,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// ContextAnalysisConfig определяет параметры контекстного анализа
type ContextAnalysisConfig struct {
	AnalyzeDFG              bool     `json:"analyze_dfg"`              // Анализ потоков данных
	AnalyzeCFG              bool     `json:"analyze_cfg"`              // Анализ потоков управления
	CheckLibraryContext     bool     `json:"check_library_context"`    // Проверка контекста библиотеки
	MinimumConfidenceBoost  float64  `json:"minimum_confidence_boost"` // Минимальный буст уверенности
	ExcludedLibraryPrefixes []string `json:"excluded_library_prefixes"`
	RequiredCallStack       []string `json:"required_call_stack,omitempty"`
}

// PatchStrategy определяет стратегию применения патча
// PatchStrategyConfig определяет конфигурацию стратегии применения патча,
// используемую в описаниях паттернов (JSON-конфигурация). Название отличное
// от `PatchStrategy` (интерфейс) чтобы избежать дублирования типов.
type PatchStrategyConfig struct {
	Type              string   `json:"type"` // return_constant, nop_injection, condition_inversion, smt_solve
	ReturnValue       string   `json:"return_value,omitempty"`
	InstructionSet    []string `json:"instruction_set,omitempty"`
	ConditionModifier string   `json:"condition_modifier,omitempty"`
	Risk              string   `json:"risk"` // low, medium, high, critical
	Description       string   `json:"description"`
}

// SMTConstraint определяет ограничение для SMT-солвера
type SMTConstraint struct {
	Variable    string `json:"variable"`
	Operator    string `json:"operator"` // ==, !=, <, >, <=, >=
	Value       string `json:"value"`
	Description string `json:"description"`
}

// AdvancedPatcherEngine управляет продвинутыми паттернами для обхода защит
type AdvancedPatcherEngine struct {
	patterns      map[string]*AdvancedPatcherPattern
	compiledRegex map[string]*regexp.Regexp
	mu            sync.RWMutex
	smtSolver     SMTSolverInterface
	dfgAnalyzer   DFGAnalyzerInterface
	cfgAnalyzer   CFGAnalyzerInterface
}

// SMTSolverInterface определяет интерфейс для SMT-солвера
type SMTSolverInterface interface {
	Solve(constraints []SMTConstraint) (map[string]interface{}, error)
	VerifyConstraints(constraints []SMTConstraint, values map[string]interface{}) bool
}

// DFGAnalyzerInterface определяет интерфейс для анализа потоков данных
type DFGAnalyzerInterface interface {
	AnalyzeDataFlow(code string) (map[string][]string, error)
	TraceVariable(variable string, code string) ([]string, error)
}

// CFGAnalyzerInterface определяет интерфейс для анализа потоков управления
type CFGAnalyzerInterface interface {
	BuildCFG(code string) (interface{}, error)
	FindDominators(cfg interface{}) (map[string][]string, error)
	DetectLoops(cfg interface{}) ([]interface{}, error)
}

// NewAdvancedPatcherEngine создает новый экземпляр продвинутого движка патчинга
func NewAdvancedPatcherEngine(smtSolver SMTSolverInterface, dfgAnalyzer DFGAnalyzerInterface, cfgAnalyzer CFGAnalyzerInterface) *AdvancedPatcherEngine {
	return &AdvancedPatcherEngine{
		patterns:      make(map[string]*AdvancedPatcherPattern),
		compiledRegex: make(map[string]*regexp.Regexp),
		smtSolver:     smtSolver,
		dfgAnalyzer:   dfgAnalyzer,
		cfgAnalyzer:   cfgAnalyzer,
	}
}

// RegisterPattern регистрирует новый продвинутый паттерн
func (ape *AdvancedPatcherEngine) RegisterPattern(pattern *AdvancedPatcherPattern) error {
	if pattern == nil || pattern.ID == "" {
		return fmt.Errorf("invalid pattern: nil or empty ID")
	}

	ape.mu.Lock()
	defer ape.mu.Unlock()

	// Компилируем регулярные выражения
	for _, p := range pattern.Patterns {
		if _, err := regexp.Compile(p); err != nil {
			return fmt.Errorf("invalid regex pattern %q: %w", p, err)
		}
	}

	ape.patterns[pattern.ID] = pattern

	// Кэшируем скомпилированные регулярные выражения
	for i, p := range pattern.Patterns {
		regex, _ := regexp.Compile(p)
		ape.compiledRegex[fmt.Sprintf("%s_%d", pattern.ID, i)] = regex
	}

	return nil
}

// DetectVirtualizedCode обнаруживает виртуализированный код
func (ape *AdvancedPatcherEngine) DetectVirtualizedCode(code string) ([]PatternDetectionResult, error) {
	var results []PatternDetectionResult

	ape.mu.RLock()
	defer ape.mu.RUnlock()

	// Паттерны для обнаружения виртуализации
	virtualizationPatterns := []string{
		`dispatch_table|vm_handler|bytecode_interpreter`,
		`switch\s*\(\s*opcode\s*\)|case\s*0x[0-9a-fA-F]+:`,
		`stack_machine|register_machine|accumulator`,
		`instruction_fetch|instruction_decode|instruction_execute`,
	}

	for _, pattern := range virtualizationPatterns {
		regex, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}

		matches := regex.FindAllStringIndex(code, -1)
		for _, match := range matches {
			results = append(results, PatternDetectionResult{
				Type:       "virtualized_code",
				Pattern:    pattern,
				StartPos:   match[0],
				EndPos:     match[1],
				Confidence: 0.75,
				Suggestion: "Use SMT solver to analyze bytecode semantics",
			})
		}
	}

	return results, nil
}

// DetectProtectorSignatures обнаруживает сигнатуры протекторов
func (ape *AdvancedPatcherEngine) DetectProtectorSignatures(code string) ([]PatternDetectionResult, error) {
	var results []PatternDetectionResult

	ape.mu.RLock()
	defer ape.mu.RUnlock()

	// Известные сигнатуры протекторов
	protectorSignatures := map[string][]string{
		"dexguard": {
			`com\.ysoft\.dexguard`,
			`DexGuard|dexguard\.jar`,
			`anti_debug|anti_emulator|anti_tampering`,
		},
		"ijiami": {
			`com\.ijiami`,
			`ijm_|ijiami`,
			`encryption_key|obfuscation_table`,
		},
		"qihoo360": {
			`com\.qihoo\.magic`,
			`360safe|jiagu`,
			`anti_crack|license_check`,
		},
		"apkprotect": {
			`com\.apkprotect`,
			`APKProtect|apkprot`,
			`vm_execute|bytecode_run`,
		},
	}

	for protector, signatures := range protectorSignatures {
		for _, sig := range signatures {
			regex, err := regexp.Compile(sig)
			if err != nil {
				continue
			}

			matches := regex.FindAllStringIndex(code, -1)
			for _, match := range matches {
				results = append(results, PatternDetectionResult{
					Type:       "protector_signature",
					Pattern:    sig,
					Protector:  protector,
					StartPos:   match[0],
					EndPos:     match[1],
					Confidence: 0.85,
					Suggestion: fmt.Sprintf("Protector detected: %s. Use specialized deobfuscation.", protector),
				})
			}
		}
	}

	return results, nil
}

// AnalyzeContextForFalsePositives анализирует контекст для снижения ложных срабатываний
func (ape *AdvancedPatcherEngine) AnalyzeContextForFalsePositives(code string, pattern *AdvancedPatcherPattern) (float64, error) {
	if pattern == nil || !pattern.ContextAnalysis.AnalyzeDFG && !pattern.ContextAnalysis.AnalyzeCFG {
		return 1.0, nil // Нет контекстного анализа, возвращаем полную уверенность
	}

	confidenceBoost := 1.0

	// Анализ потоков данных
	if pattern.ContextAnalysis.AnalyzeDFG && ape.dfgAnalyzer != nil {
		dfg, err := ape.dfgAnalyzer.AnalyzeDataFlow(code)
		if err == nil {
			// Проверяем, находится ли паттерн в контексте потока данных
			if len(dfg) > 0 {
				confidenceBoost *= 1.1 // Буст уверенности при наличии потока данных
			}
		}
	}

	// Анализ потоков управления
	if pattern.ContextAnalysis.AnalyzeCFG && ape.cfgAnalyzer != nil {
		cfg, err := ape.cfgAnalyzer.BuildCFG(code)
		if err == nil {
			// Проверяем доминаторы и циклы
			dominators, _ := ape.cfgAnalyzer.FindDominators(cfg)
			loops, _ := ape.cfgAnalyzer.DetectLoops(cfg)

			if len(dominators) > 0 && len(loops) > 0 {
				confidenceBoost *= 1.15 // Дополнительный буст при наличии сложной структуры управления
			}
		}
	}

	// Проверка контекста библиотеки
	if pattern.ContextAnalysis.CheckLibraryContext {
		for _, prefix := range pattern.ContextAnalysis.ExcludedLibraryPrefixes {
			if strings.Contains(code, prefix) {
				confidenceBoost *= 0.5 // Снижение уверенности при обнаружении библиотечного кода
				break
			}
		}
	}

	// Применяем минимальный порог
	if confidenceBoost < pattern.ContextAnalysis.MinimumConfidenceBoost {
		confidenceBoost = pattern.ContextAnalysis.MinimumConfidenceBoost
	}

	return confidenceBoost, nil
}

// SolvePatchWithSMT решает задачу патчинга с помощью SMT-солвера
func (ape *AdvancedPatcherEngine) SolvePatchWithSMT(pattern *AdvancedPatcherPattern, code string) (map[string]interface{}, error) {
	if ape.smtSolver == nil || len(pattern.SMTConstraints) == 0 {
		return nil, fmt.Errorf("SMT solver not available or no constraints defined")
	}

	// Решаем ограничения
	solution, err := ape.smtSolver.Solve(pattern.SMTConstraints)
	if err != nil {
		return nil, fmt.Errorf("SMT solver failed: %w", err)
	}

	// Верифицируем решение
	if !ape.smtSolver.VerifyConstraints(pattern.SMTConstraints, solution) {
		return nil, fmt.Errorf("SMT solution verification failed")
	}

	return solution, nil
}

// PatternDetectionResult представляет результат обнаружения паттерна
type PatternDetectionResult struct {
	Type       string
	Pattern    string
	Protector  string
	StartPos   int
	EndPos     int
	Confidence float64
	Suggestion string
}

// GetAllPatterns возвращает все зарегистрированные паттерны
func (ape *AdvancedPatcherEngine) GetAllPatterns() map[string]*AdvancedPatcherPattern {
	ape.mu.RLock()
	defer ape.mu.RUnlock()

	patterns := make(map[string]*AdvancedPatcherPattern)
	for k, v := range ape.patterns {
		patterns[k] = v
	}
	return patterns
}

// InitializeDefaultPatterns инициализирует набор паттернов по умолчанию
func (ape *AdvancedPatcherEngine) InitializeDefaultPatterns() error {
	defaultPatterns := []*AdvancedPatcherPattern{
		{
			ID:          "virtualized_code_detection",
			Name:        "Virtualized Code Detection",
			Description: "Detects and suggests patches for virtualized/obfuscated bytecode",
			Category:    "virtualization",
			Severity:    "high",
			Confidence:  0.75,
			Patterns: []string{
				`dispatch_table|vm_handler|bytecode_interpreter`,
				`switch\s*\(\s*opcode\s*\)`,
			},
			ContextAnalysis: ContextAnalysisConfig{
				AnalyzeDFG:             true,
				AnalyzeCFG:             true,
				CheckLibraryContext:    true,
				MinimumConfidenceBoost: 0.6,
			},
			PatchStrategies: []PatchStrategyConfig{
				{
					Type:        "smt_solve",
					Risk:        "high",
					Description: "Use SMT solver to analyze bytecode semantics",
				},
			},
		},
		{
			ID:          "anti_cheat_detection",
			Name:        "Anti-Cheat Detection",
			Description: "Detects anti-cheat mechanisms and suggests bypass strategies",
			Category:    "anti-cheat",
			Severity:    "critical",
			Confidence:  0.8,
			Patterns: []string{
				`anti_cheat|cheat_detection|integrity_check`,
				`memory_scan|code_injection_check|debugger_check`,
			},
			ContextAnalysis: ContextAnalysisConfig{
				AnalyzeDFG:             true,
				AnalyzeCFG:             true,
				MinimumConfidenceBoost: 0.7,
			},
			PatchStrategies: []PatchStrategyConfig{
				{
					Type:        "return_constant",
					ReturnValue: "true",
					Risk:        "medium",
					Description: "Return constant true for integrity checks",
				},
			},
		},
	}

	for _, pattern := range defaultPatterns {
		if err := ape.RegisterPattern(pattern); err != nil {
			return fmt.Errorf("failed to register pattern %s: %w", pattern.ID, err)
		}
	}

	return nil
}
